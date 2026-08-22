const path = require('node:path');
const crypto = require('node:crypto');
const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { getCookie } = require('hono/cookie');
const { bodyLimit } = require('hono/body-limit');
const { getConnInfo } = require('@hono/node-server/conninfo');
const { Eta } = require('eta');

const eta = new Eta({ views: path.join(__dirname, 'views') });

const welcomeTitles = ['Welcome', 'Welcome back', 'Hello there', 'Good to see you', 'Nice to meet you'];

const welcomeTitle = () => welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)];

const styles = `nav {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.75rem 1.25rem;
  border-bottom: 1px solid light-dark(#e2e8f0, #1f2937);
}
main {
  max-width: 40rem;
  margin: 0 auto;
  padding: 1.25rem;
}`;

const users = new Map();

const SESSION_COOKIE = 'session';
const CSRF_COOKIE = 'csrf';
const SESSION_MAX_AGE = 25200;
const MAX_BODY_SIZE = 16 * 1024;
const MAX_EMAIL_LENGTH = 254;
const MAX_PASSWORD_LENGTH = 1024;
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const SIGNIN_RATE_LIMIT = 10;
const REGISTER_RATE_LIMIT = 5;
const RATE_LIMIT_MAX_TRACKED = 10000;
const isLocalDevelopment = process.env.NODE_ENV === 'development';
const hmacSecret = process.env.HMAC_SECRET || (isLocalDevelopment ? crypto.randomBytes(32).toString('hex') : null);

if (!hmacSecret) {
  console.error('HMAC_SECRET environment variable is required');
  process.exit(1);
}

if (!isLocalDevelopment && hmacSecret.length < 32) {
  console.error('HMAC_SECRET must be at least 32 characters long');
  process.exit(1);
}

const signSession = (email) => {
  const expiresAt = Date.now() + SESSION_MAX_AGE * 1000;
  const payload = `${Buffer.from(email).toString('base64url')}.${expiresAt}`;
  const signature = crypto.createHmac('sha256', hmacSecret).update(payload).digest('base64url');
  return `${payload}.${signature}`;
};

const verifySession = (cookieValue) => {
  if (!cookieValue) return null;
  const [emailEncoded, expiresAt, signature] = cookieValue.split('.');
  if (!emailEncoded || !expiresAt || !signature) return null;
  const payload = `${emailEncoded}.${expiresAt}`;
  const expected = crypto.createHmac('sha256', hmacSecret).update(payload).digest('base64url');
  const given = Buffer.from(signature);
  const known = Buffer.from(expected);
  if (given.length !== known.length || !crypto.timingSafeEqual(given, known)) return null;
  if (!/^\d+$/.test(expiresAt) || Date.now() > Number(expiresAt)) return null;
  return Buffer.from(emailEncoded, 'base64url').toString('utf8');
};

const sessionCookie = (value) =>
  `${SESSION_COOKIE}=${encodeURIComponent(value)}; Path=/; HttpOnly;${
    isLocalDevelopment ? '' : ' Secure;'
  } SameSite=Lax; Max-Age=${SESSION_MAX_AGE}`;

const expiredSessionCookie = () =>
  `${SESSION_COOKIE}=; Path=/; HttpOnly;${isLocalDevelopment ? '' : ' Secure;'} SameSite=Lax; Max-Age=0`;

const csrfCookie = (value) =>
  `${CSRF_COOKIE}=${encodeURIComponent(value)}; Path=/; HttpOnly;${
    isLocalDevelopment ? '' : ' Secure;'
  } SameSite=Lax; Max-Age=${SESSION_MAX_AGE}`;

const hashPassword = (password, salt) =>
  new Promise((resolve, reject) =>
    crypto.scrypt(password, salt, 64, (err, derivedKey) => (err ? reject(err) : resolve(derivedKey.toString('hex'))))
  );

const DUMMY_SALT = crypto.randomBytes(16).toString('hex');
const dummyHash = hashPassword(crypto.randomBytes(32).toString('hex'), DUMMY_SALT);

const signCsrfToken = () => {
  const payload = `${crypto.randomBytes(16).toString('base64url')}.${Date.now()}`;
  const signature = crypto.createHmac('sha256', hmacSecret).update(`csrf:${payload}`).digest('base64url');
  return `${payload}.${signature}`;
};

const verifyCsrfToken = (token) => {
  if (typeof token !== 'string') return false;
  const [nonce, issuedAt, signature] = token.split('.');
  if (!nonce || !issuedAt || !signature || !/^\d+$/.test(issuedAt)) return false;
  const payload = `${nonce}.${issuedAt}`;
  const expected = crypto.createHmac('sha256', hmacSecret).update(`csrf:${payload}`).digest('base64url');
  const given = Buffer.from(signature);
  const known = Buffer.from(expected);
  if (given.length !== known.length || !crypto.timingSafeEqual(given, known)) return false;
  return Date.now() - Number(issuedAt) <= SESSION_MAX_AGE * 1000;
};

const verifyCsrf = (c, formToken) => {
  if (typeof formToken !== 'string') return false;
  if (getCookie(c, CSRF_COOKIE) !== formToken) return false;
  return verifyCsrfToken(formToken);
};

const renderWithCsrf = (c, template, data, status) => {
  const csrfToken = signCsrfToken();
  c.header('Set-Cookie', csrfCookie(csrfToken));
  return c.html(eta.render(template, { ...data, csrfToken }), status);
};

const saveUser = async (email, password) => {
  const salt = crypto.randomBytes(16).toString('hex');
  const passwordHash = await hashPassword(password, salt);
  users.set(email, { email, passwordHash, salt });
};

const rateBuckets = new Map();

const clientAddress = (c) => {
  try {
    return getConnInfo(c).remote.address || 'unknown';
  } catch {
    return 'unknown';
  }
};

const takeRateToken = (key, limit) => {
  const now = Date.now();
  if (rateBuckets.size > RATE_LIMIT_MAX_TRACKED) {
    for (const [trackedKey, bucket] of rateBuckets) {
      if (bucket.resetAt <= now) rateBuckets.delete(trackedKey);
    }
  }
  const bucket = rateBuckets.get(key);
  if (!bucket || bucket.resetAt <= now) {
    rateBuckets.set(key, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return { limited: false, retryAfter: Math.ceil(RATE_LIMIT_WINDOW_MS / 1000) };
  }
  bucket.count += 1;
  return {
    limited: bucket.count > limit,
    retryAfter: Math.max(1, Math.ceil((bucket.resetAt - now) / 1000))
  };
};

const verifyCredentials = async (email, password) => {
  const user = users.get(email);
  const salt = user ? user.salt : DUMMY_SALT;
  const expectedHash = user ? user.passwordHash : await dummyHash;
  const passwordHash = await hashPassword(password, salt);
  const matches =
    Buffer.byteLength(passwordHash) === Buffer.byteLength(expectedHash) &&
    crypto.timingSafeEqual(Buffer.from(passwordHash), Buffer.from(expectedHash));
  return matches && Boolean(user);
};

const app = new Hono();

app.use(
  secureHeaders({
    contentSecurityPolicy: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", 'https://unpkg.com'],
      styleSrc: ["'self'", 'https://unpkg.com'],
      imgSrc: ["'self'", 'data:'],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"]
    }
  })
);
app.use(bodyLimit({ maxSize: MAX_BODY_SIZE }));

app.get('/styles.css', (c) => c.body(styles, 200, { 'Content-Type': 'text/css; charset=utf-8' }));
app.get('/', (c) => {
  if (verifySession(getCookie(c, SESSION_COOKIE))) return c.redirect('/profile');
  return renderWithCsrf(c, 'signin', {
    welcome: welcomeTitle(),
    notice: c.req.query('registered') === '1' ? 'Account created successfully. Please sign in.' : undefined
  });
});

app.post('/', async (c) => {
  const rate = takeRateToken(`signin:${clientAddress(c)}`, SIGNIN_RATE_LIMIT);
  if (rate.limited) {
    c.header('Retry-After', String(rate.retryAfter));
    return renderWithCsrf(
      c,
      'signin',
      { welcome: welcomeTitle(), error: 'Too many attempts. Please try again later.' },
      429
    );
  }
  const body = await c.req.parseBody();
  const email = String(body.email || '')
    .trim()
    .toLowerCase();
  const password = String(body.password || '');
  if (!verifyCsrf(c, body.csrf)) {
    return renderWithCsrf(
      c,
      'signin',
      { welcome: welcomeTitle(), email, error: 'Your request could not be verified. Please try again.' },
      403
    );
  }
  const withinLimits = email.length <= MAX_EMAIL_LENGTH && password.length <= MAX_PASSWORD_LENGTH;
  if (withinLimits && email && password && (await verifyCredentials(email, password))) {
    c.header('Set-Cookie', sessionCookie(signSession(email)));
    return c.redirect('/profile');
  }
  return renderWithCsrf(c, 'signin', { welcome: welcomeTitle(), email, error: 'Invalid email or password.' }, 401);
});

app.get('/register', (c) => renderWithCsrf(c, 'register', {}));

app.post('/register', async (c) => {
  const rate = takeRateToken(`register:${clientAddress(c)}`, REGISTER_RATE_LIMIT);
  if (rate.limited) {
    c.header('Retry-After', String(rate.retryAfter));
    return renderWithCsrf(c, 'register', { error: 'Too many attempts. Please try again later.' }, 429);
  }
  const body = await c.req.parseBody();
  const email = String(body.email || '')
    .trim()
    .toLowerCase();
  const password = String(body.password || '');
  if (!verifyCsrf(c, body.csrf)) {
    return renderWithCsrf(
      c,
      'register',
      { email, error: 'Your request could not be verified. Please try again.' },
      403
    );
  }
  if (password.length < 8) {
    return renderWithCsrf(c, 'register', { email, error: 'Password must be at least 8 characters long.' }, 400);
  }
  if (email.length > MAX_EMAIL_LENGTH || password.length > MAX_PASSWORD_LENGTH) {
    return renderWithCsrf(c, 'register', { email: '', error: 'Email or password is too long.' }, 400);
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return renderWithCsrf(c, 'register', { email: '', error: 'Please enter a valid email address.' }, 400);
  }
  if (users.has(email)) {
    return renderWithCsrf(c, 'register', { email, error: 'An account with this email already exists.' }, 409);
  }
  await saveUser(email, password);
  return c.redirect('/?registered=1');
});

app.get('/profile', (c) => {
  const email = verifySession(getCookie(c, SESSION_COOKIE));
  if (!email) return c.redirect('/');
  c.header('Cache-Control', 'no-store');
  return renderWithCsrf(c, 'profile', { email });
});

app.post('/signout', async (c) => {
  const body = await c.req.parseBody();
  if (verifyCsrf(c, body.csrf)) {
    c.header('Set-Cookie', expiredSessionCookie());
  }
  return c.redirect('/');
});
app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
