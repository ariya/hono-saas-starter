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

const users = new Map();

const SESSION_COOKIE = 'session';
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
  } Max-Age=${SESSION_MAX_AGE}`;

const expiredSessionCookie = () =>
  `${SESSION_COOKIE}=; Path=/; HttpOnly;${isLocalDevelopment ? '' : ' Secure;'} Max-Age=0`;

const hashPassword = (password, salt) =>
  new Promise((resolve, reject) =>
    crypto.scrypt(password, salt, 64, (err, derivedKey) => (err ? reject(err) : resolve(derivedKey.toString('hex'))))
  );

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
  if (!user) return false;
  const passwordHash = await hashPassword(password, user.salt);
  return (
    Buffer.byteLength(passwordHash) === Buffer.byteLength(user.passwordHash) &&
    crypto.timingSafeEqual(Buffer.from(passwordHash), Buffer.from(user.passwordHash))
  );
};

const app = new Hono();

app.use(secureHeaders());
app.use(bodyLimit({ maxSize: MAX_BODY_SIZE }));

app.get('/', (c) => {
  if (verifySession(getCookie(c, SESSION_COOKIE))) return c.redirect('/profile');
  return c.html(
    eta.render('signin', {
      welcome: welcomeTitle(),
      csrfToken: signCsrfToken(),
      notice: c.req.query('registered') === '1' ? 'Account created successfully. Please sign in.' : undefined
    })
  );
});

app.post('/', async (c) => {
  const rate = takeRateToken(`signin:${clientAddress(c)}`, SIGNIN_RATE_LIMIT);
  if (rate.limited) {
    c.header('Retry-After', String(rate.retryAfter));
    return c.html(
      eta.render('signin', {
        welcome: welcomeTitle(),
        csrfToken: signCsrfToken(),
        error: 'Too many attempts. Please try again later.'
      }),
      429
    );
  }
  const body = await c.req.parseBody();
  const email = String(body.email || '')
    .trim()
    .toLowerCase();
  const password = String(body.password || '');
  const csrfFailure = () =>
    c.html(
      eta.render('signin', {
        welcome: welcomeTitle(),
        email,
        csrfToken: signCsrfToken(),
        error: 'Your request could not be verified. Please try again.'
      }),
      403
    );
  if (!verifyCsrfToken(body.csrf)) return csrfFailure();
  const withinLimits = email.length <= MAX_EMAIL_LENGTH && password.length <= MAX_PASSWORD_LENGTH;
  if (withinLimits && email && password && (await verifyCredentials(email, password))) {
    c.header('Set-Cookie', sessionCookie(signSession(email)));
    return c.redirect('/profile');
  }
  return c.html(
    eta.render('signin', {
      welcome: welcomeTitle(),
      email,
      csrfToken: signCsrfToken(),
      error: 'Invalid email or password.'
    }),
    401
  );
});

app.get('/register', (c) => c.html(eta.render('register', { csrfToken: signCsrfToken() })));

app.post('/register', async (c) => {
  const rate = takeRateToken(`register:${clientAddress(c)}`, REGISTER_RATE_LIMIT);
  if (rate.limited) {
    c.header('Retry-After', String(rate.retryAfter));
    return c.html(
      eta.render('register', {
        csrfToken: signCsrfToken(),
        error: 'Too many attempts. Please try again later.'
      }),
      429
    );
  }
  const body = await c.req.parseBody();
  const email = String(body.email || '')
    .trim()
    .toLowerCase();
  const password = String(body.password || '');
  const renderRegister = (data, status) => c.html(eta.render('register', data), status);
  if (!verifyCsrfToken(body.csrf)) {
    return renderRegister(
      {
        csrfToken: signCsrfToken(),
        email,
        error: 'Your request could not be verified. Please try again.'
      },
      403
    );
  }
  if (password.length < 8) {
    return renderRegister(
      {
        csrfToken: signCsrfToken(),
        email,
        error: 'Password must be at least 8 characters long.'
      },
      400
    );
  }
  if (email.length > MAX_EMAIL_LENGTH || password.length > MAX_PASSWORD_LENGTH) {
    return renderRegister(
      {
        csrfToken: signCsrfToken(),
        email: '',
        error: 'Email or password is too long.'
      },
      400
    );
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return renderRegister(
      {
        csrfToken: signCsrfToken(),
        email: '',
        error: 'Please enter a valid email address.'
      },
      400
    );
  }
  if (users.has(email)) {
    return renderRegister(
      {
        csrfToken: signCsrfToken(),
        email,
        error: 'An account with this email already exists.'
      },
      409
    );
  }
  await saveUser(email, password);
  return c.redirect('/?registered=1');
});

app.get('/profile', (c) => {
  const email = verifySession(getCookie(c, SESSION_COOKIE));
  if (!email) return c.redirect('/');
  return c.html(eta.render('profile', { email, csrfToken: signCsrfToken() }));
});

app.post('/signout', async (c) => {
  const body = await c.req.parseBody();
  if (verifyCsrfToken(body.csrf)) {
    c.header('Set-Cookie', expiredSessionCookie());
  }
  return c.redirect('/');
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
