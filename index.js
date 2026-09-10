const path = require('node:path');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { getConnInfo } = require('@hono/node-server/conninfo');
const { secureHeaders } = require('hono/secure-headers');
const { bodyLimit } = require('hono/body-limit');
const { setCookie, getCookie, deleteCookie } = require('hono/cookie');
const { Eta } = require('eta');

const app = new Hono();
const eta = new Eta({ views: path.join(__dirname, 'views') });
const isProduction = process.env.NODE_ENV === 'production';

const users = new Map();
const sessionMaxAge = 7 * 60 * 60;
const passwordMinLength = 8;
const passwordMaxLength = 128;
const emailMaxLength = 254;
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const isValidEmail = (email) => email.length > 0 && email.length <= emailMaxLength && emailPattern.test(email);
const hmacSecret = process.env.HMAC_SECRET || (isProduction ? null : crypto.randomBytes(32).toString('hex'));
if (!hmacSecret) {
  throw new Error('HMAC_SECRET environment variable is required');
}

const scryptAsync = promisify(crypto.scrypt);

const hashPassword = async (password, salt) => (await scryptAsync(password, salt, 64)).toString('hex');

const verifyPassword = async (password, user) => {
  const expected = Buffer.from(user.passwordHash, 'hex');
  const actual = Buffer.from(await hashPassword(password, user.salt), 'hex');
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
};

const dummySalt = crypto.randomBytes(16).toString('hex');
const dummyHash = crypto.scryptSync('dummy-password', dummySalt, 64).toString('hex');

const signValue = (value) => crypto.createHmac('sha256', hmacSecret).update(value).digest('hex');

const createSessionToken = (email) => {
  const payload = `${email}:${Date.now() + sessionMaxAge * 1000}`;
  return `${Buffer.from(payload).toString('base64url')}.${signValue(payload)}`;
};

const verifySessionToken = (token) => {
  if (!token) return null;
  const [encoded, signature] = token.split('.');
  if (!encoded || !signature) return null;
  const payload = Buffer.from(encoded, 'base64url').toString();
  const expected = signValue(payload);
  if (signature.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
    return null;
  }
  const [email, expiry] = payload.split(':');
  if (!email || !expiry || Number(expiry) < Date.now()) return null;
  return email;
};

const createCsrfToken = () => {
  const nonce = crypto.randomBytes(16).toString('hex');
  return `${nonce}.${signValue(`csrf:${nonce}`)}`;
};

const verifyCsrfToken = (token) => {
  if (!token) return false;
  const [nonce, signature] = token.split('.');
  if (!nonce || !signature) return false;
  const expected = signValue(`csrf:${nonce}`);
  return signature.length === expected.length && crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
};

const createUser = async (email, password) => {
  const normalized = email.trim().toLowerCase();
  const salt = crypto.randomBytes(16).toString('hex');
  const passwordHash = await hashPassword(password, salt);
  users.set(normalized, { email: normalized, passwordHash, salt });
  return users.get(normalized);
};

if (!isProduction && process.env.SEED_DEMO_USER === 'true') {
  createUser('demo@example.com', 'password123').catch(() => {});
}

const rateLimitWindowMs = 15 * 60 * 1000;
const rateLimitMax = 10;
const rateLimitHits = new Map();

const clientKey = (c) => {
  try {
    return getConnInfo(c).remote.address || 'unknown';
  } catch {
    return 'unknown';
  }
};

const authRateLimit = async (c, next) => {
  const key = clientKey(c);
  const now = Date.now();
  const entry = rateLimitHits.get(key);
  if (!entry || now > entry.reset) {
    if (rateLimitHits.size > 10000) {
      for (const [k, v] of rateLimitHits) {
        if (now > v.reset) rateLimitHits.delete(k);
      }
    }
    rateLimitHits.set(key, { count: 1, reset: now + rateLimitWindowMs });
  } else {
    entry.count += 1;
    if (entry.count > rateLimitMax) {
      return c.text('Too many attempts, please try again later', 429);
    }
  }
  await next();
};

app.use(secureHeaders());
app.use(bodyLimit({ maxSize: 16 * 1024, onError: (c) => c.text('Payload too large', 413) }));

const welcomeTitles = ['Welcome', 'Welcome back', 'Hello again', 'Good to see you', 'Sign in to continue'];
const pickWelcome = () => welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)];

const renderSignin = (c, error, status = 200) =>
  c.html(
    eta.render('signin', { title: 'Sign In', heading: pickWelcome(), csrfToken: createCsrfToken(), error }),
    status
  );

app.get('/', (c) => {
  if (verifySessionToken(getCookie(c, 'session'))) return c.redirect('/profile');
  return renderSignin(c);
});

const renderRegister = (c, error, status = 200, message = null) =>
  c.html(
    eta.render('register', {
      title: 'Register',
      heading: 'Create your account',
      csrfToken: createCsrfToken(),
      error,
      message
    }),
    status
  );

app.get('/register', (c) => renderRegister(c));

app.post('/register', authRateLimit, async (c) => {
  const body = await c.req.parseBody();
  const email = String(body.email || '')
    .trim()
    .toLowerCase();
  const password = String(body.password || '');
  if (!verifyCsrfToken(String(body.csrfToken || ''))) {
    return renderRegister(c, 'Invalid or expired form token', 403);
  }
  if (!isValidEmail(email)) {
    return renderRegister(c, 'Please enter a valid email address', 400);
  }
  if (password.length < passwordMinLength) {
    return renderRegister(c, `Password must be at least ${passwordMinLength} characters long`, 400);
  }
  if (password.length > passwordMaxLength) {
    return renderRegister(c, `Password must be at most ${passwordMaxLength} characters long`, 400);
  }
  if (users.has(email)) {
    await hashPassword(password, dummySalt);
  } else {
    await createUser(email, password);
  }
  return renderRegister(c, null, 200, 'Account created. Redirecting to sign in…');
});

app.post('/signin', authRateLimit, async (c) => {
  const body = await c.req.parseBody();
  const email = String(body.email || '')
    .trim()
    .toLowerCase();
  const password = String(body.password || '');
  if (!verifyCsrfToken(String(body.csrfToken || ''))) {
    return renderSignin(c, 'Invalid or expired form token', 403);
  }
  if (password.length > passwordMaxLength) {
    return renderSignin(c, 'Invalid email or password', 401);
  }
  const user = users.get(email);
  if (!user) {
    await verifyPassword(password, { passwordHash: dummyHash, salt: dummySalt });
    return renderSignin(c, 'Invalid email or password', 401);
  }
  if (!(await verifyPassword(password, user))) {
    return renderSignin(c, 'Invalid email or password', 401);
  }
  setCookie(c, 'session', createSessionToken(user.email), {
    path: '/',
    httpOnly: true,
    sameSite: 'Lax',
    secure: isProduction,
    maxAge: sessionMaxAge
  });
  return c.redirect('/profile');
});

app.get('/profile', (c) => {
  const email = verifySessionToken(getCookie(c, 'session'));
  if (!email) return c.redirect('/');
  return c.html(eta.render('profile', { title: 'Profile', email, csrfToken: createCsrfToken() }));
});

app.post('/signout', async (c) => {
  const body = await c.req.parseBody();
  if (!verifyCsrfToken(String(body.csrfToken || ''))) {
    return c.text('Invalid or expired form token', 403);
  }
  deleteCookie(c, 'session', { path: '/' });
  return c.redirect('/');
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
