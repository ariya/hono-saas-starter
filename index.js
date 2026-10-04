const crypto = require('node:crypto');
const { promisify } = require('node:util');
const path = require('node:path');
const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { getConnInfo } = require('@hono/node-server/conninfo');
const { secureHeaders } = require('hono/secure-headers');
const { setCookie, getCookie, deleteCookie } = require('hono/cookie');
const { Eta } = require('eta');

const app = new Hono();
const eta = new Eta({ views: path.join(__dirname, 'views') });
const isProduction = process.env.NODE_ENV === 'production';
const sessionSecret = process.env.HMAC_SECRET || crypto.randomBytes(32).toString('hex');
const SESSION_MAX_AGE = 7 * 60 * 60;
const scrypt = promisify(crypto.scrypt);
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const RATE_LIMIT_MAX = 10;
const rateLimitStore = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitStore) {
    if (now > entry.resetAt) rateLimitStore.delete(key);
  }
}, RATE_LIMIT_WINDOW_MS).unref();

const welcomeTitles = ['Welcome', 'Welcome back', 'Hello there', 'Good to see you', 'Sign in to continue'];
const users = new Map();

function pickWelcomeTitle() {
  return welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)];
}

function getUser(email) {
  return users.get(String(email).toLowerCase());
}

async function createUser(email, password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const passwordHash = (await scrypt(String(password), salt, 64)).toString('hex');
  const user = { email: String(email).toLowerCase(), passwordHash, salt };
  users.set(user.email, user);
  return user;
}

async function verifyPassword(user, password) {
  const expected = Buffer.from(user.passwordHash, 'hex');
  const candidate = await scrypt(String(password), user.salt, 64);
  return candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected);
}

function encodeSession(email) {
  const payload = Buffer.from(JSON.stringify({ email, exp: Date.now() + SESSION_MAX_AGE * 1000 })).toString(
    'base64url'
  );
  const signature = crypto.createHmac('sha256', sessionSecret).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

function decodeSession(token) {
  if (!token) return null;
  const [payload, signature] = String(token).split('.');
  if (!payload || !signature) return null;
  const expected = crypto.createHmac('sha256', sessionSecret).update(payload).digest('base64url');
  const signatureBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expected);
  if (signatureBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(signatureBuffer, expectedBuffer)) {
    return null;
  }
  let data;
  try {
    data = JSON.parse(Buffer.from(payload, 'base64url').toString());
  } catch {
    return null;
  }
  if (!data || typeof data.email !== 'string' || typeof data.exp !== 'number' || data.exp < Date.now()) {
    return null;
  }
  return getUser(data.email) ? data.email : null;
}

function createCsrfToken() {
  const expiry = String(Date.now() + 60 * 60 * 1000);
  const signature = crypto.createHmac('sha256', sessionSecret).update(expiry).digest('base64url');
  return `${expiry}.${signature}`;
}

function verifyCsrfToken(token) {
  if (!token) return false;
  const [expiry, signature] = String(token).split('.');
  if (!expiry || !signature) return false;
  const expected = crypto.createHmac('sha256', sessionSecret).update(expiry).digest('base64url');
  const signatureBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expected);
  if (signatureBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(signatureBuffer, expectedBuffer)) {
    return false;
  }
  return Number(expiry) > Date.now();
}

function renderSignin(c, status, error) {
  return c.html(eta.render('signin', { title: pickWelcomeTitle(), csrfToken: createCsrfToken(), error }), status);
}

function isRateLimited(key) {
  const now = Date.now();
  const entry = rateLimitStore.get(key);
  if (!entry || now > entry.resetAt) {
    rateLimitStore.set(key, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return false;
  }
  entry.count += 1;
  return entry.count > RATE_LIMIT_MAX;
}

function clientKey(c, scope) {
  const info = getConnInfo(c);
  return `${scope}:${info.remote.address || 'unknown'}`;
}

function renderRegister(c, status, error) {
  return c.html(eta.render('register', { csrfToken: createCsrfToken(), error }), status);
}

app.use(secureHeaders());

app.get('/', (c) => {
  if (decodeSession(getCookie(c, 'session'))) return c.redirect('/profile');
  return renderSignin(c, 200);
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

app.get('/register', (c) => renderRegister(c, 200));

app.get('/signout', (c) => {
  deleteCookie(c, 'session', { path: '/' });
  return c.redirect('/');
});

app.get('/profile', (c) => {
  const email = decodeSession(getCookie(c, 'session'));
  if (!email) return c.redirect('/');
  return c.html(eta.render('profile', { email }));
});

app.post('/signin', async (c) => {
  const body = await c.req.parseBody();
  if (isRateLimited(clientKey(c, 'signin'))) {
    return renderSignin(c, 429, 'Too many sign-in attempts. Please try again later.');
  }
  if (!verifyCsrfToken(body._csrf)) {
    return renderSignin(c, 403, 'Your form session expired. Please try again.');
  }
  const user = getUser(body.email);
  if (!user || !(await verifyPassword(user, body.password))) {
    return renderSignin(c, 401, 'Invalid email or password.');
  }
  setCookie(c, 'session', encodeSession(user.email), {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'Lax',
    path: '/',
    maxAge: SESSION_MAX_AGE
  });
  return c.redirect('/profile');
});

app.post('/register', async (c) => {
  const body = await c.req.parseBody();
  if (isRateLimited(clientKey(c, 'register'))) {
    return renderRegister(c, 429, 'Too many registration attempts. Please try again later.');
  }
  if (!verifyCsrfToken(body._csrf)) {
    return renderRegister(c, 403, 'Your form session expired. Please try again.');
  }
  const email = String(body.email || '')
    .trim()
    .toLowerCase();
  const password = String(body.password || '');
  if (password.length < 8) {
    return renderRegister(c, 400, 'Password must be at least 8 characters long.');
  }
  if (!email) {
    return renderRegister(c, 400, 'Email is required.');
  }
  if (getUser(email)) {
    return renderRegister(c, 400, 'An account with that email already exists.');
  }
  await createUser(email, password);
  return c.html(eta.render('register-success', {}));
});

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
