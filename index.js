const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');
const path = require('path');
const crypto = require('crypto');

const eta = new Eta({ views: path.join(__dirname, 'views') });

const WELCOME_TITLES = ['Welcome back', 'Good to see you again', 'Hello there', 'Welcome', 'Hey, welcome'];

const HMAC_SECRET = process.env.HMAC_SECRET || crypto.randomBytes(32).toString('hex');
const IS_PROD = process.env.NODE_ENV === 'production';
const SESSION_MAX_AGE = 7 * 60 * 60;
const SCRYPT_KEYLEN = 64;
const SCRYPT_COST = { N: 16384, r: 8, p: 1 };

const MIN_PASSWORD_LEN = 8;
const MAX_PASSWORD_LEN = 128;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const RATE_LIMIT_WINDOW = 15 * 60 * 1000;
const RATE_LIMIT_MAX = 20;
const DUMMY_SALT = crypto.randomBytes(16).toString('hex');
const DUMMY_HASH = hashPasswordRaw('dummy', DUMMY_SALT);

const users = new Map();
const rateLimits = new Map();

function hashPasswordRaw(password, salt) {
  return crypto.scryptSync(password, salt, SCRYPT_KEYLEN, SCRYPT_COST).toString('hex');
}

function safeCompare(a, b) {
  if (!/^[0-9a-f]+$/i.test(a) || !/^[0-9a-f]+$/i.test(b) || a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

function checkRateLimit(ip) {
  const now = Date.now();
  const entry = rateLimits.get(ip);
  if (!entry || now - entry.start > RATE_LIMIT_WINDOW) {
    rateLimits.set(ip, { start: now, count: 1 });
    return true;
  }
  entry.count++;
  return entry.count <= RATE_LIMIT_MAX;
}

function signSession(email) {
  const payload = `${email}.${Date.now()}`;
  const sig = crypto.createHmac('sha256', HMAC_SECRET).update(payload).digest('hex');
  return `${payload}.${sig}`;
}

function verifySession(token) {
  if (!token) return null;
  const lastDot = token.lastIndexOf('.');
  if (lastDot === -1) return null;
  const secondLastDot = token.lastIndexOf('.', lastDot - 1);
  if (secondLastDot === -1) return null;
  const email = token.slice(0, secondLastDot);
  const ts = token.slice(secondLastDot + 1, lastDot);
  const sig = token.slice(lastDot + 1);
  const payload = `${email}.${ts}`;
  const expected = crypto.createHmac('sha256', HMAC_SECRET).update(payload).digest('hex');
  if (!/^[0-9a-f]+$/i.test(sig) || sig.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'))) return null;
  if (Date.now() - Number(ts) > SESSION_MAX_AGE * 1000) return null;
  return email;
}

function sessionCookie(token) {
  const parts = [`session=${token}`, 'Path=/', `Max-Age=${SESSION_MAX_AGE}`, 'HttpOnly', 'SameSite=Lax'];
  if (IS_PROD) parts.push('Secure');
  return parts.join('; ');
}

function generateCsrfToken() {
  const nonce = crypto.randomBytes(16).toString('hex');
  const sig = crypto.createHmac('sha256', HMAC_SECRET).update(nonce).digest('hex');
  return `${nonce}.${sig}`;
}

function verifyCsrfToken(token) {
  if (!token) return false;
  const dot = token.lastIndexOf('.');
  if (dot === -1) return false;
  const nonce = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const expected = crypto.createHmac('sha256', HMAC_SECRET).update(nonce).digest('hex');
  if (!/^[0-9a-f]+$/i.test(sig) || sig.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'));
}

function clearSessionCookie() {
  return 'session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax';
}

function renderSignIn(c, error) {
  const title = WELCOME_TITLES[Math.floor(Math.random() * WELCOME_TITLES.length)];
  const csrf = generateCsrfToken();
  return c.html(eta.render('sign-in', { title, error, csrf }));
}

function renderRegister(c, error) {
  const csrf = generateCsrfToken();
  return c.html(eta.render('register', { error, csrf }));
}

function getSessionEmail(c) {
  const cookie = c.req.header('Cookie') || '';
  const match = cookie.match(/(?:^|;\s*)session=([^;]+)/);
  if (!match) return null;
  return verifySession(decodeURIComponent(match[1]));
}

function getClientIp(c) {
  return c.req.header('x-forwarded-for')?.split(',')[0]?.trim() || c.req.header('x-real-ip') || 'unknown';
}

const app = new Hono();

app.use(secureHeaders());

app.get('/', (c) => {
  if (getSessionEmail(c)) return c.redirect('/profile');
  return renderSignIn(c, null);
});

app.post('/', async (c) => {
  const body = await c.req.parseBody();

  if (!verifyCsrfToken(body._csrf)) {
    return renderSignIn(c, 'Invalid request. Please try again.');
  }

  if (!checkRateLimit(getClientIp(c))) {
    return renderSignIn(c, 'Too many attempts. Please try again later.');
  }

  const email = (body.email || '').trim().toLowerCase();
  const password = body.password || '';

  if (!EMAIL_RE.test(email)) {
    return renderSignIn(c, 'Invalid email or password');
  }

  const user = users.get(email);
  const hash = user ? hashPasswordRaw(password, user.salt) : DUMMY_HASH;
  const stored = user ? user.hash : DUMMY_HASH;

  if (!user || !safeCompare(hash, stored)) {
    return renderSignIn(c, 'Invalid email or password');
  }

  const token = signSession(email);
  c.header('Set-Cookie', sessionCookie(token));
  return c.redirect('/profile');
});

app.get('/register', (c) => {
  if (getSessionEmail(c)) return c.redirect('/profile');
  return renderRegister(c, null);
});

app.post('/register', async (c) => {
  const body = await c.req.parseBody();

  if (!verifyCsrfToken(body._csrf)) {
    return renderRegister(c, 'Invalid request. Please try again.');
  }

  if (!checkRateLimit(getClientIp(c))) {
    return renderRegister(c, 'Too many attempts. Please try again later.');
  }

  const email = (body.email || '').trim().toLowerCase();
  const password = body.password || '';

  if (!EMAIL_RE.test(email)) {
    return renderRegister(c, 'Invalid email format');
  }

  if (password.length < MIN_PASSWORD_LEN) {
    return renderRegister(c, `Password must be at least ${MIN_PASSWORD_LEN} characters`);
  }

  if (password.length > MAX_PASSWORD_LEN) {
    return renderRegister(c, `Password must be at most ${MAX_PASSWORD_LEN} characters`);
  }

  if (users.has(email)) {
    return renderRegister(c, 'If this email is not registered, you will receive a confirmation email');
  }

  const salt = crypto.randomBytes(16).toString('hex');
  const hash = hashPasswordRaw(password, salt);
  users.set(email, { hash, salt });

  return c.redirect('/');
});

app.get('/profile', (c) => {
  const email = getSessionEmail(c);
  if (!email) return c.redirect('/');
  const csrf = generateCsrfToken();
  return c.html(eta.render('profile', { email, csrf }));
});

app.post('/signout', async (c) => {
  const body = await c.req.parseBody();
  if (!verifyCsrfToken(body._csrf)) {
    return c.redirect('/profile');
  }
  c.header('Set-Cookie', clearSessionCookie());
  return c.redirect('/');
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
