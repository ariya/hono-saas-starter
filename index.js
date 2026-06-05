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

const users = new Map();

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, SCRYPT_KEYLEN, SCRYPT_COST).toString('hex');
}

function signSession(email) {
  const payload = `${email}.${Date.now()}`;
  const sig = crypto.createHmac('sha256', HMAC_SECRET).update(payload).digest('hex');
  return `${payload}.${sig}`;
}

function verifySession(token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [email, ts, sig] = parts;
  const payload = `${email}.${ts}`;
  const expected = crypto.createHmac('sha256', HMAC_SECRET).update(payload).digest('hex');
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
  if (sig.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'));
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

  const email = (body.email || '').trim().toLowerCase();
  const password = body.password || '';

  const user = users.get(email);
  if (!user || hashPassword(password, user.salt) !== user.hash) {
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

  const email = (body.email || '').trim().toLowerCase();
  const password = body.password || '';

  if (password.length < MIN_PASSWORD_LEN) {
    return renderRegister(c, `Password must be at least ${MIN_PASSWORD_LEN} characters`);
  }

  if (users.has(email)) {
    return renderRegister(c, 'An account with this email already exists');
  }

  const salt = crypto.randomBytes(16).toString('hex');
  const hash = hashPassword(password, salt);
  users.set(email, { hash, salt });

  return c.redirect('/');
});

app.get('/profile', (c) => {
  const email = getSessionEmail(c);
  if (!email) return c.redirect('/');
  return c.html(eta.render('profile', { email }));
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
