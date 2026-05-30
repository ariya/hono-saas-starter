const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { getCookie, setCookie, deleteCookie } = require('hono/cookie');
const { Eta } = require('eta');

const eta = new Eta({ views: path.join(__dirname, 'views') });

const isProduction = process.env.NODE_ENV === 'production';

const SESSION_COOKIE = 'session';
const SESSION_MAX_AGE = 7 * 60 * 60;

const sessionCookieOptions = () => ({
  httpOnly: true,
  secure: isProduction,
  sameSite: 'Lax',
  path: '/',
  maxAge: SESSION_MAX_AGE
});

const users = new Map();

const createUser = (email, passwordHash, salt) => {
  users.set(email, { email, passwordHash, salt });
};

const findUser = (email) => users.get(email);

const scrypt = promisify(crypto.scrypt);
const SCRYPT_KEYLEN = 64;

const hashPassword = async (password, salt) => {
  const useSalt = salt || crypto.randomBytes(16).toString('hex');
  const derived = (await scrypt(password, useSalt, SCRYPT_KEYLEN)).toString('hex');
  return { salt: useSalt, passwordHash: derived };
};

const verifyPassword = async (user, password) => {
  if (!user) return false;
  const { passwordHash } = await hashPassword(password, user.salt);
  const a = Buffer.from(passwordHash, 'hex');
  const b = Buffer.from(user.passwordHash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};

const SESSION_SECRET = process.env.HMAC_SECRET || (isProduction ? null : 'insecure-dev-secret');

if (!SESSION_SECRET) {
  throw new Error('HMAC_SECRET environment variable is required');
}

const sign = (value) => crypto.createHmac('sha256', SESSION_SECRET).update(value).digest('hex');

const createSession = (email) => {
  const expires = Date.now() + SESSION_MAX_AGE * 1000;
  const payload = `${expires}:${email}`;
  return `${Buffer.from(payload).toString('base64url')}.${sign(payload)}`;
};

const readSession = (token) => {
  if (!token) return null;
  const idx = token.lastIndexOf('.');
  if (idx < 0) return null;
  const payload = Buffer.from(token.slice(0, idx), 'base64url').toString();
  const signature = token.slice(idx + 1);
  const expected = sign(payload);
  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  const sep = payload.indexOf(':');
  if (sep < 0) return null;
  const expires = Number(payload.slice(0, sep));
  const email = payload.slice(sep + 1);
  if (!Number.isFinite(expires) || Date.now() > expires) return null;
  return email;
};

const createCsrfToken = () => {
  const nonce = crypto.randomBytes(16).toString('hex');
  return `${nonce}.${sign('csrf:' + nonce)}`;
};

const verifyCsrfToken = (token) => {
  if (!token) return false;
  const idx = token.lastIndexOf('.');
  if (idx < 0) return false;
  const nonce = token.slice(0, idx);
  const signature = token.slice(idx + 1);
  const expected = sign('csrf:' + nonce);
  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};

const app = new Hono();

app.use(secureHeaders());

const welcomeTitles = ['Welcome', 'Welcome back', 'Hello again', 'Good to see you', 'Glad you are here'];

const pickWelcome = () => welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)];

const renderSignin = (extra = {}) => eta.render('signin', { title: pickWelcome(), csrf: createCsrfToken(), ...extra });

app.get('/', (c) => {
  if (currentUserEmail(c)) return c.redirect('/profile');
  return c.html(renderSignin());
});

app.post('/', async (c) => {
  const body = await c.req.parseBody();
  if (!verifyCsrfToken(typeof body._csrf === 'string' ? body._csrf : '')) {
    return c.html(renderSignin({ error: 'Invalid request. Please try again.' }), 403);
  }
  const email = typeof body.email === 'string' ? body.email : '';
  const password = typeof body.password === 'string' ? body.password : '';
  const user = findUser(email);
  if (!(await verifyPassword(user, password))) {
    return c.html(renderSignin({ error: 'Invalid email or password.' }), 401);
  }
  setCookie(c, SESSION_COOKIE, createSession(user.email), sessionCookieOptions());
  return c.redirect('/profile');
});

const currentUserEmail = (c) => {
  const email = readSession(getCookie(c, SESSION_COOKIE));
  if (!email || !findUser(email)) return null;
  return email;
};

const renderRegister = (extra = {}) => eta.render('register', { csrf: createCsrfToken(), ...extra });

const MIN_PASSWORD_LENGTH = 8;

app.get('/register', (c) => {
  if (currentUserEmail(c)) return c.redirect('/profile');
  return c.html(renderRegister());
});

app.post('/register', async (c) => {
  const body = await c.req.parseBody();
  if (!verifyCsrfToken(typeof body._csrf === 'string' ? body._csrf : '')) {
    return c.html(renderRegister({ error: 'Invalid request. Please try again.' }), 403);
  }
  const email = typeof body.email === 'string' ? body.email.trim() : '';
  const password = typeof body.password === 'string' ? body.password : '';
  if (!email) {
    return c.html(renderRegister({ error: 'Email is required.' }), 400);
  }
  if (password.length < MIN_PASSWORD_LENGTH) {
    return c.html(renderRegister({ error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters.` }), 400);
  }
  if (findUser(email)) {
    return c.html(renderRegister({ error: 'An account with that email already exists.' }), 409);
  }
  const { passwordHash, salt } = await hashPassword(password);
  createUser(email, passwordHash, salt);
  return c.html(eta.render('success', { message: 'Your account is ready. You can now sign in.' }));
});

app.get('/profile', (c) => {
  const email = currentUserEmail(c);
  if (!email) return c.redirect('/');
  return c.html(eta.render('profile', { email, csrf: createCsrfToken() }));
});

app.post('/signout', async (c) => {
  const body = await c.req.parseBody();
  if (!verifyCsrfToken(typeof body._csrf === 'string' ? body._csrf : '')) {
    return c.redirect('/profile');
  }
  deleteCookie(c, SESSION_COOKIE, { path: '/' });
  return c.redirect('/');
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
