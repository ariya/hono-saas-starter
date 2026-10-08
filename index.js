const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');
const { createHmac, randomBytes, scrypt, timingSafeEqual } = require('node:crypto');
const { promisify } = require('node:util');
const path = require('node:path');
const { deleteCookie, getCookie, setCookie } = require('hono/cookie');

const scryptAsync = promisify(scrypt);

const SESSION_COOKIE = 'session';
const SESSION_TTL = 7 * 60 * 60;
const CSRF_TTL = 2 * 60 * 60;
const MIN_PASSWORD_LENGTH = 8;
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const isDevelopment = process.env.NODE_ENV === 'development';
const hmacSecret = process.env.HMAC_SECRET;

if (!hmacSecret) {
  throw new Error('HMAC_SECRET environment variable is required');
}

const app = new Hono();
const eta = new Eta({ views: path.join(__dirname, 'views') });
const users = new Map();

app.use(secureHeaders());

const welcomeTitles = ['Welcome', 'Welcome back', 'Hello there', 'Good to see you', 'Nice to have you here'];

const hashPassword = async (password, salt) => (await scryptAsync(password, salt, 64)).toString('hex');

const sign = (value) => createHmac('sha256', hmacSecret).update(value).digest('base64url');

const createSession = (email) => {
  const payload = Buffer.from(
    JSON.stringify({ sub: email, exp: Math.floor(Date.now() / 1000) + SESSION_TTL })
  ).toString('base64url');
  return `${payload}.${sign(`session.${payload}`)}`;
};

const verifySession = (token) => {
  if (!token) {
    return null;
  }
  const parts = token.split('.');
  if (parts.length !== 2) {
    return null;
  }
  const [payload, signature] = parts;
  const expected = Buffer.from(sign(`session.${payload}`));
  const actual = Buffer.from(signature);
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
    return null;
  }
  const session = JSON.parse(Buffer.from(payload, 'base64url').toString());
  if (session.exp <= Math.floor(Date.now() / 1000) || !users.has(session.sub)) {
    return null;
  }
  return session;
};

const createCsrfToken = () => {
  const data = `${Math.floor(Date.now() / 1000)}.${randomBytes(16).toString('base64url')}`;
  return `${data}.${sign(`csrf.${data}`)}`;
};

const verifyCsrfToken = (token) => {
  const parts = token.split('.');
  if (parts.length !== 3) {
    return false;
  }
  const [issuedAt, nonce, signature] = parts;
  const expected = Buffer.from(sign(`csrf.${issuedAt}.${nonce}`));
  const actual = Buffer.from(signature);
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
    return false;
  }
  const age = Math.floor(Date.now() / 1000) - Number(issuedAt);
  return age >= 0 && age <= CSRF_TTL;
};

const verifyPassword = async (password, user) => {
  const actual = Buffer.from(await hashPassword(password, user.salt), 'hex');
  const expected = Buffer.from(user.passwordHash, 'hex');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
};

const authenticate = async (email, password) => {
  const user = users.get(email);
  if (!user) {
    await hashPassword(password, 'timing-equalizer');
    return null;
  }
  return (await verifyPassword(password, user)) ? user : null;
};

const formField = (body, name) => (typeof body[name] === 'string' ? body[name] : '');

const renderSignin = (c, status = 200, data = {}) => {
  const welcome = welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)];
  return c.html(
    eta.render('signin', { title: 'Sign In', welcome, email: '', error: '', csrf: createCsrfToken(), ...data }),
    status
  );
};

app.get('/', (c) => {
  if (verifySession(getCookie(c, SESSION_COOKIE))) {
    return c.redirect('/profile');
  }
  return renderSignin(c);
});

const renderRegister = (c, status = 200, data = {}) =>
  c.html(eta.render('register', { title: 'Register', email: '', error: '', csrf: createCsrfToken(), ...data }), status);

app.get('/register', (c) => renderRegister(c));

app.post('/register', async (c) => {
  const body = await c.req.parseBody();
  if (!verifyCsrfToken(formField(body, 'csrf'))) {
    return renderRegister(c, 403, { error: 'Your form has expired. Please try again.' });
  }
  const email = formField(body, 'email').trim().toLowerCase();
  const password = formField(body, 'password');
  if (!emailPattern.test(email)) {
    return renderRegister(c, 400, { email, error: 'Please enter a valid email address.' });
  }
  if (password.length < MIN_PASSWORD_LENGTH) {
    return renderRegister(c, 400, { email, error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters.` });
  }
  const salt = randomBytes(16).toString('hex');
  const passwordHash = await hashPassword(password, salt);
  if (users.has(email)) {
    return renderRegister(c, 409, { email, error: 'An account with this email already exists.' });
  }
  users.set(email, { email, salt, passwordHash });
  return renderRegister(c, 201, {
    success: 'Account created. Redirecting you to sign in...',
    refresh: '3;url=/'
  });
});

app.get('/profile', (c) => {
  const session = verifySession(getCookie(c, SESSION_COOKIE));
  if (!session) {
    return c.redirect('/');
  }
  return c.html(eta.render('profile', { title: 'Profile', email: session.sub }));
});

app.post('/', async (c) => {
  const body = await c.req.parseBody();
  if (!verifyCsrfToken(formField(body, 'csrf'))) {
    return renderSignin(c, 403, { error: 'Your form has expired. Please try again.' });
  }
  const email = formField(body, 'email').trim().toLowerCase();
  const password = formField(body, 'password');
  const user = await authenticate(email, password);
  if (!user) {
    return renderSignin(c, 401, { email, error: 'Invalid email or password.' });
  }
  setCookie(c, SESSION_COOKIE, createSession(user.email), {
    httpOnly: true,
    secure: !isDevelopment,
    sameSite: 'Lax',
    path: '/',
    maxAge: SESSION_TTL
  });
  return c.redirect('/profile');
});

app.post('/signout', (c) => {
  deleteCookie(c, SESSION_COOKIE, { path: '/', secure: !isDevelopment });
  return c.redirect('/');
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
