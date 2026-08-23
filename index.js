const path = require('node:path');
const { createHmac, randomBytes, scryptSync, timingSafeEqual } = require('node:crypto');
const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { getCookie, setCookie } = require('hono/cookie');
const { Eta } = require('eta');

const app = new Hono();
const eta = new Eta({ views: path.join(__dirname, 'views') });

const MIN_PASSWORD_LENGTH = 8;

const SESSION_COOKIE = 'session';
const SESSION_MAX_AGE = 7 * 60 * 60;
const CSRF_COOKIE = 'csrf';
const CSRF_MAX_AGE = 2 * 60 * 60;
const isDevelopment = process.env.NODE_ENV === 'development';
const hmacSecret = process.env.HMAC_SECRET || (isDevelopment ? randomBytes(32).toString('hex') : '');

if (!hmacSecret) {
  console.error('HMAC_SECRET is required');
  process.exit(1);
}

const users = new Map();

const hashPassword = (password, salt) => scryptSync(password, salt, 64).toString('hex');

const createUser = (email, password) => {
  const normalized = String(email).trim().toLowerCase();
  const salt = randomBytes(16).toString('hex');
  const user = { email: normalized, salt, hash: hashPassword(password, salt) };
  users.set(normalized, user);
  return user;
};

const findUser = (email) => users.get(String(email).trim().toLowerCase());

const verifyPassword = (user, password) => {
  const salt = user ? user.salt : 'unknown';
  const expected = Buffer.from(user ? user.hash : hashPassword('', salt), 'hex');
  const actual = Buffer.from(hashPassword(password, salt), 'hex');
  return Boolean(user) && timingSafeEqual(expected, actual);
};

if (process.env.DEMO_EMAIL && process.env.DEMO_PASSWORD) {
  createUser(process.env.DEMO_EMAIL, process.env.DEMO_PASSWORD);
}

const cookieOptions = (maxAge) => ({
  path: '/',
  httpOnly: true,
  secure: !isDevelopment,
  sameSite: 'Lax',
  maxAge
});

const sign = (value) => createHmac('sha256', hmacSecret).update(value).digest('base64url');

const createSession = (email) => {
  const payload = `${Buffer.from(email).toString('base64url')}.${Date.now() + SESSION_MAX_AGE * 1000}`;
  return `${payload}.${sign(payload)}`;
};

const readSession = (token) => {
  if (typeof token !== 'string') {
    return null;
  }
  const parts = token.split('.');
  if (parts.length !== 3) {
    return null;
  }
  if (!equals(sign(`${parts[0]}.${parts[1]}`), parts[2])) {
    return null;
  }
  const expiresAt = Number(parts[1]);
  if (!Number.isFinite(expiresAt) || expiresAt < Date.now()) {
    return null;
  }
  return findUser(Buffer.from(parts[0], 'base64url').toString()) || null;
};

const equals = (a, b) => {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
};

const issueCsrfToken = (c) => {
  const nonce = randomBytes(16).toString('base64url');
  setCookie(c, CSRF_COOKIE, nonce, cookieOptions(CSRF_MAX_AGE));
  return `${nonce}.${sign(`csrf:${nonce}`)}`;
};

const verifyCsrfToken = (c, token) => {
  const nonce = getCookie(c, CSRF_COOKIE);
  if (!nonce || typeof token !== 'string') {
    return false;
  }
  const [provided, signature] = token.split('.');
  if (!provided || !signature) {
    return false;
  }
  return equals(sign(`csrf:${provided}`), signature) && equals(provided, nonce);
};

const greetings = ['Welcome', 'Welcome back', 'Good to see you', 'Hello again', 'Nice to have you back'];

const randomGreeting = () => greetings[Math.floor(Math.random() * greetings.length)];

app.use(secureHeaders());

const renderSignIn = (c, data) =>
  eta.render('signin', {
    heading: randomGreeting(),
    email: '',
    error: '',
    csrfToken: issueCsrfToken(c),
    ...data
  });

app.get('/', (c) => {
  if (readSession(getCookie(c, SESSION_COOKIE))) {
    return c.redirect('/profile', 303);
  }
  return c.html(renderSignIn(c, {}));
});

app.post('/', async (c) => {
  const body = await c.req.parseBody();
  const email = typeof body.email === 'string' ? body.email : '';
  const password = typeof body.password === 'string' ? body.password : '';
  if (!verifyCsrfToken(c, body.csrf)) {
    return c.html(renderSignIn(c, { email, error: 'Your session expired. Please try again.' }), 403);
  }
  const user = findUser(email);
  if (!verifyPassword(user, password)) {
    return c.html(renderSignIn(c, { email, error: 'Invalid email or password.' }), 401);
  }
  setCookie(c, SESSION_COOKIE, createSession(user.email), cookieOptions(SESSION_MAX_AGE));
  return c.redirect('/profile', 303);
});

const renderRegister = (c, data) =>
  eta.render('register', { email: '', error: '', csrfToken: issueCsrfToken(c), ...data });

app.get('/register', (c) => {
  if (readSession(getCookie(c, SESSION_COOKIE))) {
    return c.redirect('/profile', 303);
  }
  return c.html(renderRegister(c, {}));
});

app.post('/register', async (c) => {
  const body = await c.req.parseBody();
  const email = typeof body.email === 'string' ? body.email.trim() : '';
  const password = typeof body.password === 'string' ? body.password : '';
  if (!verifyCsrfToken(c, body.csrf)) {
    return c.html(renderRegister(c, { email, error: 'Your session expired. Please try again.' }), 403);
  }
  if (!email.includes('@')) {
    return c.html(renderRegister(c, { email, error: 'Enter a valid email address.' }), 400);
  }
  if (password.length < MIN_PASSWORD_LENGTH) {
    return c.html(
      renderRegister(c, { email, error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters.` }),
      400
    );
  }
  return c.redirect('/', 303);
});

app.get('/profile', (c) => {
  const user = readSession(getCookie(c, SESSION_COOKIE));
  if (!user) {
    return c.redirect('/', 303);
  }
  return c.html(eta.render('profile', { email: user.email }));
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
