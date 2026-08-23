const path = require('node:path');
const { createHmac, randomBytes, scryptSync, timingSafeEqual } = require('node:crypto');
const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { setCookie } = require('hono/cookie');
const { Eta } = require('eta');

const app = new Hono();
const eta = new Eta({ views: path.join(__dirname, 'views') });

const SESSION_COOKIE = 'session';
const SESSION_MAX_AGE = 7 * 60 * 60;
const isDevelopment = process.env.NODE_ENV === 'development';
const hmacSecret = randomBytes(32);

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
  const payload = `${parts[0]}.${parts[1]}`;
  const expected = Buffer.from(sign(payload));
  const actual = Buffer.from(parts[2]);
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
    return null;
  }
  const expiresAt = Number(parts[1]);
  if (!Number.isFinite(expiresAt) || expiresAt < Date.now()) {
    return null;
  }
  return findUser(Buffer.from(parts[0], 'base64url').toString()) || null;
};

const greetings = ['Welcome', 'Welcome back', 'Good to see you', 'Hello again', 'Nice to have you back'];

const randomGreeting = () => greetings[Math.floor(Math.random() * greetings.length)];

app.use(secureHeaders());

const renderSignIn = (data) => eta.render('signin', { heading: randomGreeting(), email: '', error: '', ...data });

app.get('/', (c) => c.html(renderSignIn({})));

app.post('/', async (c) => {
  const body = await c.req.parseBody();
  const email = typeof body.email === 'string' ? body.email : '';
  const password = typeof body.password === 'string' ? body.password : '';
  const user = findUser(email);
  if (!verifyPassword(user, password)) {
    return c.html(renderSignIn({ email, error: 'Invalid email or password.' }), 401);
  }
  setCookie(c, SESSION_COOKIE, createSession(user.email), {
    path: '/',
    httpOnly: true,
    secure: !isDevelopment,
    sameSite: 'Lax',
    maxAge: SESSION_MAX_AGE
  });
  return c.redirect('/profile', 303);
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
