const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');
const { createHmac, scrypt, timingSafeEqual } = require('node:crypto');
const { promisify } = require('node:util');
const path = require('node:path');
const { setCookie } = require('hono/cookie');

const scryptAsync = promisify(scrypt);

const SESSION_COOKIE = 'session';
const SESSION_TTL = 7 * 60 * 60;
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

const signSession = (payload) => createHmac('sha256', hmacSecret).update(payload).digest('base64url');

const createSession = (email) => {
  const payload = Buffer.from(
    JSON.stringify({ sub: email, exp: Math.floor(Date.now() / 1000) + SESSION_TTL })
  ).toString('base64url');
  return `${payload}.${signSession(payload)}`;
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
  return c.html(eta.render('signin', { title: 'Sign In', welcome, email: '', error: '', ...data }), status);
};

app.get('/', (c) => renderSignin(c));

app.post('/', async (c) => {
  const body = await c.req.parseBody();
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

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
