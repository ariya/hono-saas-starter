const path = require('path');
const crypto = require('crypto');
const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { setCookie, deleteCookie } = require('hono/cookie');
const { Eta } = require('eta');

const eta = new Eta({ views: path.join(__dirname, 'views'), cache: true });

const users = new Map();

const hashPassword = (password, salt) => {
  return crypto.scryptSync(password, salt, 64).toString('hex');
};

const verifyPassword = (password, salt, expectedHex) => {
  const candidate = hashPassword(password, salt);
  const a = Buffer.from(candidate, 'hex');
  const b = Buffer.from(expectedHex, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
};

const SESSION_COOKIE = 'sid';
const SESSION_MAX_AGE_SECONDS = 7 * 60 * 60;
const IS_PROD = process.env.NODE_ENV === 'production';

const sessionCookieOptions = () => ({
  httpOnly: true,
  secure: IS_PROD,
  sameSite: 'Lax',
  path: '/',
  maxAge: SESSION_MAX_AGE_SECONDS
});

const app = new Hono();

app.use(secureHeaders());

const WELCOME_TITLES = ['Welcome', 'Welcome back', 'Hello again', 'Good to see you', 'Sign in to continue'];

const pickWelcomeTitle = () => WELCOME_TITLES[Math.floor(Math.random() * WELCOME_TITLES.length)];

app.get('/', (c) => {
  return c.html(eta.render('signin', { title: pickWelcomeTitle(), error: null, email: '' }));
});

app.post('/signin', async (c) => {
  const body = await c.req.parseBody();
  const email = String(body.email || '')
    .trim()
    .toLowerCase();
  const password = String(body.password || '');
  const user = users.get(email);
  const ok = user && verifyPassword(password, user.salt, user.hash);
  if (!ok) {
    return c.html(eta.render('signin', { title: pickWelcomeTitle(), error: 'Invalid email or password.', email }), 401);
  }
  setCookie(c, SESSION_COOKIE, email, sessionCookieOptions());
  return c.redirect('/profile', 303);
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
