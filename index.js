const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { getCookie, getSignedCookie, setCookie, setSignedCookie, deleteCookie } = require('hono/cookie');
const { Eta } = require('eta');
const path = require('node:path');
const crypto = require('node:crypto');

const eta = new Eta({ views: path.join(__dirname, 'views'), cache: false });

const isDev = process.env.NODE_ENV !== 'production';

const HMAC_SECRET = process.env.HMAC_SECRET || (isDev ? 'dev-insecure-secret' : null);
if (!HMAC_SECRET) {
  throw new Error('HMAC_SECRET environment variable is required in production');
}

const WELCOME_TITLES = ['Welcome back', 'Hello again', 'Good to see you', 'We missed you', 'Glad you are here'];

const users = new Map();

const hashPassword = (password, salt) => {
  return crypto.scryptSync(password, salt, 64).toString('hex');
};

const createUser = (email, password) => {
  const salt = crypto.randomBytes(16).toString('hex');
  const user = { email, salt, passwordHash: hashPassword(password, salt) };
  users.set(email, user);
  return user;
};

const findUser = (email) => users.get(email);

const verifyPassword = (password, user) => {
  return crypto.timingSafeEqual(
    Buffer.from(user.passwordHash, 'hex'),
    Buffer.from(hashPassword(password, user.salt), 'hex')
  );
};

const createCsrfToken = () => {
  const payload = String(Math.floor(Date.now() / 1000));
  const sig = crypto.createHmac('sha256', HMAC_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
};

const verifyCsrfToken = (token) => {
  if (!token || typeof token !== 'string') return false;
  const idx = token.lastIndexOf('.');
  if (idx < 1) return false;
  const payload = token.slice(0, idx);
  const sig = token.slice(idx + 1);
  const expected = crypto.createHmac('sha256', HMAC_SECRET).update(payload).digest('base64url');
  if (sig.length !== expected.length) return false;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return false;
  const issued = Number(payload);
  if (!Number.isFinite(issued)) return false;
  return Math.floor(Date.now() / 1000) - issued <= 3600;
};

const csrfGuard = async (c, next) => {
  const body = await c.req.parseBody();
  if (!verifyCsrfToken(body.csrf)) {
    return c.text('Invalid or missing CSRF token', 403);
  }
  await next();
};

const getCurrentUser = async (c) => {
  const email = await getSignedCookie(c, HMAC_SECRET, 'session');
  if (!email) return null;
  return findUser(email) || null;
};

createUser('demo@example.com', 'password123456');

const app = new Hono();

app.use(secureHeaders());

const renderSignin = (data) => {
  const welcome = data.welcome || WELCOME_TITLES[Math.floor(Math.random() * WELCOME_TITLES.length)];
  return eta.render('signin', { csrfToken: createCsrfToken(), welcome, ...data });
};

app.get('/', (c) => {
  return c.html(renderSignin({}));
});

app.post('/signin', csrfGuard, async (c) => {
  const body = await c.req.parseBody();
  const email = String(body.email || '').toLowerCase();
  const password = String(body.password || '');
  const user = findUser(email);
  if (!user || !verifyPassword(password, user)) {
    return c.html(renderSignin({ email, error: 'Invalid email or password.' }), 401);
  }
  await setSignedCookie(c, 'session', user.email, HMAC_SECRET, {
    path: '/',
    httpOnly: true,
    sameSite: 'Lax',
    secure: !isDev,
    maxAge: 7 * 60 * 60
  });
  return c.redirect('/profile');
});

app.get('/profile', async (c) => {
  const user = await getCurrentUser(c);
  if (!user) return c.redirect('/');
  return c.html(eta.render('profile', { email: user.email }));
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
