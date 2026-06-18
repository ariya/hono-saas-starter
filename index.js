const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { bodyLimit } = require('hono/body-limit');
const { getCookie, getSignedCookie, setCookie, setSignedCookie, deleteCookie } = require('hono/cookie');
const { Eta } = require('eta');
const path = require('node:path');
const crypto = require('node:crypto');

const eta = new Eta({ views: path.join(__dirname, 'views'), cache: false });

const isDev = process.env.NODE_ENV !== 'production';

const HMAC_SECRET = process.env.HMAC_SECRET || (isDev ? crypto.randomBytes(32).toString('hex') : null);
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

const DUMMY_SALT = crypto.randomBytes(16).toString('hex');
const DUMMY_USER = { email: '', salt: DUMMY_SALT, passwordHash: hashPassword('dummy-password', DUMMY_SALT) };

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

const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX = 10;
const loginAttempts = new Map();

const recentAttempts = (key) => {
  const now = Date.now();
  const list = (loginAttempts.get(key) || []).filter((t) => now - t < RATE_LIMIT_WINDOW_MS);
  loginAttempts.set(key, list);
  return list;
};

const recordAttempt = (key) => {
  recentAttempts(key).push(Date.now());
};

const isRateLimited = (key) => recentAttempts(key).length >= RATE_LIMIT_MAX;

const getClientIp = (c) => c.req.raw.socket?.remoteAddress || 'unknown';

createUser('demo@example.com', 'password123456');

const app = new Hono();

app.use(secureHeaders());
app.use(bodyLimit({ maxSize: 16 * 1024 }));

const renderSignin = (data) => {
  const welcome = data.welcome || WELCOME_TITLES[Math.floor(Math.random() * WELCOME_TITLES.length)];
  return eta.render('signin', { csrfToken: createCsrfToken(), welcome, ...data });
};

const renderRegister = (data) => {
  return eta.render('register', { csrfToken: createCsrfToken(), ...data });
};

const renderProfile = (data) => {
  return eta.render('profile', { csrfToken: createCsrfToken(), ...data });
};

app.get('/', async (c) => {
  const user = await getCurrentUser(c);
  if (user) return c.redirect('/profile');
  return c.html(renderSignin({}));
});

app.get('/register', async (c) => {
  const user = await getCurrentUser(c);
  if (user) return c.redirect('/profile');
  return c.html(renderRegister({}));
});

const MIN_PASSWORD_LENGTH = 8;
const MAX_PASSWORD_LENGTH = 1024;

app.post('/register', csrfGuard, async (c) => {
  const body = await c.req.parseBody();
  const email = String(body.email || '').toLowerCase();
  const password = String(body.password || '');
  if (password.length < MIN_PASSWORD_LENGTH) {
    return c.html(
      renderRegister({ email, error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters long.` }),
      400
    );
  }
  if (password.length > MAX_PASSWORD_LENGTH) {
    return c.html(
      renderRegister({ email, error: `Password must be at most ${MAX_PASSWORD_LENGTH} characters long.` }),
      400
    );
  }
  if (findUser(email)) {
    return c.html(renderRegister({ email, error: 'An account with this email already exists.' }), 400);
  }
  createUser(email, password);
  return c.html(renderRegister({ success: 'Account created. Redirecting to sign in…', redirect: '/' }), 201);
});

app.post('/signin', csrfGuard, async (c) => {
  const body = await c.req.parseBody();
  const email = String(body.email || '').toLowerCase();
  const password = String(body.password || '');
  const ip = getClientIp(c);
  if (isRateLimited(`ip:${ip}`) || isRateLimited(`email:${email}`)) {
    return c.text('Too many sign-in attempts. Please try again later.', 429);
  }
  recordAttempt(`ip:${ip}`);
  recordAttempt(`email:${email}`);
  if (password.length > MAX_PASSWORD_LENGTH) {
    return c.html(renderSignin({ email, error: 'Invalid email or password.' }), 401);
  }
  const existing = findUser(email);
  const user = existing || DUMMY_USER;
  const valid = verifyPassword(password, user);
  if (!existing || !valid) {
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
  return c.html(renderProfile({ email: user.email }));
});

app.post('/signout', csrfGuard, (c) => {
  deleteCookie(c, 'session', {
    path: '/',
    httpOnly: true,
    sameSite: 'Lax',
    secure: !isDev
  });
  return c.redirect('/');
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
