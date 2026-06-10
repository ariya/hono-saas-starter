const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const { deleteCookie, getCookie, setCookie } = require('hono/cookie');
const { getConnInfo } = require('@hono/node-server/conninfo');

const app = new Hono();
const eta = new Eta({ views: __dirname });

const SESSION_TTL_SECONDS = 7 * 60 * 60;
const isProduction = process.env.NODE_ENV === 'production';
if (isProduction && !process.env.HMAC_SECRET) {
  console.error('HMAC_SECRET environment variable is required in production');
  process.exit(1);
}

const hmacSecret = process.env.HMAC_SECRET ? Buffer.from(process.env.HMAC_SECRET) : crypto.randomBytes(32);

const sign = (value) => crypto.createHmac('sha256', hmacSecret).update(value).digest('base64url');

const CSRF_TTL_SECONDS = 2 * 60 * 60;

const createCsrfToken = () => {
  const expires = Date.now() + CSRF_TTL_SECONDS * 1000;
  const payload = `csrf.${expires}`;
  return `${expires}.${sign(payload)}`;
};

const verifyCsrfToken = (token) => {
  if (typeof token !== 'string') {
    return false;
  }
  const parts = token.split('.');
  if (parts.length !== 2) {
    return false;
  }
  const [expires, signature] = parts;
  const expected = sign(`csrf.${expires}`);
  const given = Buffer.from(signature);
  if (given.length !== Buffer.byteLength(expected) || !crypto.timingSafeEqual(given, Buffer.from(expected))) {
    return false;
  }
  return /^\d+$/.test(expires) && Number(expires) >= Date.now();
};

const createSessionToken = (email) => {
  const expires = Date.now() + SESSION_TTL_SECONDS * 1000;
  const payload = `${Buffer.from(email).toString('base64url')}.${expires}`;
  return `${payload}.${sign(payload)}`;
};

const verifySessionToken = (token) => {
  if (typeof token !== 'string') {
    return null;
  }
  const parts = token.split('.');
  if (parts.length !== 3) {
    return null;
  }
  const [encodedEmail, expires, signature] = parts;
  const payload = `${encodedEmail}.${expires}`;
  const expected = sign(payload);
  const given = Buffer.from(signature);
  if (given.length !== Buffer.byteLength(expected) || !crypto.timingSafeEqual(given, Buffer.from(expected))) {
    return null;
  }
  if (!/^\d+$/.test(expires) || Number(expires) < Date.now()) {
    return null;
  }
  return Buffer.from(encodedEmail, 'base64url').toString();
};

const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const RATE_LIMIT_MAX_ATTEMPTS = 20;
const RATE_LIMIT_MAX_ENTRIES = 10000;

const attemptLog = new Map();

const isRateLimited = (key) => {
  const now = Date.now();
  if (attemptLog.size > RATE_LIMIT_MAX_ENTRIES) {
    for (const [k, entry] of attemptLog) {
      if (now - entry.start > RATE_LIMIT_WINDOW_MS) {
        attemptLog.delete(k);
      }
    }
  }
  const entry = attemptLog.get(key);
  if (!entry || now - entry.start > RATE_LIMIT_WINDOW_MS) {
    attemptLog.set(key, { start: now, count: 1 });
    return false;
  }
  entry.count += 1;
  return entry.count > RATE_LIMIT_MAX_ATTEMPTS;
};

const clientKey = (c) => {
  try {
    return getConnInfo(c).remote.address || 'unknown';
  } catch {
    return 'unknown';
  }
};

const users = new Map();

const saveUser = (email, passwordHash, salt) => {
  users.set(email.toLowerCase(), { email: email.toLowerCase(), passwordHash, salt });
};

const findUser = (email) => users.get(String(email).toLowerCase());

const EMAIL_MAX_LENGTH = 254;
const PASSWORD_MAX_LENGTH = 128;

const withinInputLimits = (email, password) =>
  email.length <= EMAIL_MAX_LENGTH && password.length <= PASSWORD_MAX_LENGTH;

const scrypt = promisify(crypto.scrypt);

const hashPassword = (password, salt) => scrypt(String(password), salt, 64);

const verifyCredentials = async (email, password) => {
  const user = findUser(email);
  if (!user) {
    return null;
  }
  const candidate = await hashPassword(password, user.salt);
  return crypto.timingSafeEqual(candidate, user.passwordHash) ? user : null;
};

app.use(secureHeaders());

const welcomeTitles = ['Welcome', 'Welcome back', 'Good to see you', 'Hello again', 'Great to have you here'];

const pickWelcomeTitle = () => welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)];

const currentUser = (c) => {
  const email = verifySessionToken(getCookie(c, 'session'));
  return email ? findUser(email) : null;
};

const renderSignIn = (data = {}) =>
  eta.render('signin', { title: pickWelcomeTitle(), error: null, csrfToken: createCsrfToken(), ...data });

app.get('/', (c) => {
  if (currentUser(c)) {
    return c.redirect('/profile', 303);
  }
  return c.html(renderSignIn());
});

app.post('/signin', async (c) => {
  if (isRateLimited(clientKey(c))) {
    return c.html(renderSignIn({ error: 'Too many attempts. Please try again later.' }), 429);
  }
  const body = await c.req.parseBody();
  if (!verifyCsrfToken(body.csrf)) {
    return c.html(renderSignIn({ error: 'Your session expired. Please try again.' }), 403);
  }
  const email = String(body.email || '').trim();
  const password = String(body.password || '');
  if (!withinInputLimits(email, password)) {
    return c.html(renderSignIn({ error: 'Invalid email or password.' }), 401);
  }
  const user = await verifyCredentials(email, password);
  if (!user) {
    return c.html(renderSignIn({ error: 'Invalid email or password.' }), 401);
  }
  setCookie(c, 'session', createSessionToken(user.email), {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'Lax',
    path: '/',
    maxAge: SESSION_TTL_SECONDS
  });
  return c.redirect('/profile', 303);
});

const renderRegister = (data = {}) => eta.render('register', { error: null, csrfToken: createCsrfToken(), ...data });

app.get('/register', (c) => {
  if (currentUser(c)) {
    return c.redirect('/profile', 303);
  }
  return c.html(renderRegister());
});

app.post('/register', async (c) => {
  if (isRateLimited(clientKey(c))) {
    return c.html(renderRegister({ error: 'Too many attempts. Please try again later.' }), 429);
  }
  const body = await c.req.parseBody();
  if (!verifyCsrfToken(body.csrf)) {
    return c.html(renderRegister({ error: 'Your session expired. Please try again.' }), 403);
  }
  const email = String(body.email || '').trim();
  const password = String(body.password || '');
  if (!email) {
    return c.html(renderRegister({ error: 'Email is required.' }), 400);
  }
  if (!withinInputLimits(email, password)) {
    return c.html(renderRegister({ error: 'Email or password is too long.' }), 400);
  }
  if (password.length < 8) {
    return c.html(renderRegister({ error: 'Password must be at least 8 characters long.' }), 400);
  }
  if (findUser(email)) {
    return c.html(renderRegister({ error: 'An account with this email already exists.' }), 409);
  }
  const salt = crypto.randomBytes(16).toString('hex');
  saveUser(email, await hashPassword(password, salt), salt);
  return c.html(eta.render('registered', { email: email.toLowerCase() }));
});

app.get('/profile', (c) => {
  const user = currentUser(c);
  if (!user) {
    return c.redirect('/', 303);
  }
  return c.html(eta.render('profile', { email: user.email, csrfToken: createCsrfToken() }));
});

app.post('/signout', async (c) => {
  const body = await c.req.parseBody();
  if (verifyCsrfToken(body.csrf)) {
    deleteCookie(c, 'session', { path: '/' });
  }
  return c.redirect('/', 303);
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
