const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { getCookie, setCookie, deleteCookie } = require('hono/cookie');
const { getConnInfo } = require('@hono/node-server/conninfo');
const { Eta } = require('eta');

const eta = new Eta({ views: path.join(__dirname, 'views') });

const isProduction = process.env.NODE_ENV === 'production';

const SESSION_COOKIE = 'session';
const SESSION_MAX_AGE = 7 * 60 * 60;

const MIN_PASSWORD_LENGTH = 8;
const MAX_PASSWORD_LENGTH = 128;

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

const normalizeEmail = (value) => (typeof value === 'string' ? value.trim().toLowerCase() : '');

const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

const scrypt = promisify(crypto.scrypt);
const SCRYPT_KEYLEN = 64;

const hashPassword = async (password, salt) => {
  const useSalt = salt || crypto.randomBytes(16).toString('hex');
  const derived = (await scrypt(password, useSalt, SCRYPT_KEYLEN)).toString('hex');
  return { salt: useSalt, passwordHash: derived };
};

const DUMMY_SALT = crypto.randomBytes(16).toString('hex');
const DUMMY_HASH = crypto.scryptSync('', DUMMY_SALT, SCRYPT_KEYLEN).toString('hex');

const verifyPassword = async (user, password) => {
  const salt = user ? user.salt : DUMMY_SALT;
  const target = user ? user.passwordHash : DUMMY_HASH;
  const { passwordHash } = await hashPassword(password, salt);
  const a = Buffer.from(passwordHash, 'hex');
  const b = Buffer.from(target, 'hex');
  const match = a.length === b.length && crypto.timingSafeEqual(a, b);
  return Boolean(user) && match;
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

const CSRF_COOKIE = 'csrf';

const csrfCookieId = (c) => {
  let id = getCookie(c, CSRF_COOKIE);
  if (!id) {
    id = crypto.randomBytes(16).toString('hex');
    setCookie(c, CSRF_COOKIE, id, { httpOnly: true, secure: isProduction, sameSite: 'Lax', path: '/' });
  }
  return id;
};

const csrfToken = (c) => sign('csrf:' + csrfCookieId(c));

const verifyCsrf = (c, submitted) => {
  const id = getCookie(c, CSRF_COOKIE);
  if (!id || !submitted) return false;
  const expected = sign('csrf:' + id);
  const a = Buffer.from(submitted);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};

const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const RATE_LIMIT_MAX = 10;
const rateLimitHits = new Map();

const clientIp = (c) => {
  const forwarded = c.req.header('x-forwarded-for');
  if (forwarded) return forwarded.split(',')[0].trim();
  return getConnInfo(c).remote.address || 'unknown';
};

const isRateLimited = (key) => {
  const now = Date.now();
  if (rateLimitHits.size > 10000) {
    for (const [existing, value] of rateLimitHits) {
      if (now > value.reset) rateLimitHits.delete(existing);
    }
  }
  const entry = rateLimitHits.get(key);
  if (!entry || now > entry.reset) {
    rateLimitHits.set(key, { count: 1, reset: now + RATE_LIMIT_WINDOW_MS });
    return false;
  }
  entry.count += 1;
  return entry.count > RATE_LIMIT_MAX;
};

const app = new Hono();

app.use(
  secureHeaders({
    contentSecurityPolicy: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", 'https://cdn.jsdelivr.net'],
      imgSrc: ["'self'", 'data:'],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"]
    }
  })
);

const welcomeTitles = ['Welcome', 'Welcome back', 'Hello again', 'Good to see you', 'Glad you are here'];

const pickWelcome = () => welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)];

const renderSignin = (c, extra = {}) => eta.render('signin', { title: pickWelcome(), csrf: csrfToken(c), ...extra });

app.get('/', (c) => {
  if (currentUserEmail(c)) return c.redirect('/profile');
  return c.html(renderSignin(c));
});

app.post('/', async (c) => {
  if (isRateLimited(`signin:${clientIp(c)}`)) {
    return c.html(renderSignin(c, { error: 'Too many attempts. Please try again later.' }), 429);
  }
  const body = await c.req.parseBody();
  if (!verifyCsrf(c, typeof body._csrf === 'string' ? body._csrf : '')) {
    return c.html(renderSignin(c, { error: 'Invalid request. Please try again.' }), 403);
  }
  const email = normalizeEmail(body.email);
  const password = typeof body.password === 'string' ? body.password : '';
  if (password.length > MAX_PASSWORD_LENGTH) {
    return c.html(renderSignin(c, { error: 'Invalid email or password.' }), 401);
  }
  const user = findUser(email);
  if (!(await verifyPassword(user, password))) {
    return c.html(renderSignin(c, { error: 'Invalid email or password.' }), 401);
  }
  setCookie(c, SESSION_COOKIE, createSession(user.email), sessionCookieOptions());
  return c.redirect('/profile');
});

const currentUserEmail = (c) => {
  const email = readSession(getCookie(c, SESSION_COOKIE));
  if (!email || !findUser(email)) return null;
  return email;
};

const renderRegister = (c, extra = {}) => eta.render('register', { csrf: csrfToken(c), ...extra });

app.get('/register', (c) => {
  if (currentUserEmail(c)) return c.redirect('/profile');
  return c.html(renderRegister(c));
});

app.post('/register', async (c) => {
  if (isRateLimited(`register:${clientIp(c)}`)) {
    return c.html(renderRegister(c, { error: 'Too many attempts. Please try again later.' }), 429);
  }
  const body = await c.req.parseBody();
  if (!verifyCsrf(c, typeof body._csrf === 'string' ? body._csrf : '')) {
    return c.html(renderRegister(c, { error: 'Invalid request. Please try again.' }), 403);
  }
  const email = normalizeEmail(body.email);
  const password = typeof body.password === 'string' ? body.password : '';
  if (!isValidEmail(email)) {
    return c.html(renderRegister(c, { error: 'Enter a valid email address.' }), 400);
  }
  if (password.length < MIN_PASSWORD_LENGTH) {
    return c.html(renderRegister(c, { error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters.` }), 400);
  }
  if (password.length > MAX_PASSWORD_LENGTH) {
    return c.html(renderRegister(c, { error: `Password must be at most ${MAX_PASSWORD_LENGTH} characters.` }), 400);
  }
  if (findUser(email)) {
    return c.html(renderRegister(c, { error: 'An account with that email already exists.' }), 409);
  }
  const { passwordHash, salt } = await hashPassword(password);
  createUser(email, passwordHash, salt);
  return c.html(eta.render('success', { message: 'Your account is ready. You can now sign in.' }));
});

app.get('/profile', (c) => {
  const email = currentUserEmail(c);
  if (!email) return c.redirect('/');
  return c.html(eta.render('profile', { email, csrf: csrfToken(c) }));
});

app.post('/signout', async (c) => {
  const body = await c.req.parseBody();
  if (!verifyCsrf(c, typeof body._csrf === 'string' ? body._csrf : '')) {
    return c.redirect('/profile');
  }
  deleteCookie(c, SESSION_COOKIE, { path: '/' });
  return c.redirect('/');
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
