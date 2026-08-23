const path = require('node:path');
const { createHmac, randomBytes, scryptSync, timingSafeEqual } = require('node:crypto');
const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { getConnInfo } = require('@hono/node-server/conninfo');
const { bodyLimit } = require('hono/body-limit');
const { secureHeaders } = require('hono/secure-headers');
const { deleteCookie, getCookie, setCookie } = require('hono/cookie');
const { Eta } = require('eta');

const app = new Hono();
const eta = new Eta({ views: path.join(__dirname, 'views') });

const MIN_PASSWORD_LENGTH = 8;
const MAX_PASSWORD_LENGTH = 128;
const MAX_BODY_SIZE = 16 * 1024;

const SESSION_COOKIE = 'session';
const SESSION_MAX_AGE = 7 * 60 * 60;
const CSRF_COOKIE = 'csrf';
const CSRF_MAX_AGE = 2 * 60 * 60;
const MIN_SECRET_LENGTH = 32;

const AUTH_WINDOW = 15 * 60 * 1000;
const AUTH_MAX_PER_ACCOUNT = 5;
const AUTH_MAX_PER_ADDRESS = 20;
const AUTH_TRACKED_KEYS = 20000;

const isDevelopment = process.env.NODE_ENV === 'development';
const trustProxy = process.env.TRUST_PROXY === 'true';
const hmacSecret = process.env.HMAC_SECRET || (isDevelopment ? randomBytes(32).toString('hex') : '');

if (hmacSecret.length < MIN_SECRET_LENGTH) {
  console.error(`HMAC_SECRET is required and must be at least ${MIN_SECRET_LENGTH} characters`);
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

const attempts = new Map();

const clientAddress = (c) => {
  if (trustProxy) {
    const forwarded = c.req.header('x-forwarded-for');
    if (forwarded) {
      return forwarded.split(',')[0].trim();
    }
  }
  return getConnInfo(c).remote.address || 'unknown';
};

const freshAttempts = (key, now) => (attempts.get(key) || []).filter((at) => at > now - AUTH_WINDOW);

const tooManyAttempts = (limits) => {
  const now = Date.now();
  return limits.some(([key, max]) => freshAttempts(key, now).length >= max);
};

const recordAttempt = (limits) => {
  const now = Date.now();
  for (const [key, hits] of attempts) {
    if (hits.every((at) => at <= now - AUTH_WINDOW)) {
      attempts.delete(key);
    }
  }
  for (const [key] of limits) {
    if (!attempts.has(key) && attempts.size >= AUTH_TRACKED_KEYS) {
      attempts.delete(attempts.keys().next().value);
    }
    attempts.set(key, [...freshAttempts(key, now), now]);
  }
};

const clearAttempts = (limits) => {
  for (const [key] of limits) {
    attempts.delete(key);
  }
};

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
app.post('*', bodyLimit({ maxSize: MAX_BODY_SIZE }));

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
  const limits = [
    [`signin:${clientAddress(c)}`, AUTH_MAX_PER_ADDRESS],
    [`account:${email.trim().toLowerCase()}`, AUTH_MAX_PER_ACCOUNT]
  ];
  if (tooManyAttempts(limits)) {
    c.header('Retry-After', String(AUTH_WINDOW / 1000));
    return c.html(renderSignIn(c, { email, error: 'Too many attempts. Please try again later.' }), 429);
  }
  if (!verifyCsrfToken(c, body.csrf)) {
    recordAttempt(limits);
    return c.html(renderSignIn(c, { email, error: 'Your session expired. Please try again.' }), 403);
  }
  const user = findUser(email);
  if (password.length > MAX_PASSWORD_LENGTH || !verifyPassword(user, password)) {
    recordAttempt(limits);
    return c.html(renderSignIn(c, { email, error: 'Invalid email or password.' }), 401);
  }
  clearAttempts(limits);
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
  const limits = [[`register:${clientAddress(c)}`, AUTH_MAX_PER_ADDRESS]];
  if (tooManyAttempts(limits)) {
    c.header('Retry-After', String(AUTH_WINDOW / 1000));
    return c.html(renderRegister(c, { email, error: 'Too many attempts. Please try again later.' }), 429);
  }
  recordAttempt(limits);
  if (!verifyCsrfToken(c, body.csrf)) {
    return c.html(renderRegister(c, { email, error: 'Your session expired. Please try again.' }), 403);
  }
  if (!email.includes('@')) {
    return c.html(renderRegister(c, { email, error: 'Enter a valid email address.' }), 400);
  }
  if (password.length < MIN_PASSWORD_LENGTH || password.length > MAX_PASSWORD_LENGTH) {
    return c.html(
      renderRegister(c, {
        email,
        error: `Password must be between ${MIN_PASSWORD_LENGTH} and ${MAX_PASSWORD_LENGTH} characters.`
      }),
      400
    );
  }
  if (findUser(email)) {
    return c.html(renderRegister(c, { email, error: 'That email address is already registered.' }), 409);
  }
  const user = createUser(email, password);
  return c.html(eta.render('registered', { email: user.email }), 201);
});

app.get('/profile', (c) => {
  const user = readSession(getCookie(c, SESSION_COOKIE));
  if (!user) {
    return c.redirect('/', 303);
  }
  return c.html(eta.render('profile', { email: user.email, csrfToken: issueCsrfToken(c) }));
});

app.post('/signout', async (c) => {
  const body = await c.req.parseBody();
  if (!verifyCsrfToken(c, body.csrf)) {
    return c.redirect('/profile', 303);
  }
  deleteCookie(c, SESSION_COOKIE, { path: '/' });
  deleteCookie(c, CSRF_COOKIE, { path: '/' });
  return c.redirect('/', 303);
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
