const crypto = require('node:crypto');
const { promisify } = require('node:util');
const path = require('node:path');
const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { getConnInfo } = require('@hono/node-server/conninfo');
const { secureHeaders } = require('hono/secure-headers');
const { setCookie, getCookie, deleteCookie } = require('hono/cookie');
const { Eta } = require('eta');

const app = new Hono();
const eta = new Eta({ views: path.join(__dirname, 'views') });
const isDevelopment = process.env.NODE_ENV === 'development';
const isProduction = process.env.NODE_ENV === 'production';

function resolveSessionSecret() {
  const secret = process.env.HMAC_SECRET;
  if (secret && secret.length >= 32) return secret;
  if (isProduction) {
    throw new Error('HMAC_SECRET must be set to a value of at least 32 characters in production');
  }
  return crypto.randomBytes(32).toString('hex');
}

const sessionSecret = resolveSessionSecret();
const SESSION_MAX_AGE = 7 * 60 * 60;
const CSRF_COOKIE_MAX_AGE = 60 * 60;
const scrypt = promisify(crypto.scrypt);
const SCRYPT_OPTIONS = { N: 2 ** 17, r: 8, p: 1, maxmem: 160 * 1024 * 1024 };
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const RATE_LIMIT_MAX = 10;
const MAX_USERS = 10000;
const EMAIL_MAX_LENGTH = 254;
const PASSWORD_MIN_LENGTH = 8;
const PASSWORD_MAX_LENGTH = 200;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const rateLimitStore = new Map();
const revokedSessions = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitStore) {
    if (now > entry.resetAt) rateLimitStore.delete(key);
  }
  for (const [jti, expiry] of revokedSessions) {
    if (now > expiry) revokedSessions.delete(jti);
  }
}, RATE_LIMIT_WINDOW_MS).unref();

const welcomeTitles = ['Welcome', 'Welcome back', 'Hello there', 'Good to see you', 'Sign in to continue'];
const users = new Map();
const dummyUser = {
  email: '',
  salt: crypto.randomBytes(16).toString('hex'),
  passwordHash: crypto.randomBytes(64).toString('hex')
};

function pickWelcomeTitle() {
  return welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)];
}

function getUser(email) {
  return users.get(String(email).toLowerCase());
}

function normalizeEmail(value) {
  const email = String(value || '')
    .trim()
    .toLowerCase();
  if (!email || email.length > EMAIL_MAX_LENGTH || !EMAIL_PATTERN.test(email)) return null;
  return email;
}

async function createUser(email, password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const passwordHash = (await scrypt(String(password), salt, 64, SCRYPT_OPTIONS)).toString('hex');
  const user = { email: String(email).toLowerCase(), passwordHash, salt };
  users.set(user.email, user);
  return user;
}

async function verifyPassword(user, password) {
  const expected = Buffer.from(user.passwordHash, 'hex');
  const candidate = await scrypt(String(password), user.salt, 64, SCRYPT_OPTIONS);
  return candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected);
}

function encodeSession(email) {
  const payload = Buffer.from(
    JSON.stringify({ email, jti: crypto.randomBytes(16).toString('hex'), exp: Date.now() + SESSION_MAX_AGE * 1000 })
  ).toString('base64url');
  const signature = crypto.createHmac('sha256', sessionSecret).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

function decodeSession(token) {
  if (!token) return null;
  const [payload, signature] = String(token).split('.');
  if (!payload || !signature) return null;
  const expected = crypto.createHmac('sha256', sessionSecret).update(payload).digest('base64url');
  const signatureBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expected);
  if (signatureBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(signatureBuffer, expectedBuffer)) {
    return null;
  }
  let data;
  try {
    data = JSON.parse(Buffer.from(payload, 'base64url').toString());
  } catch {
    return null;
  }
  if (
    !data ||
    typeof data.email !== 'string' ||
    typeof data.jti !== 'string' ||
    typeof data.exp !== 'number' ||
    data.exp < Date.now()
  ) {
    return null;
  }
  if (revokedSessions.has(data.jti) || !getUser(data.email)) return null;
  return { email: data.email, jti: data.jti, exp: data.exp };
}

function createCsrfToken(c) {
  let token = getCookie(c, 'csrf');
  if (!token) {
    token = crypto.randomBytes(32).toString('hex');
    setCookie(c, 'csrf', token, {
      httpOnly: true,
      secure: !isDevelopment,
      sameSite: 'Lax',
      path: '/',
      maxAge: CSRF_COOKIE_MAX_AGE
    });
  }
  return token;
}

function verifyCsrfToken(c, token) {
  const expected = getCookie(c, 'csrf');
  if (!expected || !token) return false;
  const tokenBuffer = Buffer.from(String(token));
  const expectedBuffer = Buffer.from(expected);
  return tokenBuffer.length === expectedBuffer.length && crypto.timingSafeEqual(tokenBuffer, expectedBuffer);
}

function renderSignin(c, status, error) {
  return c.html(eta.render('signin', { title: pickWelcomeTitle(), csrfToken: createCsrfToken(c), error }), status);
}

function isRateLimited(key) {
  const now = Date.now();
  const entry = rateLimitStore.get(key);
  if (!entry || now > entry.resetAt) {
    rateLimitStore.set(key, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return false;
  }
  entry.count += 1;
  return entry.count > RATE_LIMIT_MAX;
}

function clientKey(c, scope) {
  const info = getConnInfo(c);
  return `${scope}:${info.remote.address || 'unknown'}`;
}

function renderRegister(c, status, error) {
  return c.html(eta.render('register', { csrfToken: createCsrfToken(c), error }), status);
}

app.use(
  secureHeaders({
    contentSecurityPolicy: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", 'https://unpkg.com'],
      fontSrc: ["'self'", 'https://unpkg.com', 'data:'],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"]
    }
  })
);

app.get('/', (c) => {
  if (decodeSession(getCookie(c, 'session'))) return c.redirect('/profile');
  return renderSignin(c, 200);
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

app.get('/register', (c) => renderRegister(c, 200));

app.get('/signout', (c) => {
  const session = decodeSession(getCookie(c, 'session'));
  if (session) revokedSessions.set(session.jti, session.exp);
  deleteCookie(c, 'session', { path: '/' });
  return c.redirect('/');
});

app.get('/profile', (c) => {
  const session = decodeSession(getCookie(c, 'session'));
  if (!session) return c.redirect('/');
  return c.html(eta.render('profile', { email: session.email }));
});

app.post('/signin', async (c) => {
  const body = await c.req.parseBody();
  if (isRateLimited(clientKey(c, 'signin'))) {
    return renderSignin(c, 429, 'Too many sign-in attempts. Please try again later.');
  }
  if (!verifyCsrfToken(c, body._csrf)) {
    return renderSignin(c, 403, 'Your form session expired. Please try again.');
  }
  const email = String(body.email || '')
    .trim()
    .toLowerCase();
  const password = String(body.password || '');
  if (!email || email.length > EMAIL_MAX_LENGTH || password.length > PASSWORD_MAX_LENGTH) {
    return renderSignin(c, 401, 'Invalid email or password.');
  }
  const user = getUser(email);
  const valid = await verifyPassword(user || dummyUser, password);
  if (!user || !valid) {
    return renderSignin(c, 401, 'Invalid email or password.');
  }
  setCookie(c, 'session', encodeSession(user.email), {
    httpOnly: true,
    secure: !isDevelopment,
    sameSite: 'Lax',
    path: '/',
    maxAge: SESSION_MAX_AGE
  });
  return c.redirect('/profile');
});

app.post('/register', async (c) => {
  const body = await c.req.parseBody();
  if (isRateLimited(clientKey(c, 'register'))) {
    return renderRegister(c, 429, 'Too many registration attempts. Please try again later.');
  }
  if (!verifyCsrfToken(c, body._csrf)) {
    return renderRegister(c, 403, 'Your form session expired. Please try again.');
  }
  const email = normalizeEmail(body.email);
  const password = String(body.password || '');
  if (!email) {
    return renderRegister(c, 400, 'Please enter a valid email address.');
  }
  if (password.length < PASSWORD_MIN_LENGTH) {
    return renderRegister(c, 400, `Password must be at least ${PASSWORD_MIN_LENGTH} characters long.`);
  }
  if (password.length > PASSWORD_MAX_LENGTH) {
    return renderRegister(c, 400, `Password must be at most ${PASSWORD_MAX_LENGTH} characters long.`);
  }
  if (getUser(email)) {
    await verifyPassword(dummyUser, password);
    return c.html(eta.render('register-success', {}));
  }
  if (users.size >= MAX_USERS) {
    return renderRegister(c, 503, 'Registration is temporarily unavailable. Please try again later.');
  }
  await createUser(email, password);
  return c.html(eta.render('register-success', {}));
});

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
