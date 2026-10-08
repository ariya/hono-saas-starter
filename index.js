const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');
const { createHmac, randomBytes, scrypt, timingSafeEqual } = require('node:crypto');
const { promisify } = require('node:util');
const path = require('node:path');
const { deleteCookie, getCookie, setCookie } = require('hono/cookie');
const { bodyLimit } = require('hono/body-limit');

const scryptAsync = promisify(scrypt);

const SESSION_COOKIE = 'session';
const CSRF_COOKIE = 'csrf';
const SESSION_TTL = 7 * 60 * 60;
const CSRF_TTL = 2 * 60 * 60;
const MIN_PASSWORD_LENGTH = 8;
const MAX_PASSWORD_LENGTH = 128;
const MAX_EMAIL_LENGTH = 254;
const MAX_BODY_SIZE = 4 * 1024;
const MAX_TRACKED_CLIENTS = 10000;
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const isDevelopment = process.env.NODE_ENV === 'development';
const hmacSecret = process.env.HMAC_SECRET;

if (!hmacSecret || hmacSecret.length < 32) {
  throw new Error('HMAC_SECRET environment variable must be at least 32 characters');
}

const app = new Hono();
const eta = new Eta({ views: path.join(__dirname, 'views') });
const users = new Map();

app.use(secureHeaders());
app.use(bodyLimit({ maxSize: MAX_BODY_SIZE, onError: (c) => c.text('Payload too large', 413) }));

const welcomeTitles = ['Welcome', 'Welcome back', 'Hello there', 'Good to see you', 'Nice to have you here'];

const hashPassword = async (password, salt) => (await scryptAsync(password, salt, 64)).toString('hex');

const sign = (value) => createHmac('sha256', hmacSecret).update(value).digest('base64url');

const createSession = (user) => {
  const payload = Buffer.from(
    JSON.stringify({ sub: user.email, ver: user.sessionVersion, exp: Math.floor(Date.now() / 1000) + SESSION_TTL })
  ).toString('base64url');
  return `${payload}.${sign(`session.${payload}`)}`;
};

const verifySession = (token) => {
  if (!token) {
    return null;
  }
  const parts = token.split('.');
  if (parts.length !== 2) {
    return null;
  }
  const [payload, signature] = parts;
  const expected = Buffer.from(sign(`session.${payload}`));
  const actual = Buffer.from(signature);
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
    return null;
  }
  const session = JSON.parse(Buffer.from(payload, 'base64url').toString());
  const user = users.get(session.sub);
  if (session.exp <= Math.floor(Date.now() / 1000) || !user || session.ver !== user.sessionVersion) {
    return null;
  }
  return session;
};

const createCsrfToken = () => {
  const data = `${Math.floor(Date.now() / 1000)}.${randomBytes(16).toString('base64url')}`;
  return `${data}.${sign(`csrf.${data}`)}`;
};

const issueCsrfToken = (c) => {
  const token = createCsrfToken();
  setCookie(c, CSRF_COOKIE, token, {
    httpOnly: true,
    secure: !isDevelopment,
    sameSite: 'Strict',
    path: '/',
    maxAge: CSRF_TTL
  });
  return token;
};

const verifyCsrfToken = (token) => {
  const parts = token.split('.');
  if (parts.length !== 3) {
    return false;
  }
  const [issuedAt, nonce, signature] = parts;
  const expected = Buffer.from(sign(`csrf.${issuedAt}.${nonce}`));
  const actual = Buffer.from(signature);
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
    return false;
  }
  const age = Math.floor(Date.now() / 1000) - Number(issuedAt);
  return age >= 0 && age <= CSRF_TTL;
};

const verifyCsrfRequest = (c, body) => {
  const field = formField(body, 'csrf');
  const cookie = getCookie(c, CSRF_COOKIE) ?? '';
  const a = Buffer.from(field);
  const b = Buffer.from(cookie);
  return a.length === b.length && timingSafeEqual(a, b) && verifyCsrfToken(field);
};

const verifyPassword = async (password, user) => {
  const actual = Buffer.from(await hashPassword(password, user.salt), 'hex');
  const expected = Buffer.from(user.passwordHash, 'hex');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
};

const authenticate = async (email, password) => {
  if (password.length > MAX_PASSWORD_LENGTH) {
    return null;
  }
  const user = users.get(email);
  if (!user) {
    await hashPassword(password, 'timing-equalizer');
    return null;
  }
  return (await verifyPassword(password, user)) ? user : null;
};

const formField = (body, name) => (typeof body[name] === 'string' ? body[name] : '');

const createRateLimiter = (limit, windowMs) => {
  const hits = new Map();
  return async (c, next) => {
    const now = Date.now();
    if (hits.size > MAX_TRACKED_CLIENTS) {
      for (const [key, entry] of hits) {
        if (entry.resetAt <= now) {
          hits.delete(key);
        }
      }
    }
    const key = c.env?.incoming?.socket?.remoteAddress ?? 'unknown';
    let entry = hits.get(key);
    if (!entry || entry.resetAt <= now) {
      entry = { count: 0, resetAt: now + windowMs };
      hits.set(key, entry);
    }
    entry.count += 1;
    if (entry.count > limit) {
      c.header('Retry-After', String(Math.ceil((entry.resetAt - now) / 1000)));
      return c.text('Too many attempts. Please try again later.', 429);
    }
    await next();
  };
};

const authRateLimit = createRateLimiter(10, 15 * 60 * 1000);

const renderSignin = (c, status = 200, data = {}) => {
  const welcome = welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)];
  return c.html(
    eta.render('signin', { title: 'Sign In', welcome, email: '', error: '', csrf: issueCsrfToken(c), ...data }),
    status
  );
};

app.get('/', (c) => {
  if (verifySession(getCookie(c, SESSION_COOKIE))) {
    return c.redirect('/profile');
  }
  return renderSignin(c);
});

const renderRegister = (c, status = 200, data = {}) =>
  c.html(eta.render('register', { title: 'Register', email: '', error: '', csrf: issueCsrfToken(c), ...data }), status);

app.get('/register', (c) => renderRegister(c));

app.post('/register', authRateLimit, async (c) => {
  const body = await c.req.parseBody();
  if (!verifyCsrfRequest(c, body)) {
    return renderRegister(c, 403, { error: 'Your form has expired. Please try again.' });
  }
  const email = formField(body, 'email').trim().toLowerCase();
  const password = formField(body, 'password');
  if (email.length > MAX_EMAIL_LENGTH || !emailPattern.test(email)) {
    return renderRegister(c, 400, { email, error: 'Please enter a valid email address.' });
  }
  if (password.length < MIN_PASSWORD_LENGTH || password.length > MAX_PASSWORD_LENGTH) {
    return renderRegister(c, 400, {
      email,
      error: `Password must be between ${MIN_PASSWORD_LENGTH} and ${MAX_PASSWORD_LENGTH} characters.`
    });
  }
  const salt = randomBytes(16).toString('hex');
  const passwordHash = await hashPassword(password, salt);
  if (users.has(email)) {
    return renderRegister(c, 409, { email, error: 'An account with this email already exists.' });
  }
  users.set(email, { email, salt, passwordHash, sessionVersion: 0 });
  return renderRegister(c, 201, {
    success: 'Account created. Redirecting you to sign in...',
    refresh: '3;url=/'
  });
});

app.get('/profile', (c) => {
  const session = verifySession(getCookie(c, SESSION_COOKIE));
  if (!session) {
    return c.redirect('/');
  }
  return c.html(eta.render('profile', { title: 'Profile', email: session.sub }));
});

app.post('/', authRateLimit, async (c) => {
  const body = await c.req.parseBody();
  if (!verifyCsrfRequest(c, body)) {
    return renderSignin(c, 403, { error: 'Your form has expired. Please try again.' });
  }
  const email = formField(body, 'email').trim().toLowerCase();
  const password = formField(body, 'password');
  const user = await authenticate(email, password);
  if (!user) {
    return renderSignin(c, 401, { email, error: 'Invalid email or password.' });
  }
  setCookie(c, SESSION_COOKIE, createSession(user), {
    httpOnly: true,
    secure: !isDevelopment,
    sameSite: 'Lax',
    path: '/',
    maxAge: SESSION_TTL
  });
  return c.redirect('/profile');
});

app.post('/signout', (c) => {
  const session = verifySession(getCookie(c, SESSION_COOKIE));
  if (session) {
    users.get(session.sub).sessionVersion += 1;
  }
  deleteCookie(c, SESSION_COOKIE, { path: '/', secure: !isDevelopment });
  return c.redirect('/');
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
