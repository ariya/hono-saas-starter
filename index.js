const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { bodyLimit } = require('hono/body-limit');
const { getSignedCookie, setSignedCookie, deleteCookie } = require('hono/cookie');
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
const sessions = new Map();

const scryptAsync = (password, salt, keylen) =>
  new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, keylen, (err, buf) => {
      if (err) reject(err);
      else resolve(buf);
    });
  });

const hashPassword = (password, salt) => {
  return scryptAsync(password, salt, 64).then((buf) => buf.toString('hex'));
};

const createUser = async (email, password) => {
  const salt = crypto.randomBytes(16).toString('hex');
  const user = { email, salt, passwordHash: await hashPassword(password, salt) };
  users.set(email, user);
  return user;
};

const findUser = (email) => users.get(email);

const verifyPassword = async (password, user) => {
  const [expected, actual] = await Promise.all([hashPassword(password, user.salt), user.passwordHash]);
  const a = Buffer.from(actual, 'hex');
  const b = Buffer.from(expected, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
};

const DUMMY_SALT = crypto.randomBytes(16).toString('hex');
let DUMMY_USER = null;

const ensureDummyUser = async () => {
  if (!DUMMY_USER) {
    DUMMY_USER = { email: '', salt: DUMMY_SALT, passwordHash: await hashPassword('dummy-password', DUMMY_SALT) };
  }
  return DUMMY_USER;
};

const CSRF_ANON_SUBJECT = 'anon';

const createCsrfToken = (subject) => {
  const payload = `${subject}.${Math.floor(Date.now() / 1000)}`;
  const sig = crypto.createHmac('sha256', HMAC_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
};

const verifyCsrfToken = (token, expectedSubject) => {
  if (!token || typeof token !== 'string') return false;
  const firstDot = token.indexOf('.');
  const lastDot = token.lastIndexOf('.');
  if (firstDot < 1 || lastDot <= firstDot) return false;
  const subject = token.slice(0, firstDot);
  const timestamp = token.slice(firstDot + 1, lastDot);
  const sig = token.slice(lastDot + 1);
  if (subject !== expectedSubject) return false;
  const payload = `${subject}.${timestamp}`;
  const expected = crypto.createHmac('sha256', HMAC_SECRET).update(payload).digest('base64url');
  if (sig.length !== expected.length) return false;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return false;
  const issued = Number(timestamp);
  if (!Number.isFinite(issued)) return false;
  return Math.floor(Date.now() / 1000) - issued <= 3600;
};

const csrfGuard = async (c, next) => {
  const sessionId = await getSessionId(c);
  const subject = sessionId && sessions.has(sessionId) ? sessionId : CSRF_ANON_SUBJECT;
  const body = await c.req.parseBody();
  if (!verifyCsrfToken(body.csrf, subject)) {
    return c.text('Invalid or missing CSRF token', 403);
  }
  await next();
};

const getCurrentUser = async (c) => {
  const sessionId = await getSignedCookie(c, HMAC_SECRET, 'session');
  if (!sessionId) return null;
  const email = sessions.get(sessionId);
  if (!email) return null;
  return findUser(email) || null;
};

const getSessionId = async (c) => {
  return (await getSignedCookie(c, HMAC_SECRET, 'session')) || null;
};

const createSession = (email) => {
  const sessionId = crypto.randomBytes(32).toString('hex');
  sessions.set(sessionId, email);
  return sessionId;
};

const destroySession = async (c) => {
  const sessionId = await getSessionId(c);
  if (sessionId) sessions.delete(sessionId);
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

const app = new Hono();

app.use(
  secureHeaders({
    contentSecurityPolicy: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", 'https://oat.ink'],
      imgSrc: ["'self'"],
      fontSrc: ["'self'", 'https://oat.ink'],
      connectSrc: ["'self'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"]
    }
  })
);
app.use(bodyLimit({ maxSize: 16 * 1024 }));

const renderSignin = (data) => {
  const welcome = data.welcome || WELCOME_TITLES[Math.floor(Math.random() * WELCOME_TITLES.length)];
  return eta.render('signin', { csrfToken: createCsrfToken(CSRF_ANON_SUBJECT), welcome, ...data });
};

const renderRegister = (data) => {
  return eta.render('register', { csrfToken: createCsrfToken(CSRF_ANON_SUBJECT), ...data });
};

const renderProfile = (data, sessionId) => {
  return eta.render('profile', { csrfToken: createCsrfToken(sessionId), ...data });
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
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

app.post('/register', csrfGuard, async (c) => {
  const body = await c.req.parseBody();
  const email = String(body.email || '').toLowerCase();
  const password = String(body.password || '');
  if (!EMAIL_RE.test(email)) {
    return c.html(renderRegister({ email, error: 'Please enter a valid email address.' }), 400);
  }
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
  const salt = crypto.randomBytes(16).toString('hex');
  const passwordHash = await hashPassword(password, salt);
  if (findUser(email)) {
    return c.html(renderRegister({ success: 'Account created. Redirecting to sign in…', redirect: '/' }), 201);
  }
  users.set(email, { email, salt, passwordHash });
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
  const user = existing || (await ensureDummyUser());
  const valid = await verifyPassword(password, user);
  if (!existing || !valid) {
    return c.html(renderSignin({ email, error: 'Invalid email or password.' }), 401);
  }
  await setSignedCookie(c, 'session', createSession(user.email), HMAC_SECRET, {
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
  const sessionId = await getSessionId(c);
  return c.html(renderProfile({ email: user.email }, sessionId));
});

app.post('/signout', csrfGuard, async (c) => {
  await destroySession(c);
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

(async () => {
  if (isDev) {
    await createUser('demo@example.com', 'password123456');
  }
  serve({ fetch: app.fetch, port });
  console.log('Listening on port', port);
})();
