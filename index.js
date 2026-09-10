const path = require('node:path');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { getConnInfo } = require('@hono/node-server/conninfo');
const { secureHeaders } = require('hono/secure-headers');
const { bodyLimit } = require('hono/body-limit');
const { setCookie, getCookie, deleteCookie } = require('hono/cookie');
const { Eta } = require('eta');

const app = new Hono();
const eta = new Eta({ views: path.join(__dirname, 'views') });
const isProduction = process.env.NODE_ENV === 'production';

const users = new Map();
const maxUsers = Number(process.env.MAX_USERS) || 10000;
const revokedSessions = new Map();
const sessionRevokeMaxEntries = 10000;
const sessionMaxAge = 7 * 60 * 60;
const passwordMinLength = 8;
const passwordMaxLength = 128;
const emailMaxLength = 254;
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const isValidEmail = (email) => email.length > 0 && email.length <= emailMaxLength && emailPattern.test(email);
const hmacSecret = process.env.HMAC_SECRET || (isProduction ? null : crypto.randomBytes(32).toString('hex'));
if (!hmacSecret) {
  throw new Error('HMAC_SECRET environment variable is required');
}

const scryptAsync = promisify(crypto.scrypt);

const hashPassword = async (password, salt) => (await scryptAsync(password, salt, 64)).toString('hex');

const verifyPassword = async (password, user) => {
  const expected = Buffer.from(user.passwordHash, 'hex');
  const actual = Buffer.from(await hashPassword(password, user.salt), 'hex');
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
};

const dummySalt = crypto.randomBytes(16).toString('hex');
const dummyHash = crypto.scryptSync('dummy-password', dummySalt, 64).toString('hex');

const signValue = (value) => crypto.createHmac('sha256', hmacSecret).update(value).digest('hex');

const createSessionToken = (email) => {
  const payload = `${email}:${Date.now() + sessionMaxAge * 1000}`;
  return `${Buffer.from(payload).toString('base64url')}.${signValue(payload)}`;
};

const verifySessionToken = (token) => {
  if (!token) return null;
  const [encoded, signature] = token.split('.');
  if (!encoded || !signature) return null;
  const payload = Buffer.from(encoded, 'base64url').toString();
  const expected = signValue(payload);
  if (signature.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
    return null;
  }
  if (revokedSessions.has(signature)) return null;
  const [email, expiry] = payload.split(':');
  if (!email || !expiry || Number(expiry) < Date.now()) return null;
  return email;
};

const pruneRevokedSessions = (now) => {
  for (const [signature, expiry] of revokedSessions) {
    if (now > expiry) revokedSessions.delete(signature);
  }
  while (revokedSessions.size > sessionRevokeMaxEntries) {
    revokedSessions.delete(revokedSessions.keys().next().value);
  }
};

const revokeSession = (token) => {
  if (!token) return;
  const [encoded, signature] = token.split('.');
  if (!signature) return;
  let expiry = Date.now() + sessionMaxAge * 1000;
  try {
    const parsed = Number(Buffer.from(encoded, 'base64url').toString().split(':')[1]);
    if (!Number.isNaN(parsed)) expiry = parsed;
  } catch {
    expiry = Date.now() + sessionMaxAge * 1000;
  }
  revokedSessions.set(signature, expiry);
  pruneRevokedSessions(Date.now());
};

const csrfMaxAge = 2 * 60 * 60 * 1000;

const csrfBinding = (c) => {
  const session = getCookie(c, 'session');
  if (session) return session;
  let csrfId = getCookie(c, 'csrf');
  if (!csrfId) {
    csrfId = crypto.randomBytes(32).toString('hex');
    setCookie(c, 'csrf', csrfId, {
      path: '/',
      httpOnly: true,
      sameSite: 'Strict',
      secure: isProduction,
      maxAge: sessionMaxAge
    });
  }
  return csrfId;
};

const createCsrfToken = (c) => {
  const expiry = Date.now() + csrfMaxAge;
  return `${expiry}.${signValue(`csrf:${csrfBinding(c)}:${expiry}`)}`;
};

const verifyCsrfToken = (c, token) => {
  if (!token) return false;
  const [expiry, signature] = token.split('.');
  if (!expiry || !signature || Number(expiry) < Date.now()) return false;
  const binding = getCookie(c, 'session') || getCookie(c, 'csrf');
  if (!binding) return false;
  const expected = signValue(`csrf:${binding}:${expiry}`);
  return signature.length === expected.length && crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
};

const createUser = async (email, password) => {
  const normalized = email.trim().toLowerCase();
  const salt = crypto.randomBytes(16).toString('hex');
  const passwordHash = await hashPassword(password, salt);
  users.set(normalized, { email: normalized, passwordHash, salt });
  return users.get(normalized);
};

if (!isProduction && process.env.SEED_DEMO_USER === 'true') {
  createUser('demo@example.com', 'password123').catch(() => {});
}

const rateLimitWindowMs = 15 * 60 * 1000;
const rateLimitMax = 10;
const rateLimitMaxEntries = 10000;
const rateLimitPruneInterval = 500;
const rateLimitHits = new Map();
let rateLimitOps = 0;

const clientKey = (c) => {
  try {
    return getConnInfo(c).remote.address || 'unknown';
  } catch {
    return 'unknown';
  }
};

const pruneRateLimitHits = (now) => {
  for (const [key, value] of rateLimitHits) {
    if (now > value.reset) rateLimitHits.delete(key);
  }
  while (rateLimitHits.size > rateLimitMaxEntries) {
    rateLimitHits.delete(rateLimitHits.keys().next().value);
  }
};

const authRateLimit = async (c, next) => {
  const key = clientKey(c);
  const now = Date.now();
  rateLimitOps += 1;
  if (rateLimitOps % rateLimitPruneInterval === 0) pruneRateLimitHits(now);
  const entry = rateLimitHits.get(key);
  if (!entry || now > entry.reset) {
    rateLimitHits.set(key, { count: 1, reset: now + rateLimitWindowMs });
  } else {
    entry.count += 1;
    if (entry.count > rateLimitMax) {
      return c.text('Too many attempts, please try again later', 429);
    }
  }
  await next();
};

app.use(
  secureHeaders({
    contentSecurityPolicy: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", 'https://unpkg.com'],
      styleSrc: ["'self'", 'https://unpkg.com'],
      imgSrc: ["'self'", 'data:'],
      fontSrc: ["'self'", 'https://unpkg.com'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"]
    }
  })
);
app.use(bodyLimit({ maxSize: 16 * 1024, onError: (c) => c.text('Payload too large', 413) }));
app.use(async (c, next) => {
  await next();
  c.header('Cache-Control', 'no-store');
});

const appStyles = 'nav { display: flex; justify-content: space-between; align-items: center; gap: 1rem; }';
app.get('/app.css', (c) => c.body(appStyles, 200, { 'Content-Type': 'text/css; charset=utf-8' }));

const welcomeTitles = ['Welcome', 'Welcome back', 'Hello again', 'Good to see you', 'Sign in to continue'];
const pickWelcome = () => welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)];

const renderSignin = (c, error, status = 200) =>
  c.html(
    eta.render('signin', { title: 'Sign In', heading: pickWelcome(), csrfToken: createCsrfToken(c), error }),
    status
  );

app.get('/', (c) => {
  if (verifySessionToken(getCookie(c, 'session'))) return c.redirect('/profile');
  return renderSignin(c);
});

const renderRegister = (c, error, status = 200, message = null) =>
  c.html(
    eta.render('register', {
      title: 'Register',
      heading: 'Create your account',
      csrfToken: createCsrfToken(c),
      error,
      message
    }),
    status
  );

app.get('/register', (c) => renderRegister(c));

app.post('/register', authRateLimit, async (c) => {
  const body = await c.req.parseBody();
  const email = String(body.email || '')
    .trim()
    .toLowerCase();
  const password = String(body.password || '');
  if (!verifyCsrfToken(c, String(body.csrfToken || ''))) {
    return renderRegister(c, 'Invalid or expired form token', 403);
  }
  if (!isValidEmail(email)) {
    return renderRegister(c, 'Please enter a valid email address', 400);
  }
  if (password.length < passwordMinLength) {
    return renderRegister(c, `Password must be at least ${passwordMinLength} characters long`, 400);
  }
  if (password.length > passwordMaxLength) {
    return renderRegister(c, `Password must be at most ${passwordMaxLength} characters long`, 400);
  }
  if (users.has(email)) {
    await hashPassword(password, dummySalt);
  } else if (users.size >= maxUsers) {
    return renderRegister(c, 'Registration is temporarily unavailable', 503);
  } else {
    await createUser(email, password);
  }
  return renderRegister(c, null, 200, 'Account created. Redirecting to sign in…');
});

app.post('/signin', authRateLimit, async (c) => {
  const body = await c.req.parseBody();
  const email = String(body.email || '')
    .trim()
    .toLowerCase();
  const password = String(body.password || '');
  if (!verifyCsrfToken(c, String(body.csrfToken || ''))) {
    return renderSignin(c, 'Invalid or expired form token', 403);
  }
  if (password.length > passwordMaxLength) {
    return renderSignin(c, 'Invalid email or password', 401);
  }
  const user = users.get(email);
  if (!user) {
    await verifyPassword(password, { passwordHash: dummyHash, salt: dummySalt });
    return renderSignin(c, 'Invalid email or password', 401);
  }
  if (!(await verifyPassword(password, user))) {
    return renderSignin(c, 'Invalid email or password', 401);
  }
  setCookie(c, 'session', createSessionToken(user.email), {
    path: '/',
    httpOnly: true,
    sameSite: 'Lax',
    secure: isProduction,
    maxAge: sessionMaxAge
  });
  return c.redirect('/profile');
});

app.get('/profile', (c) => {
  const email = verifySessionToken(getCookie(c, 'session'));
  if (!email) return c.redirect('/');
  return c.html(eta.render('profile', { title: 'Profile', email, csrfToken: createCsrfToken(c) }));
});

app.post('/signout', async (c) => {
  const body = await c.req.parseBody();
  if (!verifyCsrfToken(c, String(body.csrfToken || ''))) {
    return c.text('Invalid or expired form token', 403);
  }
  revokeSession(getCookie(c, 'session'));
  deleteCookie(c, 'session', { path: '/' });
  return c.redirect('/');
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
