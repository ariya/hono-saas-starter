const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { getCookie, setCookie, deleteCookie } = require('hono/cookie');
const { Eta } = require('eta');
const { randomInt, randomBytes, scryptSync, timingSafeEqual, createHmac } = require('crypto');

const eta = new Eta({ views: 'views' });

const welcomeTitles = ['Welcome back', 'Hello again', 'Good to see you', 'Hey there', 'Greetings'];

const users = new Map();

const isProd = process.env.NODE_ENV === 'production';

const sessionDurationMs = 7 * 60 * 60 * 1000;

const hmacSecret = process.env.HMAC_SECRET || (isProd ? null : randomBytes(32).toString('hex'));

if (!hmacSecret) {
  console.error('Refusing to start: HMAC_SECRET environment variable is required in production');
  process.exit(1);
}

function hashPassword(password, salt) {
  return scryptSync(password, salt, 64).toString('hex');
}

function verifyUser(email, password) {
  const user = users.get(
    String(email || '')
      .trim()
      .toLowerCase()
  );
  if (!user) return null;
  const candidate = Buffer.from(hashPassword(password, user.salt), 'hex');
  const stored = Buffer.from(user.hash, 'hex');
  return candidate.length === stored.length && timingSafeEqual(candidate, stored) ? user : null;
}

function createCsrfToken() {
  const nonce = randomBytes(16).toString('base64url');
  const sig = createHmac('sha256', hmacSecret).update(`csrf:${nonce}`).digest('base64url');
  return `${nonce}.${sig}`;
}

function verifyCsrfToken(token) {
  if (typeof token !== 'string') return false;
  const dot = token.lastIndexOf('.');
  if (dot < 1) return false;
  const nonce = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const expected = createHmac('sha256', hmacSecret).update(`csrf:${nonce}`).digest('base64url');
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

function signSession(email) {
  const payload = Buffer.from(JSON.stringify({ email, exp: Date.now() + sessionDurationMs })).toString('base64url');
  const sig = createHmac('sha256', hmacSecret).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

function verifySession(token) {
  if (typeof token !== 'string') return null;
  const dot = token.lastIndexOf('.');
  if (dot < 1) return null;
  const payload = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const expected = createHmac('sha256', hmacSecret).update(payload).digest('base64url');
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (typeof data.email !== 'string' || typeof data.exp !== 'number' || Date.now() > data.exp) {
      return null;
    }
    return data.email;
  } catch {
    return null;
  }
}

const app = new Hono();

app.use(secureHeaders());

app.get('/', (c) => {
  if (verifySession(getCookie(c, 'session'))) {
    return c.redirect('/profile');
  }
  const title = welcomeTitles[randomInt(welcomeTitles.length)];
  return c.html(eta.render('signin', { title, error: null, csrf: createCsrfToken() }));
});

app.post('/signin', async (c) => {
  const body = await c.req.parseBody();
  if (!verifyCsrfToken(body._csrf)) {
    const title = welcomeTitles[randomInt(welcomeTitles.length)];
    return c.html(
      eta.render('signin', { title, error: 'Session expired. Please try again.', csrf: createCsrfToken() }),
      403
    );
  }
  const user = verifyUser(body.email, body.password || '');
  if (!user) {
    const title = welcomeTitles[randomInt(welcomeTitles.length)];
    return c.html(eta.render('signin', { title, error: 'Invalid email or password.', csrf: createCsrfToken() }), 401);
  }
  setCookie(c, 'session', signSession(user.email), {
    httpOnly: true,
    path: '/',
    secure: isProd,
    maxAge: sessionDurationMs / 1000
  });
  return c.redirect('/profile');
});

app.get('/register', (c) => {
  return c.html(eta.render('register', { error: null, success: null, csrf: createCsrfToken() }));
});

app.post('/register', async (c) => {
  const body = await c.req.parseBody();
  const csrf = createCsrfToken();
  if (!verifyCsrfToken(body._csrf)) {
    return c.html(eta.render('register', { error: 'Session expired. Please try again.', success: null, csrf }), 403);
  }
  const password = String(body.password || '');
  if (password.length < 8) {
    return c.html(
      eta.render('register', { error: 'Password must be at least 8 characters long.', success: null, csrf }),
      400
    );
  }
  const email = String(body.email || '')
    .trim()
    .toLowerCase();
  if (!email || !email.includes('@')) {
    return c.html(eta.render('register', { error: 'Please enter a valid email address.', success: null, csrf }), 400);
  }
  if (users.has(email)) {
    return c.html(
      eta.render('register', { error: 'An account with this email already exists.', success: null, csrf }),
      409
    );
  }
  const salt = randomBytes(16).toString('hex');
  const hash = hashPassword(password, salt);
  users.set(email, { email, hash, salt });
  return c.html(
    eta.render('register', { error: null, success: 'Account created successfully. Redirecting…', csrf }),
    201
  );
});

app.get('/profile', (c) => {
  const email = verifySession(getCookie(c, 'session'));
  if (!email) {
    return c.redirect('/');
  }
  return c.html(eta.render('profile', { email }));
});

app.post('/signout', (c) => {
  deleteCookie(c, 'session', { path: '/', httpOnly: true, secure: isProd });
  return c.redirect('/');
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
