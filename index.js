const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');
const path = require('path');
const crypto = require('crypto');

const app = new Hono();
const eta = new Eta({ views: path.join(__dirname) });
const isProduction = process.env.NODE_ENV === 'production';
const HMAC_SECRET =
  process.env.HMAC_SECRET ||
  (isProduction
    ? (() => {
        throw new Error('HMAC_SECRET env var is required in production');
      })()
    : 'dev-secret');

app.use(secureHeaders());

const users = new Map();

async function hashPassword(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, key) => (err ? reject(err) : resolve(key.toString('hex'))));
  });
}

async function verifyPassword(password, hash, salt) {
  const derived = await hashPassword(password, salt);
  return crypto.timingSafeEqual(Buffer.from(derived), Buffer.from(hash));
}

const SESSION_MAX_AGE = 7 * 60 * 60;

function signSession(email) {
  const ts = Math.floor(Date.now() / 1000);
  const payload = `${email}:${ts}`;
  const sig = crypto.createHmac('sha256', HMAC_SECRET).update(payload).digest('hex');
  return `${payload}.${sig}`;
}

function verifySession(token) {
  try {
    const dot = token.lastIndexOf('.');
    if (dot === -1) return null;
    const payload = token.slice(0, dot);
    const sig = token.slice(dot + 1);
    const expected = crypto.createHmac('sha256', HMAC_SECRET).update(payload).digest('hex');
    const expectedBuf = Buffer.from(expected, 'hex');
    const sigBuf = Buffer.from(sig, 'hex');
    if (sigBuf.length !== expectedBuf.length) return null;
    if (!crypto.timingSafeEqual(sigBuf, expectedBuf)) return null;
    const colon = payload.lastIndexOf(':');
    if (colon === -1) return null;
    const email = payload.slice(0, colon);
    const ts = parseInt(payload.slice(colon + 1), 10);
    if (isNaN(ts) || Math.floor(Date.now() / 1000) - ts > SESSION_MAX_AGE) return null;
    return email;
  } catch {
    return null;
  }
}

function generateCsrfToken() {
  const nonce = crypto.randomBytes(16).toString('hex');
  const sig = crypto.createHmac('sha256', HMAC_SECRET).update(nonce).digest('hex');
  return `${nonce}.${sig}`;
}

function verifyCsrfToken(token) {
  if (!token || typeof token !== 'string') return false;
  const dot = token.lastIndexOf('.');
  if (dot === -1) return false;
  const nonce = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const expected = crypto.createHmac('sha256', HMAC_SECRET).update(nonce).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'));
  } catch {
    return false;
  }
}

const welcomeTitles = ['Welcome back!', 'Good to see you!', 'Hello again!', 'Welcome!', "Glad you're here!"];

app.get('/', async (c) => {
  const cookie = c.req.header('Cookie') || '';
  const match = cookie.match(/(?:^|;\s*)session=([^;]+)/);
  const email = match ? verifySession(decodeURIComponent(match[1])) : null;
  if (email) return c.redirect('/profile');
  const title = welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)];
  const html = await eta.renderAsync('signin', { title, error: null, csrf: generateCsrfToken() });
  return c.html(html);
});

app.post('/', async (c) => {
  const { email, password, csrf } = await c.req.parseBody();
  if (!verifyCsrfToken(csrf)) {
    return c.text('Invalid request', 403);
  }
  if (!password || password.length > 1024) {
    const title = welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)];
    const html = await eta.renderAsync('signin', {
      title,
      error: 'Invalid email or password.',
      csrf: generateCsrfToken()
    });
    return c.html(html, 401);
  }
  const user = users.get(email);
  const valid = user ? await verifyPassword(password, user.hash, user.salt) : false;
  if (!valid) {
    const title = welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)];
    const html = await eta.renderAsync('signin', {
      title,
      error: 'Invalid email or password.',
      csrf: generateCsrfToken()
    });
    return c.html(html, 401);
  }
  const maxAge = 7 * 60 * 60;
  const secureFlag = isProduction ? '; Secure' : '';
  const token = signSession(email);
  c.header(
    'Set-Cookie',
    `session=${encodeURIComponent(token)}; Path=/; HttpOnly${secureFlag}; Max-Age=${maxAge}; SameSite=Lax`
  );
  return c.redirect('/profile');
});

app.get('/register', async (c) => {
  const html = await eta.renderAsync('register', {
    error: null,
    success: null,
    redirect: null,
    csrf: generateCsrfToken()
  });
  return c.html(html);
});

app.post('/register', async (c) => {
  const { email, password, csrf } = await c.req.parseBody();
  if (!verifyCsrfToken(csrf)) return c.text('Invalid request', 403);
  if (!password || password.length < 8 || password.length > 1024) {
    const html = await eta.renderAsync('register', {
      error: 'Password must be between 8 and 1024 characters.',
      success: null,
      redirect: null,
      csrf: generateCsrfToken()
    });
    return c.html(html, 422);
  }
  if (!users.has(email)) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = await hashPassword(password, salt);
    users.set(email, { email, hash, salt });
  }
  const html = await eta.renderAsync('register', {
    error: null,
    success: 'Account created! Redirecting to sign in...',
    redirect: '/',
    csrf: generateCsrfToken()
  });
  return c.html(html);
});

app.get('/profile', async (c) => {
  const cookie = c.req.header('Cookie') || '';
  const match = cookie.match(/(?:^|;\s*)session=([^;]+)/);
  const email = match ? verifySession(decodeURIComponent(match[1])) : null;
  if (!email) return c.redirect('/');
  const html = await eta.renderAsync('profile', { email });
  return c.html(html);
});

app.get('/signout', (c) => {
  c.header('Set-Cookie', 'session=; Path=/; HttpOnly; Max-Age=0; SameSite=Lax');
  return c.redirect('/');
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
