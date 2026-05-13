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
const rateLimitStore = new Map();

function isRateLimited(namespace, ip, maxAttempts, windowSeconds) {
  const now = Date.now();
  const windowMs = windowSeconds * 1000;
  const key = `${namespace}:${ip}`;
  const timestamps = (rateLimitStore.get(key) || []).filter((t) => now - t < windowMs);
  if (timestamps.length >= maxAttempts) return true;
  timestamps.push(now);
  rateLimitStore.set(key, timestamps);
  return false;
}

function getClientIp(c) {
  return c.req.header('x-forwarded-for')?.split(',')[0]?.trim() || c.req.header('x-real-ip') || 'unknown';
}

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
const SESSION_KEY = crypto
  .createHash('sha256')
  .update('session:' + HMAC_SECRET)
  .digest();

function encryptSession(email) {
  const ts = Math.floor(Date.now() / 1000);
  const plaintext = `${email}:${ts}`;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', SESSION_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString('base64url');
}

function decryptSession(token) {
  try {
    const buf = Buffer.from(token, 'base64url');
    if (buf.length < 29) return null;
    const iv = buf.subarray(0, 12);
    const tag = buf.subarray(12, 28);
    const encrypted = buf.subarray(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', SESSION_KEY, iv);
    decipher.setAuthTag(tag);
    const plaintext = decipher.update(encrypted, undefined, 'utf8') + decipher.final('utf8');
    const colon = plaintext.lastIndexOf(':');
    if (colon === -1) return null;
    const email = plaintext.slice(0, colon);
    const ts = parseInt(plaintext.slice(colon + 1), 10);
    if (isNaN(ts) || Math.floor(Date.now() / 1000) - ts > SESSION_MAX_AGE) return null;
    return email;
  } catch {
    return null;
  }
}

const CSRF_MAX_AGE = 60 * 60;

function generateCsrfToken() {
  const nonce = crypto.randomBytes(16).toString('hex');
  const ts = Math.floor(Date.now() / 1000);
  const payload = `${nonce}:${ts}`;
  const sig = crypto.createHmac('sha256', HMAC_SECRET).update(payload).digest('hex');
  return `${payload}.${sig}`;
}

function verifyCsrfToken(token) {
  if (!token || typeof token !== 'string') return false;
  try {
    const dot = token.lastIndexOf('.');
    if (dot === -1) return false;
    const payload = token.slice(0, dot);
    const sig = token.slice(dot + 1);
    const expected = crypto.createHmac('sha256', HMAC_SECRET).update(payload).digest('hex');
    const expectedBuf = Buffer.from(expected, 'hex');
    const sigBuf = Buffer.from(sig, 'hex');
    if (sigBuf.length !== expectedBuf.length) return false;
    if (!crypto.timingSafeEqual(sigBuf, expectedBuf)) return false;
    const colon = payload.lastIndexOf(':');
    if (colon === -1) return false;
    const ts = parseInt(payload.slice(colon + 1), 10);
    return !isNaN(ts) && Math.floor(Date.now() / 1000) - ts <= CSRF_MAX_AGE;
  } catch {
    return false;
  }
}

const welcomeTitles = ['Welcome back!', 'Good to see you!', 'Hello again!', 'Welcome!', "Glad you're here!"];

app.get('/', async (c) => {
  const cookie = c.req.header('Cookie') || '';
  const match = cookie.match(/(?:^|;\s*)session=([^;]+)/);
  const email = match ? decryptSession(decodeURIComponent(match[1])) : null;
  if (email) return c.redirect('/profile');
  const title = welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)];
  const html = await eta.renderAsync('signin', { title, error: null, csrf: generateCsrfToken() });
  return c.html(html);
});

app.post('/', async (c) => {
  if (isRateLimited('login', getClientIp(c), 5, 15 * 60)) {
    return c.text('Too many attempts. Please wait before trying again.', 429);
  }
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
  const token = encryptSession(email);
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
  if (isRateLimited('register', getClientIp(c), 3, 15 * 60)) {
    return c.text('Too many attempts. Please wait before trying again.', 429);
  }
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
  const email = match ? decryptSession(decodeURIComponent(match[1])) : null;
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
