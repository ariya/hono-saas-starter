const path = require('path');
const crypto = require('crypto');
const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { setCookie, deleteCookie, getCookie } = require('hono/cookie');
const { Eta } = require('eta');

const eta = new Eta({ views: path.join(__dirname, 'views'), cache: true });

const users = new Map();

const hashPassword = (password, salt) => {
  return crypto.scryptSync(password, salt, 64).toString('hex');
};

const verifyPassword = (password, salt, expectedHex) => {
  const candidate = hashPassword(password, salt);
  const a = Buffer.from(candidate, 'hex');
  const b = Buffer.from(expectedHex, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
};

const SESSION_COOKIE = 'sid';
const SESSION_MAX_AGE_SECONDS = 7 * 60 * 60;
const IS_PROD = process.env.NODE_ENV === 'production';
const HMAC_SECRET = process.env.HMAC_SECRET || (IS_PROD ? null : 'dev-only-insecure-secret');
if (!HMAC_SECRET) {
  console.error('HMAC_SECRET is required in production');
  process.exit(1);
}

const b64url = (buf) => buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

const b64urlDecode = (str) => {
  const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4));
  return Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64');
};

const hmac = (data) => crypto.createHmac('sha256', HMAC_SECRET).update(data).digest();

const signSession = (email) => {
  const issuedAt = Math.floor(Date.now() / 1000);
  const payload = `${b64url(Buffer.from(email))}.${issuedAt}`;
  const sig = b64url(hmac(payload));
  return `${payload}.${sig}`;
};

const verifySession = (token) => {
  if (typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [emailB64, issuedAtStr, sigB64] = parts;
  const payload = `${emailB64}.${issuedAtStr}`;
  let sig;
  let expected;
  try {
    sig = b64urlDecode(sigB64);
    expected = hmac(payload);
  } catch {
    return null;
  }
  if (sig.length !== expected.length || !crypto.timingSafeEqual(sig, expected)) return null;
  const issuedAt = Number.parseInt(issuedAtStr, 10);
  if (!Number.isFinite(issuedAt)) return null;
  if (Math.floor(Date.now() / 1000) - issuedAt > SESSION_MAX_AGE_SECONDS) return null;
  try {
    return b64urlDecode(emailB64).toString('utf8');
  } catch {
    return null;
  }
};

const sessionCookieOptions = () => ({
  httpOnly: true,
  secure: IS_PROD,
  sameSite: 'Lax',
  path: '/',
  maxAge: SESSION_MAX_AGE_SECONDS
});

const CSRF_TTL_SECONDS = 60 * 60;

const issueCsrfToken = () => {
  const nonce = b64url(crypto.randomBytes(16));
  const issuedAt = Math.floor(Date.now() / 1000);
  const payload = `${nonce}.${issuedAt}`;
  const sig = b64url(hmac(`csrf:${payload}`));
  return `${payload}.${sig}`;
};

const verifyCsrfToken = (token) => {
  if (typeof token !== 'string') return false;
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const [nonce, issuedAtStr, sigB64] = parts;
  const payload = `${nonce}.${issuedAtStr}`;
  let sig;
  let expected;
  try {
    sig = b64urlDecode(sigB64);
    expected = hmac(`csrf:${payload}`);
  } catch {
    return false;
  }
  if (sig.length !== expected.length || !crypto.timingSafeEqual(sig, expected)) return false;
  const issuedAt = Number.parseInt(issuedAtStr, 10);
  if (!Number.isFinite(issuedAt)) return false;
  if (Math.floor(Date.now() / 1000) - issuedAt > CSRF_TTL_SECONDS) return false;
  return true;
};

const currentUserEmail = (c) => {
  const token = getCookie(c, SESSION_COOKIE);
  if (!token) return null;
  const email = verifySession(token);
  if (!email) return null;
  if (!users.has(email)) return null;
  return email;
};

const app = new Hono();

app.use(secureHeaders());

const WELCOME_TITLES = ['Welcome', 'Welcome back', 'Hello again', 'Good to see you', 'Sign in to continue'];

const pickWelcomeTitle = () => WELCOME_TITLES[Math.floor(Math.random() * WELCOME_TITLES.length)];

app.get('/', (c) => {
  if (currentUserEmail(c)) return c.redirect('/profile', 303);
  return c.html(eta.render('signin', { title: pickWelcomeTitle(), error: null, email: '', csrf: issueCsrfToken() }));
});

app.post('/signin', async (c) => {
  const body = await c.req.parseBody();
  if (!verifyCsrfToken(String(body._csrf || ''))) {
    return c.html(
      eta.render('signin', {
        title: pickWelcomeTitle(),
        error: 'Session expired. Please try again.',
        email: '',
        csrf: issueCsrfToken()
      }),
      403
    );
  }
  const email = String(body.email || '')
    .trim()
    .toLowerCase();
  const password = String(body.password || '');
  const user = users.get(email);
  const ok = user && verifyPassword(password, user.salt, user.hash);
  if (!ok) {
    return c.html(
      eta.render('signin', {
        title: pickWelcomeTitle(),
        error: 'Invalid email or password.',
        email,
        csrf: issueCsrfToken()
      }),
      401
    );
  }
  setCookie(c, SESSION_COOKIE, signSession(email), sessionCookieOptions());
  return c.redirect('/profile', 303);
});

app.post('/signin', async (c) => {
  const body = await c.req.parseBody();
  const email = String(body.email || '')
    .trim()
    .toLowerCase();
  const password = String(body.password || '');
  const user = users.get(email);
  const ok = user && verifyPassword(password, user.salt, user.hash);
  if (!ok) {
    return c.html(eta.render('signin', { title: pickWelcomeTitle(), error: 'Invalid email or password.', email }), 401);
  }
  setCookie(c, SESSION_COOKIE, signSession(email), sessionCookieOptions());
  return c.redirect('/profile', 303);
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

app.get('/profile', (c) => {
  const email = currentUserEmail(c);
  if (!email) return c.redirect('/', 303);
  return c.html(eta.render('profile', { email }));
});

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
