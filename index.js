const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');
const crypto = require('crypto');
const { getCookie, setCookie } = require('hono/cookie');

const app = new Hono();
const eta = new Eta({ views: __dirname });
const users = [];
const isSecure = process.env.NODE_ENV === 'production';
const HMAC_SECRET = process.env.HMAC_SECRET || 'dev-secret-change-in-production';

app.use(secureHeaders());

function makeHash(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

function hmac(data) {
  return crypto.createHmac('sha256', HMAC_SECRET).update(data).digest('hex');
}

function safeEqual(a, b) {
  if (Buffer.byteLength(a) !== Buffer.byteLength(b)) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

function signSession(email) {
  const payload = Buffer.from(email).toString('base64');
  return `${payload}.${hmac(email)}`;
}

function verifySession(cookie) {
  if (!cookie) return null;
  const dot = cookie.indexOf('.');
  if (dot === -1) return null;
  const payload = cookie.slice(0, dot);
  const sig = cookie.slice(dot + 1);
  if (!payload || !sig) return null;
  let email;
  try {
    email = Buffer.from(payload, 'base64').toString('utf-8');
  } catch {
    return null;
  }
  if (!safeEqual(sig, hmac(email))) return null;
  return email;
}

function generateCsrf() {
  const raw = crypto.randomBytes(32).toString('hex');
  return `${raw}.${hmac(raw)}`;
}

const welcomeMessages = ['Welcome', 'Hello again', 'Good to see you', 'Welcome back', 'Hey there'];

app.get('/', (c) => {
  const csrf = generateCsrf();
  setCookie(c, 'csrf', csrf, { httpOnly: true, sameSite: 'Strict', secure: isSecure, path: '/' });
  const welcome = welcomeMessages[Math.floor(Math.random() * welcomeMessages.length)];
  return c.html(eta.render('signin', { welcome, csrf }));
});

app.get('/profile', (c) => {
  const session = getCookie(c, 'session');
  const email = verifySession(session);
  if (!email) return c.redirect('/');
  const csrf = generateCsrf();
  setCookie(c, 'csrf', csrf, { httpOnly: true, sameSite: 'Strict', secure: isSecure, path: '/' });
  return c.html(eta.render('profile', { email, csrf }));
});

app.post('/signin', async (c) => {
  const body = await c.req.parseBody();
  if (!safeEqual(body._csrf || '', getCookie(c, 'csrf') || '')) {
    return c.text('Invalid CSRF token', 403);
  }
  const email = body.email;
  const password = body.password;
  const user = users.find((u) => u.email === email);
  if (!user) {
    const csrf = generateCsrf();
    setCookie(c, 'csrf', csrf, { httpOnly: true, sameSite: 'Strict', secure: isSecure, path: '/' });
    const welcome = welcomeMessages[Math.floor(Math.random() * welcomeMessages.length)];
    return c.html(eta.render('signin', { welcome, error: 'Invalid email or password', csrf }));
  }
  const { hash } = makeHash(password, user.salt);
  if (!safeEqual(hash, user.hash)) {
    const csrf = generateCsrf();
    setCookie(c, 'csrf', csrf, { httpOnly: true, sameSite: 'Strict', secure: isSecure, path: '/' });
    const welcome = welcomeMessages[Math.floor(Math.random() * welcomeMessages.length)];
    return c.html(eta.render('signin', { welcome, error: 'Invalid email or password', csrf }));
  }
  const session = signSession(email);
  setCookie(c, 'session', session, { httpOnly: true, sameSite: 'Strict', secure: isSecure, maxAge: 25200, path: '/' });
  return c.redirect('/profile');
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
