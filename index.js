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
const HMAC_SECRET = process.env.HMAC_SECRET || crypto.randomBytes(32).toString('hex');
const rateLimitStore = new Map();

function rateLimit(windowMs, maxRequests) {
  return async (c, next) => {
    const ip = c.req.header('x-forwarded-for') || c.req.header('x-real-ip') || 'unknown';
    const now = Date.now();
    if (!rateLimitStore.has(ip)) {
      rateLimitStore.set(ip, []);
    }
    const timestamps = rateLimitStore.get(ip).filter((t) => now - t < windowMs);
    if (timestamps.length >= maxRequests) {
      return c.text('Too many requests', 429);
    }
    timestamps.push(now);
    rateLimitStore.set(ip, timestamps);
    await next();
  };
}

app.use(secureHeaders());

app.use(async (c, next) => {
  if (isSecure) {
    const proto = c.req.header('x-forwarded-proto') || '';
    if (proto === 'http') {
      const host = c.req.header('host') || '';
      return c.redirect(`https://${host.replace(/:\d+$/, '')}${c.req.url}`, 301);
    }
  }
  await next();
});

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
  const session = getCookie(c, 'session');
  const email = verifySession(session);
  if (email) return c.redirect('/profile');
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

app.post('/signin', rateLimit(60000, 10), async (c) => {
  const body = await c.req.parseBody();
  const csrfToken = body._csrf;
  const csrfCookie = getCookie(c, 'csrf');
  if (!csrfToken || !csrfCookie || !safeEqual(csrfToken, csrfCookie)) {
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

app.get('/register', (c) => {
  const csrf = generateCsrf();
  setCookie(c, 'csrf', csrf, { httpOnly: true, sameSite: 'Strict', secure: isSecure, path: '/' });
  return c.html(eta.render('register', { csrf }));
});

app.post('/register', rateLimit(60000, 10), async (c) => {
  const body = await c.req.parseBody();
  const csrfToken = body._csrf;
  const csrfCookie = getCookie(c, 'csrf');
  if (!csrfToken || !csrfCookie || !safeEqual(csrfToken, csrfCookie)) {
    return c.text('Invalid CSRF token', 403);
  }
  const email = body.email;
  const password = body.password;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    const csrf = generateCsrf();
    setCookie(c, 'csrf', csrf, { httpOnly: true, sameSite: 'Strict', secure: isSecure, path: '/' });
    return c.html(eta.render('register', { csrf, error: 'Valid email is required' }));
  }
  if (password.length < 8 || !/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/[0-9]/.test(password)) {
    const csrf = generateCsrf();
    setCookie(c, 'csrf', csrf, { httpOnly: true, sameSite: 'Strict', secure: isSecure, path: '/' });
    return c.html(
      eta.render('register', {
        csrf,
        error: 'Password must be at least 8 characters with uppercase, lowercase, and a number'
      })
    );
  }
  if (users.find((u) => u.email === email)) {
    const csrf = generateCsrf();
    setCookie(c, 'csrf', csrf, { httpOnly: true, sameSite: 'Strict', secure: isSecure, path: '/' });
    return c.html(eta.render('register', { csrf, error: 'Registration could not be completed' }));
  }
  const { salt, hash } = makeHash(password);
  users.push({ email, salt, hash });
  const csrf = generateCsrf();
  setCookie(c, 'csrf', csrf, { httpOnly: true, sameSite: 'Strict', secure: isSecure, path: '/' });
  return c.html(eta.render('register', { csrf, success: 'Account created! Redirecting to sign in...' }));
});

app.post('/signout', async (c) => {
  const body = await c.req.parseBody();
  const csrfToken = body._csrf;
  const csrfCookie = getCookie(c, 'csrf');
  if (!csrfToken || !csrfCookie || !safeEqual(csrfToken, csrfCookie)) {
    return c.redirect('/');
  }
  setCookie(c, 'session', '', { httpOnly: true, sameSite: 'Strict', secure: isSecure, maxAge: 0, path: '/' });
  return c.redirect('/');
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
