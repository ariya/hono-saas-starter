const path = require('path');
const crypto = require('crypto');
const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { setCookie, deleteCookie, getCookie } = require('hono/cookie');
const { Eta } = require('eta');

const eta = new Eta({ views: path.join(__dirname, 'views'), cache: true });

const users = new Map();

const SCRYPT_PARAMS = { N: 2 ** 16, r: 8, p: 1, maxmem: 128 * 1024 * 1024 };
const SCRYPT_KEYLEN = 64;

const hashPassword = (password, salt) => {
  return crypto.scryptSync(password, salt, SCRYPT_KEYLEN, SCRYPT_PARAMS).toString('hex');
};

const DUMMY_SALT = crypto.randomBytes(16).toString('hex');
const DUMMY_HASH = hashPassword('dummy-password-for-timing', DUMMY_SALT);

const verifyPassword = (password, salt, expectedHex) => {
  const candidate = hashPassword(password, salt);
  const a = Buffer.from(candidate, 'hex');
  const b = Buffer.from(expectedHex, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
};

const IS_PROD = process.env.NODE_ENV === 'production';
const HMAC_SECRET = process.env.HMAC_SECRET;
if (!HMAC_SECRET || HMAC_SECRET.length < 32) {
  console.error('HMAC_SECRET environment variable is required and must be at least 32 characters');
  process.exit(1);
}

const SESSION_COOKIE = IS_PROD ? '__Host-sid' : 'sid';
const SESSION_MAX_AGE_SECONDS = 7 * 60 * 60;

const b64url = (buf) => buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

const b64urlDecode = (str) => {
  const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4));
  return Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64');
};

const hmac = (data) => crypto.createHmac('sha256', HMAC_SECRET).update(data).digest();

const activeSessions = new Map();

const signSession = (email) => {
  const jti = b64url(crypto.randomBytes(18));
  const issuedAt = Math.floor(Date.now() / 1000);
  const payload = `${b64url(Buffer.from(email))}.${jti}.${issuedAt}`;
  const sig = b64url(hmac(payload));
  activeSessions.set(jti, { email, issuedAt });
  return `${payload}.${sig}`;
};

const verifySession = (token) => {
  if (typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 4) return null;
  const [emailB64, jti, issuedAtStr, sigB64] = parts;
  const payload = `${emailB64}.${jti}.${issuedAtStr}`;
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
  const active = activeSessions.get(jti);
  if (!active || active.issuedAt !== issuedAt) return null;
  let email;
  try {
    email = b64urlDecode(emailB64).toString('utf8');
  } catch {
    return null;
  }
  if (active.email !== email) return null;
  return { email, jti };
};

const revokeSession = (jti) => {
  if (jti) activeSessions.delete(jti);
};

const sweepExpiredSessions = () => {
  const cutoff = Math.floor(Date.now() / 1000) - SESSION_MAX_AGE_SECONDS;
  for (const [jti, s] of activeSessions) {
    if (s.issuedAt < cutoff) activeSessions.delete(jti);
  }
};

const sessionCookieOptions = () => ({
  httpOnly: true,
  secure: IS_PROD,
  sameSite: 'Lax',
  path: '/',
  maxAge: SESSION_MAX_AGE_SECONDS
});

const CSRF_COOKIE = 'csrf';
const CSRF_TTL_SECONDS = 60 * 60;

const csrfCookieOptions = () => ({
  httpOnly: true,
  secure: IS_PROD,
  sameSite: 'Lax',
  path: '/',
  maxAge: CSRF_TTL_SECONDS
});

const ensureCsrfCookie = (c) => {
  let value = getCookie(c, CSRF_COOKIE);
  if (!value || !/^[A-Za-z0-9_-]{16,64}$/.test(value)) {
    value = b64url(crypto.randomBytes(24));
    setCookie(c, CSRF_COOKIE, value, csrfCookieOptions());
  }
  return value;
};

const issueCsrfToken = (cookieValue) => {
  const issuedAt = Math.floor(Date.now() / 1000);
  const payload = `${cookieValue}.${issuedAt}`;
  const sig = b64url(hmac(`csrf:${payload}`));
  return `${payload}.${sig}`;
};

const verifyCsrfToken = (token, cookieValue) => {
  if (typeof token !== 'string' || typeof cookieValue !== 'string' || !cookieValue) return false;
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const [tokenCookie, issuedAtStr, sigB64] = parts;
  if (tokenCookie !== cookieValue) return false;
  const payload = `${tokenCookie}.${issuedAtStr}`;
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

const currentSession = (c) => {
  const token = getCookie(c, SESSION_COOKIE);
  if (!token) return null;
  const session = verifySession(token);
  if (!session) return null;
  if (!users.has(session.email)) return null;
  return session;
};

const currentUserEmail = (c) => currentSession(c)?.email || null;

const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX = 10;
const rateBuckets = new Map();

const clientKey = (c) => {
  const fwd = c.req.header('x-forwarded-for');
  if (fwd) return fwd.split(',')[0].trim();
  return c.env?.incoming?.socket?.remoteAddress || 'unknown';
};

const rateLimit = (scope) => async (c, next) => {
  const key = `${scope}:${clientKey(c)}`;
  const now = Date.now();
  const bucket = rateBuckets.get(key);
  if (!bucket || now - bucket.start > RATE_LIMIT_WINDOW_MS) {
    rateBuckets.set(key, { start: now, count: 1 });
  } else {
    bucket.count += 1;
    if (bucket.count > RATE_LIMIT_MAX) {
      const retry = Math.ceil((bucket.start + RATE_LIMIT_WINDOW_MS - now) / 1000);
      c.header('Retry-After', String(Math.max(retry, 1)));
      return c.text('Too many requests. Please try again later.', 429);
    }
  }
  if (rateBuckets.size > 10000) {
    for (const [k, v] of rateBuckets) {
      if (now - v.start > RATE_LIMIT_WINDOW_MS) rateBuckets.delete(k);
    }
  }
  return next();
};

const app = new Hono();

const MAX_BODY_BYTES = 8 * 1024;

app.use(async (c, next) => {
  if (c.req.method === 'POST') {
    const len = c.req.header('content-length');
    if (len && Number.parseInt(len, 10) > MAX_BODY_BYTES) {
      return c.text('Request body too large.', 413);
    }
    const ct = (c.req.header('content-type') || '').split(';')[0].trim().toLowerCase();
    if (ct !== 'application/x-www-form-urlencoded') {
      return c.text('Unsupported media type.', 415);
    }
  }
  return next();
});

app.use(
  secureHeaders({
    contentSecurityPolicy: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", 'https://unpkg.com'],
      imgSrc: ["'self'", 'data:'],
      scriptSrc: ["'self'"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", 'https://unpkg.com', 'data:'],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: []
    },
    referrerPolicy: 'no-referrer'
  })
);

const WELCOME_TITLES = ['Welcome', 'Welcome back', 'Hello again', 'Good to see you', 'Sign in to continue'];

const pickWelcomeTitle = () => WELCOME_TITLES[Math.floor(Math.random() * WELCOME_TITLES.length)];

app.get('/', (c) => {
  if (currentUserEmail(c)) return c.redirect('/profile', 303);
  const csrfCookie = ensureCsrfCookie(c);
  return c.html(
    eta.render('signin', { title: pickWelcomeTitle(), error: null, email: '', csrf: issueCsrfToken(csrfCookie) })
  );
});

app.post('/signin', rateLimit('signin'), async (c) => {
  const body = await c.req.parseBody();
  const csrfCookie = getCookie(c, CSRF_COOKIE) || '';
  if (!verifyCsrfToken(String(body._csrf || ''), csrfCookie)) {
    const fresh = ensureCsrfCookie(c);
    return c.html(
      eta.render('signin', {
        title: pickWelcomeTitle(),
        error: 'Session expired. Please try again.',
        email: '',
        csrf: issueCsrfToken(fresh)
      }),
      403
    );
  }
  const email = normalizeEmail(body.email);
  const password = String(body.password || '');
  const user = users.get(email);
  const salt = user ? user.salt : DUMMY_SALT;
  const hash = user ? user.hash : DUMMY_HASH;
  const hashOk = verifyPassword(password, salt, hash);
  const ok = Boolean(user) && hashOk;
  if (!ok) {
    const fresh = ensureCsrfCookie(c);
    return c.html(
      eta.render('signin', {
        title: pickWelcomeTitle(),
        error: 'Invalid email or password.',
        email,
        csrf: issueCsrfToken(fresh)
      }),
      401
    );
  }
  setCookie(c, SESSION_COOKIE, signSession(email), sessionCookieOptions());
  return c.redirect('/profile', 303);
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

app.get('/profile', (c) => {
  const email = currentUserEmail(c);
  if (!email) return c.redirect('/', 303);
  const csrfCookie = ensureCsrfCookie(c);
  return c.html(eta.render('profile', { email, csrf: issueCsrfToken(csrfCookie) }));
});

app.get('/register', (c) => {
  if (currentUserEmail(c)) return c.redirect('/profile', 303);
  const csrfCookie = ensureCsrfCookie(c);
  return c.html(eta.render('register', { error: null, email: '', csrf: issueCsrfToken(csrfCookie) }));
});

const MIN_PASSWORD_LENGTH = 8;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const normalizeEmail = (input) =>
  String(input || '')
    .normalize('NFKC')
    .trim()
    .toLowerCase();

app.post('/register', rateLimit('register'), async (c) => {
  const body = await c.req.parseBody();
  const csrfCookie = getCookie(c, CSRF_COOKIE) || '';
  const rerender = (error, email = '', status = 400) => {
    const fresh = ensureCsrfCookie(c);
    return c.html(eta.render('register', { error, email, csrf: issueCsrfToken(fresh) }), status);
  };
  if (!verifyCsrfToken(String(body._csrf || ''), csrfCookie)) {
    return rerender('Session expired. Please try again.', '', 403);
  }
  const email = normalizeEmail(body.email);
  const password = String(body.password || '');
  if (!EMAIL_RE.test(email)) return rerender('Please enter a valid email address.', email);
  if (password.length < MIN_PASSWORD_LENGTH) {
    return rerender(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`, email);
  }
  if (users.has(email)) return rerender('An account with that email already exists.', email);
  const salt = crypto.randomBytes(16).toString('hex');
  users.set(email, { email, salt, hash: hashPassword(password, salt) });
  return c.html(eta.render('register-success', { email }));
});

app.post('/signout', async (c) => {
  const body = await c.req.parseBody();
  const csrfCookie = getCookie(c, CSRF_COOKIE) || '';
  if (!verifyCsrfToken(String(body._csrf || ''), csrfCookie)) {
    return c.redirect('/profile', 303);
  }
  const session = currentSession(c);
  if (session) revokeSession(session.jti);
  deleteCookie(c, SESSION_COOKIE, { path: '/' });
  return c.redirect('/', 303);
});

const port = process.env.PORT || 3000;
setInterval(sweepExpiredSessions, 60 * 60 * 1000).unref();
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
