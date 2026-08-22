const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { bodyLimit } = require('hono/body-limit');
const { getCookie, setCookie, deleteCookie } = require('hono/cookie');
const { Eta } = require('eta');
const { randomInt, randomBytes, scryptSync, timingSafeEqual, createHmac } = require('crypto');

const eta = new Eta({ views: 'views' });

const welcomeTitles = ['Welcome back', 'Hello again', 'Good to see you', 'Hey there', 'Greetings'];

const users = new Map();

const isProd = process.env.NODE_ENV === 'production';

const sessionDurationMs = 7 * 60 * 60 * 1000;
const csrfDurationMs = 2 * 60 * 60 * 1000;
const maxBodyBytes = 16 * 1024;
const maxEmailLength = 254;
const maxPasswordLength = 256;

const providedSecret = process.env.HMAC_SECRET;
if (providedSecret !== undefined && providedSecret.length < 32) {
  console.error('Refusing to start: HMAC_SECRET must be at least 32 characters');
  process.exit(1);
}

const hmacSecret = providedSecret || (isProd ? null : randomBytes(32).toString('hex'));

if (!hmacSecret) {
  console.error('Refusing to start: HMAC_SECRET environment variable is required in production');
  process.exit(1);
}

function hashPassword(password, salt) {
  return scryptSync(password, salt, 64).toString('hex');
}

const dummySalt = randomBytes(16).toString('hex');
const dummyHash = Buffer.from(hashPassword(randomBytes(32).toString('hex'), dummySalt), 'hex');

function verifyUser(email, password) {
  const user = users.get(
    String(email || '')
      .trim()
      .toLowerCase()
  );
  if (!user) {
    timingSafeEqual(Buffer.from(hashPassword(password || '', dummySalt), 'hex'), dummyHash);
    return null;
  }
  const candidate = Buffer.from(hashPassword(password, user.salt), 'hex');
  const stored = Buffer.from(user.hash, 'hex');
  return candidate.length === stored.length && timingSafeEqual(candidate, stored) ? user : null;
}

function ensureCsrfSecret(c) {
  const existing = getCookie(c, 'csrf');
  if (existing) return existing;
  const secret = randomBytes(32).toString('base64url');
  setCookie(c, 'csrf', secret, {
    httpOnly: true,
    path: '/',
    secure: isProd,
    sameSite: 'Lax',
    maxAge: csrfDurationMs / 1000
  });
  return secret;
}

function createCsrfToken(csrfSecret) {
  const exp = Date.now() + csrfDurationMs;
  const nonce = randomBytes(16).toString('base64url');
  const sig = createHmac('sha256', hmacSecret).update(`csrf:${csrfSecret}:${exp}:${nonce}`).digest('base64url');
  return `${exp}.${nonce}.${sig}`;
}

function verifyCsrfToken(token, csrfSecret) {
  if (typeof token !== 'string' || typeof csrfSecret !== 'string' || !csrfSecret) return false;
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const [exp, nonce, sig] = parts;
  if (!/^\d+$/.test(exp) || Date.now() > Number(exp)) return false;
  const expected = createHmac('sha256', hmacSecret).update(`csrf:${csrfSecret}:${exp}:${nonce}`).digest('base64url');
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

const rateLimits = new Map();
const rateLimitMax = 5;
const rateLimitWindowMs = 15 * 60 * 1000;

function clientIp(c) {
  const forwarded = c.req.header('x-forwarded-for');
  if (forwarded) return forwarded.split(',')[0].trim();
  return c.env?.incoming?.socket?.remoteAddress || 'unknown';
}

function allowRequest(key) {
  const now = Date.now();
  const entry = rateLimits.get(key);
  if (!entry || now >= entry.resetAt) {
    rateLimits.set(key, { count: 1, resetAt: now + rateLimitWindowMs });
    return true;
  }
  entry.count += 1;
  return entry.count <= rateLimitMax;
}

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimits) {
    if (now >= entry.resetAt) {
      rateLimits.delete(key);
    }
  }
}, rateLimitWindowMs).unref();

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

app.use(
  secureHeaders({
    contentSecurityPolicy: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://unpkg.com'],
      imgSrc: ["'self'", 'data:'],
      formAction: ["'self'"],
      frameAncestors: ["'self'"],
      baseUri: ["'self'"],
      objectSrc: ["'none'"]
    }
  })
);
app.use(bodyLimit({ maxSize: maxBodyBytes }));

app.get('/', (c) => {
  if (verifySession(getCookie(c, 'session'))) {
    return c.redirect('/profile');
  }
  const csrfSecret = ensureCsrfSecret(c);
  const title = welcomeTitles[randomInt(welcomeTitles.length)];
  return c.html(eta.render('signin', { title, error: null, csrf: createCsrfToken(csrfSecret) }));
});

app.post('/signin', async (c) => {
  const body = await c.req.parseBody();
  const csrfSecret = ensureCsrfSecret(c);
  const csrf = createCsrfToken(csrfSecret);
  if (!allowRequest(`signin:${clientIp(c)}`)) {
    const title = welcomeTitles[randomInt(welcomeTitles.length)];
    return c.html(eta.render('signin', { title, error: 'Too many attempts. Please try again later.', csrf }), 429);
  }
  if (!verifyCsrfToken(body._csrf, getCookie(c, 'csrf'))) {
    const title = welcomeTitles[randomInt(welcomeTitles.length)];
    return c.html(eta.render('signin', { title, error: 'Session expired. Please try again.', csrf }), 403);
  }
  const email = String(body.email || '');
  const password = String(body.password || '');
  if (email.length > maxEmailLength || password.length > maxPasswordLength) {
    const title = welcomeTitles[randomInt(welcomeTitles.length)];
    return c.html(eta.render('signin', { title, error: 'Invalid email or password.', csrf }), 401);
  }
  const user = verifyUser(email, password);
  if (!user) {
    const title = welcomeTitles[randomInt(welcomeTitles.length)];
    return c.html(eta.render('signin', { title, error: 'Invalid email or password.', csrf }), 401);
  }
  setCookie(c, 'session', signSession(user.email), {
    httpOnly: true,
    path: '/',
    secure: isProd,
    sameSite: 'Lax',
    maxAge: sessionDurationMs / 1000
  });
  return c.redirect('/profile');
});

app.get('/register', (c) => {
  const csrfSecret = ensureCsrfSecret(c);
  return c.html(eta.render('register', { error: null, success: null, csrf: createCsrfToken(csrfSecret) }));
});

app.post('/register', async (c) => {
  const body = await c.req.parseBody();
  const csrfSecret = ensureCsrfSecret(c);
  const csrf = createCsrfToken(csrfSecret);
  if (!allowRequest(`register:${clientIp(c)}`)) {
    return c.html(
      eta.render('register', { error: 'Too many attempts. Please try again later.', success: null, csrf }),
      429
    );
  }
  if (!verifyCsrfToken(body._csrf, getCookie(c, 'csrf'))) {
    return c.html(eta.render('register', { error: 'Session expired. Please try again.', success: null, csrf }), 403);
  }
  const password = String(body.password || '');
  if (password.length < 8) {
    return c.html(
      eta.render('register', { error: 'Password must be at least 8 characters long.', success: null, csrf }),
      400
    );
  }
  if (password.length > maxPasswordLength) {
    return c.html(
      eta.render('register', { error: 'Password must be at most 256 characters long.', success: null, csrf }),
      400
    );
  }
  const email = String(body.email || '')
    .trim()
    .toLowerCase();
  if (!email.includes('@') || email.length > maxEmailLength) {
    return c.html(eta.render('register', { error: 'Please enter a valid email address.', success: null, csrf }), 400);
  }
  const salt = randomBytes(16).toString('hex');
  const hash = hashPassword(password, salt);
  if (users.has(email)) {
    return c.html(
      eta.render('register', { error: null, success: 'Account created successfully. Redirecting…', csrf }),
      201
    );
  }
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
