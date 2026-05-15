const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');
const crypto = require('crypto');

const eta = new Eta({ views: __dirname });
const app = new Hono();

app.use(
  secureHeaders({
    contentSecurityPolicy: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      upgradeInsecureRequests: []
    }
  })
);

app.use('*', (c, next) => {
  if (process.env.NODE_ENV === 'production' && c.req.header('x-forwarded-proto') === 'http') {
    return c.redirect(c.req.url.replace(/^http:/, 'https:'), 301);
  }
  return next();
});

const users = new Map();
const rateLimits = new Map();

const dummySalt = crypto.randomBytes(16).toString('hex');
const dummyHash = crypto.randomBytes(64).toString('hex');

const welcomeTitles = ['Welcome', 'Hello There', 'Good to See You', 'Sign In Below', 'Access Your Account'];

function hashPassword(password) {
  return new Promise((resolve) => {
    const salt = crypto.randomBytes(16).toString('hex');
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) return resolve(null);
      resolve({ salt, hash: derivedKey.toString('hex') });
    });
  });
}

function verifyPassword(password, salt, hash) {
  return new Promise((resolve) => {
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) return resolve(false);
      resolve(crypto.timingSafeEqual(derivedKey, Buffer.from(hash, 'hex')));
    });
  });
}

const hmacSecret = process.env.HMAC_SECRET;
if (!hmacSecret) {
  throw new Error('HMAC_SECRET environment variable is required');
}

function getClientIp(c) {
  const forwarded = c.req.header('x-forwarded-for');
  return forwarded ? forwarded.split(',')[0].trim() : 'unknown';
}

function checkRateLimit(key, maxAttempts, windowMs) {
  const now = Date.now();
  const record = rateLimits.get(key);
  if (!record || now > record.resetAt) {
    rateLimits.set(key, { attempts: 1, resetAt: now + windowMs });
    return true;
  }
  if (record.attempts >= maxAttempts) {
    return false;
  }
  record.attempts += 1;
  return true;
}

const failedLogins = new Map();

function isValidEmail(email) {
  if (!email || typeof email !== 'string') return false;
  if (email.length > 254) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function recordFailedLogin(email) {
  const now = Date.now();
  const record = failedLogins.get(email);
  if (!record || now > record.resetAt) {
    failedLogins.set(email, { count: 1, resetAt: now + 15 * 60 * 1000, lockedUntil: 0 });
  } else {
    record.count += 1;
    if (record.count >= 5) {
      record.lockedUntil = now + 15 * 60 * 1000;
    }
  }
}

function isAccountLocked(email) {
  const record = failedLogins.get(email);
  if (!record) return false;
  return Date.now() < record.lockedUntil;
}

function signSession(email, userAgent) {
  const exp = Date.now() + 7 * 60 * 60 * 1000;
  const fingerprint = crypto
    .createHash('sha256')
    .update(userAgent || '')
    .digest('base64url');
  const payload = Buffer.from(JSON.stringify({ email, exp, fingerprint })).toString('base64url');
  const signature = crypto.createHmac('sha256', hmacSecret).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

function generateCsrfToken() {
  const nonce = crypto.randomBytes(16).toString('hex');
  const signature = crypto.createHmac('sha256', hmacSecret).update(nonce).digest('hex');
  return `${nonce}.${signature}`;
}

function verifyCsrfToken(token) {
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [nonce, signature] = parts;
  const expected = crypto.createHmac('sha256', hmacSecret).update(nonce).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}

function verifySession(token, userAgent) {
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payload, signature] = parts;
  const expected = crypto.createHmac('sha256', hmacSecret).update(payload).digest('base64url');
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (Date.now() > data.exp) return null;
    const fingerprint = crypto
      .createHash('sha256')
      .update(userAgent || '')
      .digest('base64url');
    if (data.fingerprint !== fingerprint) return null;
    return data.email;
  } catch {
    return null;
  }
}

app.get('/', (c) => {
  const email = getSessionEmail(c);
  if (email) return c.redirect('/profile');
  return c.html(
    eta.render('sign-in.eta', {
      title: welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)],
      csrf: generateCsrfToken()
    })
  );
});

app.post('/', async (c) => {
  if (!checkRateLimit(`login:${getClientIp(c)}`, 5, 15 * 60 * 1000)) {
    return c.html(eta.render('sign-in.eta', { title: welcomeTitles[0], error: 'Too many attempts' }), 429);
  }
  const body = await c.req.parseBody();
  if (!verifyCsrfToken(body.csrf)) {
    return c.html(eta.render('sign-in.eta', { title: welcomeTitles[0], error: 'Invalid request' }), 403);
  }
  if (!isValidEmail(body.email)) {
    return c.html(eta.render('sign-in.eta', { title: welcomeTitles[0], error: 'Invalid email' }), 400);
  }
  if (isAccountLocked(body.email)) {
    return c.html(eta.render('sign-in.eta', { title: welcomeTitles[0], error: 'Account temporarily locked' }), 403);
  }
  const user = users.get(body.email);
  const salt = user ? user.salt : dummySalt;
  const hash = user ? user.hash : dummyHash;
  const valid = await verifyPassword(body.password, salt, hash);
  if (!user || !valid) {
    recordFailedLogin(body.email);
    return c.html(eta.render('sign-in.eta', { title: welcomeTitles[0], error: 'Invalid credentials' }), 401);
  }
  failedLogins.delete(body.email);
  const token = signSession(body.email, c.req.header('User-Agent'));
  const expires = new Date(Date.now() + 7 * 60 * 60 * 1000).toUTCString();
  const secureFlag = process.env.NODE_ENV === 'production' ? 'Secure' : '';
  c.header(
    'Set-Cookie',
    `session=${token}; HttpOnly; Path=/; SameSite=Strict; Expires=${expires}${secureFlag ? `; ${secureFlag}` : ''}`
  );
  return c.redirect('/profile');
});

function getSessionEmail(c) {
  const cookie = c.req.header('Cookie') || '';
  const match = cookie.match(/session=([^;]+)/);
  if (!match) return null;
  return verifySession(match[1], c.req.header('User-Agent'));
}

app.post('/register', async (c) => {
  if (!checkRateLimit(`register:${getClientIp(c)}`, 3, 15 * 60 * 1000)) {
    return c.html(eta.render('register.eta', { csrf: generateCsrfToken(), error: 'Too many attempts' }), 429);
  }
  const body = await c.req.parseBody();
  if (!verifyCsrfToken(body.csrf)) {
    return c.html(eta.render('register.eta', { csrf: generateCsrfToken(), error: 'Invalid request' }), 403);
  }
  if (!isValidEmail(body.email)) {
    return c.html(eta.render('register.eta', { csrf: generateCsrfToken(), error: 'Invalid email' }), 400);
  }
  if (!body.password || body.password.length < 8) {
    return c.html(
      eta.render('register.eta', { csrf: generateCsrfToken(), error: 'Password must be at least 8 characters' }),
      400
    );
  }
  if (!users.has(body.email)) {
    const hashed = await hashPassword(body.password);
    if (!hashed) {
      return c.html(eta.render('register.eta', { csrf: generateCsrfToken(), error: 'Registration failed' }), 500);
    }
    users.set(body.email, { email: body.email, salt: hashed.salt, hash: hashed.hash });
  }
  return c.html(
    `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="2;url=/"><title>Registered</title></head><body><p>Registration successful. Redirecting...</p></body></html>`
  );
});

app.get('/register', (c) => {
  const email = getSessionEmail(c);
  if (email) return c.redirect('/profile');
  return c.html(
    eta.render('register.eta', {
      csrf: generateCsrfToken()
    })
  );
});

app.get('/profile', (c) => {
  const email = getSessionEmail(c);
  if (!email) return c.redirect('/');
  return c.html(eta.render('profile.eta', { email }));
});

app.post('/signout', (c) => {
  const secureFlag = process.env.NODE_ENV === 'production' ? 'Secure' : '';
  c.header(
    'Set-Cookie',
    `session=; HttpOnly; Path=/; SameSite=Strict; Expires=Thu, 01 Jan 1970 00:00:00 GMT${secureFlag ? `; ${secureFlag}` : ''}`
  );
  return c.redirect('/');
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
