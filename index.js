const crypto = require('crypto');
const path = require('path');
const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { deleteCookie, getCookie, setCookie } = require('hono/cookie');
const { Eta } = require('eta');

const app = new Hono();
const eta = new Eta({ views: path.join(__dirname, 'views') });

app.use(secureHeaders());

const SESSION_MAX_AGE = 7 * 60 * 60;
const isProduction = process.env.NODE_ENV === 'production';
const HMAC_SECRET = process.env.HMAC_SECRET || (isProduction ? '' : crypto.randomBytes(32).toString('hex'));
if (!HMAC_SECRET) {
  console.error('HMAC_SECRET environment variable is required in production');
  process.exit(1);
}

const RATE_LIMIT_MAX = 10;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;

const users = new Map();
const rateLimits = new Map();

const clientIp = (c) => c.env.incoming?.socket?.remoteAddress || 'unknown';

const isRateLimited = (key) => {
  const now = Date.now();
  let entry = rateLimits.get(key);
  if (!entry || entry.reset <= now) {
    entry = { count: 0, reset: now + RATE_LIMIT_WINDOW_MS };
    rateLimits.set(key, entry);
    if (rateLimits.size > 1000) {
      for (const [k, v] of rateLimits) {
        if (v.reset <= now) rateLimits.delete(k);
      }
    }
  }
  entry.count += 1;
  return entry.count > RATE_LIMIT_MAX;
};

const hashPassword = (password, salt) => crypto.scryptSync(password, salt, 64);

const verifyPassword = (password, user) => {
  const candidate = hashPassword(password, user.salt);
  const stored = Buffer.from(user.hash, 'hex');
  return candidate.length === stored.length && crypto.timingSafeEqual(candidate, stored);
};

const hmac = (value) => crypto.createHmac('sha256', HMAC_SECRET).update(value).digest('hex');

const createSession = (email) => {
  const payload = `${Buffer.from(email).toString('base64url')}.${Date.now() + SESSION_MAX_AGE * 1000}`;
  return `${payload}.${hmac(payload)}`;
};

const verifySession = (token) => {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [encoded, expires, signature] = parts;
  const expected = hmac(`${encoded}.${expires}`);
  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  const expiresAt = Number(expires);
  if (!Number.isFinite(expiresAt) || expiresAt < Date.now()) return null;
  return Buffer.from(encoded, 'base64url').toString();
};

const issueCsrfToken = (c) => {
  const nonce = crypto.randomBytes(16).toString('hex');
  setCookie(c, 'csrf', nonce, {
    httpOnly: true,
    sameSite: 'Lax',
    secure: isProduction,
    maxAge: SESSION_MAX_AGE
  });
  return hmac(`csrf:${nonce}`);
};

const verifyCsrfToken = (c, token) => {
  const nonce = getCookie(c, 'csrf');
  if (!nonce || !token) return false;
  const expected = hmac(`csrf:${nonce}`);
  const a = Buffer.from(String(token));
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};

const createUser = (email, password) => {
  const salt = crypto.randomBytes(16).toString('hex');
  const user = { email, hash: hashPassword(password, salt).toString('hex'), salt };
  users.set(email, user);
  return user;
};

const welcomeTitles = ['Welcome', 'Welcome back', 'Hello', 'Hello again', 'Greetings'];

const renderSignin = (c, options = {}, status = 200) => {
  const title = welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)];
  return c.html(eta.render('signin', { title, csrf: issueCsrfToken(c), ...options }), status);
};

app.get('/', (c) => {
  if (verifySession(getCookie(c, 'session'))) return c.redirect('/profile');
  return renderSignin(c);
});

app.post('/signin', async (c) => {
  if (isRateLimited(clientIp(c))) {
    return renderSignin(c, { error: 'Too many attempts, please try again later' }, 429);
  }
  const body = await c.req.parseBody();
  if (!verifyCsrfToken(c, body.csrf)) {
    return renderSignin(c, { error: 'Invalid form submission, please try again' }, 403);
  }
  const email = String(body.email || '');
  const password = String(body.password || '');
  const user = users.get(email);
  if (!user || !verifyPassword(password, user)) {
    return renderSignin(c, { error: 'Invalid email or password' }, 401);
  }
  setCookie(c, 'session', createSession(user.email), {
    httpOnly: true,
    sameSite: 'Lax',
    secure: isProduction,
    maxAge: SESSION_MAX_AGE
  });
  return c.redirect('/profile');
});

app.get('/register', (c) => c.html(eta.render('register', { csrf: issueCsrfToken(c) })));

app.post('/register', async (c) => {
  if (isRateLimited(clientIp(c))) {
    return c.html(
      eta.render('register', { csrf: issueCsrfToken(c), error: 'Too many attempts, please try again later' }),
      429
    );
  }
  const body = await c.req.parseBody();
  if (!verifyCsrfToken(c, body.csrf)) {
    return c.html(
      eta.render('register', { csrf: issueCsrfToken(c), error: 'Invalid form submission, please try again' }),
      403
    );
  }
  const email = String(body.email || '');
  const password = String(body.password || '');
  if (!email.includes('@')) {
    return c.html(eta.render('register', { csrf: issueCsrfToken(c), error: 'A valid email address is required' }), 400);
  }
  if (password.length < 8) {
    return c.html(
      eta.render('register', { csrf: issueCsrfToken(c), error: 'Password must be at least 8 characters long' }),
      400
    );
  }
  if (users.has(email)) {
    return c.html(
      eta.render('register', { csrf: issueCsrfToken(c), error: 'An account with this email already exists' }),
      409
    );
  }
  createUser(email, password);
  return c.html(
    eta.render('register', {
      csrf: issueCsrfToken(c),
      success: 'Account created successfully, redirecting to sign in...'
    }),
    201
  );
});

app.get('/profile', (c) => {
  const email = verifySession(getCookie(c, 'session'));
  if (!email) return c.redirect('/');
  return c.html(eta.render('profile', { email, csrf: issueCsrfToken(c) }));
});

app.post('/signout', async (c) => {
  const body = await c.req.parseBody();
  if (!verifyCsrfToken(c, body.csrf)) {
    return c.redirect('/');
  }
  deleteCookie(c, 'session');
  return c.redirect('/');
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
