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

app.use(async (c, next) => {
  const length = Number(c.req.header('content-length'));
  if (c.req.method === 'POST' && Number.isFinite(length) && length > MAX_BODY_SIZE) {
    return c.text('Payload Too Large', 413);
  }
  await next();
});

const SESSION_MAX_AGE = 7 * 60 * 60;
const isProduction = process.env.NODE_ENV === 'production';
const HMAC_SECRET = process.env.HMAC_SECRET || (isProduction ? '' : crypto.randomBytes(32).toString('hex'));
if (!HMAC_SECRET) {
  console.error('HMAC_SECRET environment variable is required in production');
  process.exit(1);
}

const RATE_LIMIT_MAX = 10;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const MAX_BODY_SIZE = 16 * 1024;
const MAX_EMAIL_LENGTH = 254;
const MAX_PASSWORD_LENGTH = 256;

const users = new Map();
const rateLimits = new Map();

const DUMMY_USER = { salt: crypto.randomBytes(16).toString('hex'), hash: crypto.randomBytes(64).toString('hex') };

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

const sessionEmail = (c) => {
  const email = verifySession(getCookie(c, 'session'));
  if (!email || !users.has(email)) return null;
  return email;
};

const welcomeTitles = ['Welcome', 'Welcome back', 'Hello', 'Hello again', 'Greetings'];

const renderSignin = (c, options = {}, status = 200) => {
  const title = welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)];
  return c.html(eta.render('signin', { title, csrf: issueCsrfToken(c), ...options }), status);
};

app.get('/', (c) => {
  if (sessionEmail(c)) return c.redirect('/profile');
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
  if (email.length > MAX_EMAIL_LENGTH || password.length > MAX_PASSWORD_LENGTH) {
    return renderSignin(c, { error: 'Invalid email or password' }, 401);
  }
  const user = users.get(email);
  const passwordValid = verifyPassword(password, user || DUMMY_USER);
  if (!user || !passwordValid) {
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
  if (email.length > MAX_EMAIL_LENGTH) {
    return c.html(
      eta.render('register', { csrf: issueCsrfToken(c), error: 'Email must be at most 254 characters long' }),
      400
    );
  }
  if (password.length > MAX_PASSWORD_LENGTH) {
    return c.html(
      eta.render('register', { csrf: issueCsrfToken(c), error: 'Password must be at most 256 characters long' }),
      400
    );
  }
  if (!email.includes('@')) {
    return c.html(eta.render('register', { csrf: issueCsrfToken(c), error: 'A valid email address is required' }), 400);
  }
  if (password.length < 8) {
    return c.html(
      eta.render('register', { csrf: issueCsrfToken(c), error: 'Password must be at least 8 characters long' }),
      400
    );
  }
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = hashPassword(password, salt).toString('hex');
  if (!users.has(email)) {
    users.set(email, { email, hash, salt });
  }
  return c.html(
    eta.render('register', {
      csrf: issueCsrfToken(c),
      success: 'If this email is not registered yet, the account has been created. Redirecting to sign in...'
    })
  );
});

app.get('/profile', (c) => {
  const email = sessionEmail(c);
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
