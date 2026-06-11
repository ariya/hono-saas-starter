const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { deleteCookie, getCookie, setCookie } = require('hono/cookie');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');
const crypto = require('crypto');
const path = require('path');
const { promisify } = require('util');

const app = new Hono();
const eta = new Eta({ views: path.join(__dirname) });
const users = new Map();
const authAttempts = new Map();
const sessionMaxAge = 7 * 60 * 60;
const csrfMaxAge = 60 * 60;
const throttleWindowMs = 15 * 60 * 1000;
const throttleMaxAttempts = 10;
const secureCookies = process.env.NODE_ENV !== 'development';
const hmacSecret = process.env.HMAC_SECRET;
const scryptAsync = promisify(crypto.scrypt);
const dummyPasswordHash = 'NxMUhF5J73aEZHmWUlgDtH-kd6TJmVWF8vbK0rSIE9L6I6lgbOwuHiMSa9jrNP2H5l0CV7tBGuICMFDdFxHvkQ';
const dummyPasswordSalt = 'dummy-password-salt';
const welcomeTitles = ['Welcome', 'Welcome back', 'Sign in to continue', 'Good to see you', 'Access your account'];

const shannonEntropyBits = (value) => {
  const counts = new Map();

  for (const character of value) {
    counts.set(character, (counts.get(character) || 0) + 1);
  }

  return [...counts.values()].reduce((entropy, count) => {
    const probability = count / value.length;

    return entropy - probability * Math.log2(probability) * value.length;
  }, 0);
};

const validateHmacSecret = (secret) => {
  if (!secret || Buffer.byteLength(secret, 'utf8') < 32 || shannonEntropyBits(secret) < 128) {
    throw new Error('HMAC_SECRET must contain at least 32 bytes and 128 bits of estimated entropy');
  }
};

validateHmacSecret(hmacSecret);

const saveUser = ({ email, passwordHash, salt }) => {
  const normalizedEmail = email.trim().toLowerCase();

  users.set(normalizedEmail, { email: normalizedEmail, passwordHash, salt });
};

const findUser = (email) => users.get(email.trim().toLowerCase());

const normalizeEmail = (email) => email.trim().toLowerCase();

const getClientAddress = (c) => {
  const forwardedFor = c.req.header('x-forwarded-for');

  if (forwardedFor) {
    return forwardedFor.split(',')[0].trim();
  }

  return c.req.header('cf-connecting-ip') || c.req.header('x-real-ip') || 'unknown';
};

const throttleKey = (c, route, email) => `${route}:${getClientAddress(c)}:${normalizeEmail(email)}`;

const isThrottled = (c, route, email) => {
  const now = Date.now();
  const key = throttleKey(c, route, email);
  const attempt = authAttempts.get(key);

  if (!attempt || now > attempt.resetAt) {
    authAttempts.set(key, { count: 1, resetAt: now + throttleWindowMs });
    return false;
  }

  attempt.count += 1;

  return attempt.count > throttleMaxAttempts;
};

const hashPassword = async (password, salt = crypto.randomBytes(16).toString('base64url')) => {
  const hash = await scryptAsync(password, salt, 64);

  return { passwordHash: hash.toString('base64url'), salt };
};

const timingSafeEqual = (left, right) => {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);

  return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
};

const verifyPassword = async (password, user) => {
  const { passwordHash } = await hashPassword(password, user.salt);

  return timingSafeEqual(passwordHash, user.passwordHash);
};

const verifyUnknownPassword = async (password) => {
  await verifyPassword(password, { passwordHash: dummyPasswordHash, salt: dummyPasswordSalt });
};

const signValue = (value) => crypto.createHmac('sha256', hmacSecret).update(value).digest('base64url');

const createCsrfToken = (action, subject = '') => {
  const payload = Buffer.from(
    JSON.stringify({
      action,
      subject,
      nonce: crypto.randomBytes(16).toString('base64url'),
      expiresAt: Date.now() + csrfMaxAge * 1000
    })
  ).toString('base64url');

  return `${payload}.${signValue(payload)}`;
};

const verifyCsrfToken = (token, action, subject = '') => {
  const [payload, signature] = String(token || '').split('.');

  if (!payload || !signature || !timingSafeEqual(signature, signValue(payload))) {
    return false;
  }

  try {
    const csrfData = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));

    return Boolean(
      csrfData.action === action && csrfData.subject === subject && csrfData.nonce && Date.now() <= csrfData.expiresAt
    );
  } catch {
    return false;
  }
};

const createSessionValue = (user) => {
  const payload = Buffer.from(
    JSON.stringify({ email: user.email, expiresAt: Date.now() + sessionMaxAge * 1000 })
  ).toString('base64url');

  return `${payload}.${signValue(payload)}`;
};

const readSessionValue = (session) => {
  const [payload, signature] = String(session || '').split('.');

  if (!payload || !signature || !timingSafeEqual(signature, signValue(payload))) {
    return null;
  }

  try {
    const sessionData = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));

    if (!sessionData.email || Date.now() > sessionData.expiresAt) {
      return null;
    }

    return sessionData;
  } catch {
    return null;
  }
};

const getAuthenticatedUser = (c) => {
  const session = readSessionValue(getCookie(c, 'session'));

  if (!session) {
    return null;
  }

  return findUser(session.email) || null;
};

app.use(secureHeaders());

const render = (template, data = {}) => eta.render(template, data);

const randomWelcomeTitle = () => welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)];

const renderSignIn = (data = {}) =>
  render('sign-in.eta', {
    title: randomWelcomeTitle(),
    error: '',
    email: '',
    csrfToken: createCsrfToken('signin'),
    ...data
  });

const renderRegister = (data = {}) =>
  render('register.eta', { error: '', message: '', email: '', csrfToken: createCsrfToken('register'), ...data });

app.get('/', (c) => {
  if (getAuthenticatedUser(c)) {
    return c.redirect('/profile');
  }

  return c.html(renderSignIn());
});

app.get('/register', (c) => c.html(renderRegister()));

app.post('/register', async (c) => {
  const body = await c.req.parseBody();
  const email = String(body.email || '').trim();
  const password = String(body.password || '');

  if (isThrottled(c, 'register', email)) {
    return c.html(renderRegister({ error: 'Too many attempts. Please try again later.', email }), 429);
  }

  if (!verifyCsrfToken(body.csrfToken, 'register')) {
    return c.html(renderRegister({ error: 'Your session expired. Please try again.', email }), 403);
  }

  if (password.length < 8) {
    return c.html(renderRegister({ error: 'Password must be at least 8 characters.', email }), 400);
  }

  if (!findUser(email)) {
    saveUser({ email, ...(await hashPassword(password)) });
  }

  return c.html(
    renderRegister({ message: 'If registration can continue, you will be redirected to sign in.', redirectTo: '/' }),
    201
  );
});

app.post('/signin', async (c) => {
  const body = await c.req.parseBody();
  const email = String(body.email || '').trim();
  const password = String(body.password || '');

  if (isThrottled(c, 'signin', email)) {
    return c.html(renderSignIn({ error: 'Too many attempts. Please try again later.', email }), 429);
  }

  if (!verifyCsrfToken(body.csrfToken, 'signin')) {
    return c.html(renderSignIn({ error: 'Your session expired. Please try again.', email }), 403);
  }

  const user = findUser(email);
  const passwordValid = user ? await verifyPassword(password, user) : false;

  if (!user) {
    await verifyUnknownPassword(password);
  }

  if (!user || !passwordValid) {
    return c.html(renderSignIn({ error: 'Invalid email or password.', email }), 401);
  }

  setCookie(c, 'session', createSessionValue(user), {
    httpOnly: true,
    maxAge: sessionMaxAge,
    path: '/',
    sameSite: 'Lax',
    secure: secureCookies
  });
  return c.redirect('/profile');
});

app.get('/profile', (c) => {
  const user = getAuthenticatedUser(c);

  if (!user) {
    return c.redirect('/');
  }

  return c.html(render('profile.eta', { user, csrfToken: createCsrfToken('signout', user.email) }));
});

app.post('/signout', async (c) => {
  const user = getAuthenticatedUser(c);
  const body = await c.req.parseBody();

  if (!user || !verifyCsrfToken(body.csrfToken, 'signout', user.email)) {
    return c.redirect('/profile');
  }

  deleteCookie(c, 'session', { path: '/' });
  return c.redirect('/');
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
