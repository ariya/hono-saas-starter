const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { getCookie, setCookie } = require('hono/cookie');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');
const crypto = require('crypto');
const path = require('path');
const { promisify } = require('util');

const app = new Hono();
const eta = new Eta({ views: path.join(__dirname) });
const users = new Map();
const sessionMaxAge = 7 * 60 * 60;
const csrfMaxAge = 60 * 60;
const secureCookies = process.env.NODE_ENV !== 'development';
const hmacSecret = process.env.HMAC_SECRET;
const scryptAsync = promisify(crypto.scrypt);
const welcomeTitles = ['Welcome', 'Welcome back', 'Sign in to continue', 'Good to see you', 'Access your account'];

if (!hmacSecret) {
  throw new Error('HMAC_SECRET is required');
}

const saveUser = ({ email, passwordHash, salt }) => {
  const normalizedEmail = email.trim().toLowerCase();

  users.set(normalizedEmail, { email: normalizedEmail, passwordHash, salt });
};

const findUser = (email) => users.get(email.trim().toLowerCase());

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

const signValue = (value) => crypto.createHmac('sha256', hmacSecret).update(value).digest('base64url');

const createCsrfToken = () => {
  const payload = Buffer.from(
    JSON.stringify({ nonce: crypto.randomBytes(16).toString('base64url'), expiresAt: Date.now() + csrfMaxAge * 1000 })
  ).toString('base64url');

  return `${payload}.${signValue(payload)}`;
};

const verifyCsrfToken = (token) => {
  const [payload, signature] = String(token || '').split('.');

  if (!payload || !signature || !timingSafeEqual(signature, signValue(payload))) {
    return false;
  }

  try {
    const csrfData = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));

    return Boolean(csrfData.nonce && Date.now() <= csrfData.expiresAt);
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
  render('sign-in.eta', { title: randomWelcomeTitle(), error: '', email: '', csrfToken: createCsrfToken(), ...data });

const renderRegister = (data = {}) =>
  render('register.eta', { error: '', message: '', email: '', csrfToken: createCsrfToken(), ...data });

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

  if (!verifyCsrfToken(body.csrfToken)) {
    return c.html(renderRegister({ error: 'Your session expired. Please try again.', email }), 403);
  }

  if (password.length < 8) {
    return c.html(renderRegister({ error: 'Password must be at least 8 characters.', email }), 400);
  }

  if (findUser(email)) {
    return c.html(renderRegister({ error: 'An account already exists for that email.', email }), 409);
  }

  saveUser({ email, ...(await hashPassword(password)) });

  return c.html(renderRegister({ message: 'Account created. Redirecting to sign in.', redirectTo: '/' }), 201);
});

app.post('/signin', async (c) => {
  const body = await c.req.parseBody();
  const email = String(body.email || '').trim();
  const password = String(body.password || '');

  if (!verifyCsrfToken(body.csrfToken)) {
    return c.html(renderSignIn({ error: 'Your session expired. Please try again.', email }), 403);
  }

  const user = findUser(email);

  if (!user || !(await verifyPassword(password, user))) {
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

  return c.html(render('profile.eta', { user }));
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
