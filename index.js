const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');
const crypto = require('node:crypto');
const { setCookie } = require('hono/cookie');

const app = new Hono();
const eta = new Eta({ views: __dirname });

const SESSION_TTL_SECONDS = 7 * 60 * 60;
const isProduction = process.env.NODE_ENV === 'production';
const hmacSecret = crypto.randomBytes(32);

const sign = (value) => crypto.createHmac('sha256', hmacSecret).update(value).digest('base64url');

const createSessionToken = (email) => {
  const expires = Date.now() + SESSION_TTL_SECONDS * 1000;
  const payload = `${Buffer.from(email).toString('base64url')}.${expires}`;
  return `${payload}.${sign(payload)}`;
};

const verifySessionToken = (token) => {
  if (typeof token !== 'string') {
    return null;
  }
  const parts = token.split('.');
  if (parts.length !== 3) {
    return null;
  }
  const [encodedEmail, expires, signature] = parts;
  const payload = `${encodedEmail}.${expires}`;
  const expected = sign(payload);
  const given = Buffer.from(signature);
  if (given.length !== Buffer.byteLength(expected) || !crypto.timingSafeEqual(given, Buffer.from(expected))) {
    return null;
  }
  if (!/^\d+$/.test(expires) || Number(expires) < Date.now()) {
    return null;
  }
  return Buffer.from(encodedEmail, 'base64url').toString();
};

const users = new Map();

const saveUser = (email, passwordHash, salt) => {
  users.set(email.toLowerCase(), { email: email.toLowerCase(), passwordHash, salt });
};

const findUser = (email) => users.get(String(email).toLowerCase());

const hashPassword = (password, salt) => crypto.scryptSync(String(password), salt, 64);

const verifyCredentials = (email, password) => {
  const user = findUser(email);
  if (!user) {
    return null;
  }
  const candidate = hashPassword(password, user.salt);
  return crypto.timingSafeEqual(candidate, user.passwordHash) ? user : null;
};

app.use(secureHeaders());

const welcomeTitles = ['Welcome', 'Welcome back', 'Good to see you', 'Hello again', 'Great to have you here'];

const pickWelcomeTitle = () => welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)];

const renderSignIn = (data = {}) => eta.render('signin', { title: pickWelcomeTitle(), error: null, ...data });

app.get('/', (c) => c.html(renderSignIn()));

app.post('/signin', async (c) => {
  const body = await c.req.parseBody();
  const user = verifyCredentials(body.email, body.password);
  if (!user) {
    return c.html(renderSignIn({ error: 'Invalid email or password.' }), 401);
  }
  setCookie(c, 'session', createSessionToken(user.email), {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'Lax',
    path: '/',
    maxAge: SESSION_TTL_SECONDS
  });
  return c.redirect('/profile', 303);
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
