const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { getCookie, setCookie } = require('hono/cookie');
const { Eta } = require('eta');
const path = require('node:path');
const crypto = require('node:crypto');

const eta = new Eta({ views: path.join(__dirname, 'views'), cache: false });

const isDev = process.env.NODE_ENV !== 'production';

const WELCOME_TITLES = ['Welcome back', 'Hello again', 'Good to see you', 'We missed you', 'Glad you are here'];

const users = new Map();

const hashPassword = (password, salt) => {
  return crypto
    .createHash('sha256')
    .update(salt + password)
    .digest('hex');
};

const createUser = (email, password) => {
  const salt = crypto.randomBytes(16).toString('hex');
  const user = { email, salt, passwordHash: hashPassword(password, salt) };
  users.set(email, user);
  return user;
};

const findUser = (email) => users.get(email);

const verifyPassword = (password, user) => {
  return user.passwordHash === hashPassword(password, user.salt);
};

createUser('demo@example.com', 'password123456');

const app = new Hono();

app.use(secureHeaders());

const renderSignin = (data) => {
  const welcome = data.welcome || WELCOME_TITLES[Math.floor(Math.random() * WELCOME_TITLES.length)];
  return eta.render('signin', { welcome, ...data });
};

app.get('/', (c) => {
  return c.html(renderSignin({}));
});

app.post('/signin', async (c) => {
  const body = await c.req.parseBody();
  const email = String(body.email || '').toLowerCase();
  const password = String(body.password || '');
  const user = findUser(email);
  if (!user || !verifyPassword(password, user)) {
    return c.html(renderSignin({ email, error: 'Invalid email or password.' }), 401);
  }
  setCookie(c, 'session', user.email, {
    path: '/',
    httpOnly: true,
    sameSite: 'Lax',
    secure: !isDev,
    maxAge: 7 * 60 * 60
  });
  return c.redirect('/profile');
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
