const crypto = require('crypto');
const path = require('path');
const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { setCookie } = require('hono/cookie');
const { Eta } = require('eta');

const app = new Hono();
const eta = new Eta({ views: path.join(__dirname, 'views') });

app.use(secureHeaders());

const SESSION_MAX_AGE = 7 * 60 * 60;
const isProduction = process.env.NODE_ENV === 'production';

const users = new Map();

const hashPassword = (password, salt) =>
  crypto
    .createHash('sha256')
    .update(salt + password)
    .digest('hex');

const createUser = (email, password) => {
  const salt = crypto.randomBytes(16).toString('hex');
  const user = { email, hash: hashPassword(password, salt), salt };
  users.set(email, user);
  return user;
};

const welcomeTitles = ['Welcome', 'Welcome back', 'Hello', 'Hello again', 'Greetings'];

const renderSignin = (c, options = {}, status = 200) => {
  const title = welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)];
  return c.html(eta.render('signin', { title, ...options }), status);
};

app.get('/', (c) => renderSignin(c));

app.post('/signin', async (c) => {
  const body = await c.req.parseBody();
  const email = String(body.email || '');
  const password = String(body.password || '');
  const user = users.get(email);
  if (!user || user.hash !== hashPassword(password, user.salt)) {
    return renderSignin(c, { error: 'Invalid email or password' }, 401);
  }
  setCookie(c, 'session', user.email, {
    httpOnly: true,
    sameSite: 'Lax',
    secure: isProduction,
    maxAge: SESSION_MAX_AGE
  });
  return c.redirect('/profile');
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
