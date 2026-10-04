const crypto = require('node:crypto');
const path = require('node:path');
const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { setCookie } = require('hono/cookie');
const { Eta } = require('eta');

const app = new Hono();
const eta = new Eta({ views: path.join(__dirname, 'views') });

const welcomeTitles = ['Welcome', 'Welcome back', 'Hello there', 'Good to see you', 'Sign in to continue'];
const users = new Map();

function pickWelcomeTitle() {
  return welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)];
}

function getUser(email) {
  return users.get(String(email).toLowerCase());
}

function createUser(email, password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const passwordHash = crypto.scryptSync(password, salt, 64).toString('hex');
  const user = { email: String(email).toLowerCase(), passwordHash, salt };
  users.set(user.email, user);
  return user;
}

function verifyPassword(user, password) {
  const expected = Buffer.from(user.passwordHash, 'hex');
  const candidate = crypto.scryptSync(String(password), user.salt, 64);
  return candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected);
}

app.use(secureHeaders());

app.get('/', (c) => c.html(eta.render('signin', { title: pickWelcomeTitle() })));

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

app.post('/signin', async (c) => {
  const body = await c.req.parseBody();
  const user = getUser(body.email);
  if (!user || !verifyPassword(user, body.password)) {
    return c.html(eta.render('signin', { title: pickWelcomeTitle(), error: 'Invalid email or password.' }), 401);
  }
  setCookie(c, 'session', user.email, { httpOnly: true, path: '/', sameSite: 'Lax' });
  return c.redirect('/profile');
});

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
