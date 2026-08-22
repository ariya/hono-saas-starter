const path = require('node:path');
const crypto = require('node:crypto');
const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');

const eta = new Eta({ views: path.join(__dirname, 'views') });

const welcomeTitles = ['Welcome', 'Welcome back', 'Hello there', 'Good to see you', 'Nice to meet you'];

const welcomeTitle = () => welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)];

const users = new Map();

const saveUser = (email, password) => {
  const salt = crypto.randomBytes(16).toString('hex');
  const passwordHash = crypto
    .createHash('sha256')
    .update(salt + password)
    .digest('hex');
  users.set(email, { email, passwordHash, salt });
};

const verifyCredentials = (email, password) => {
  const user = users.get(email);
  if (!user) return false;
  const passwordHash = crypto
    .createHash('sha256')
    .update(user.salt + password)
    .digest('hex');
  return (
    Buffer.byteLength(passwordHash) === Buffer.byteLength(user.passwordHash) &&
    crypto.timingSafeEqual(Buffer.from(passwordHash), Buffer.from(user.passwordHash))
  );
};

const app = new Hono();

app.use(secureHeaders());

app.get('/', (c) => c.html(eta.render('signin', { welcome: welcomeTitle() })));

app.post('/', async (c) => {
  const body = await c.req.parseBody();
  const email = String(body.email || '')
    .trim()
    .toLowerCase();
  const password = String(body.password || '');
  if (email && password && verifyCredentials(email, password)) {
    c.header('Set-Cookie', `session=${encodeURIComponent(email)}; Path=/; HttpOnly`);
    return c.redirect('/profile');
  }
  return c.html(
    eta.render('signin', {
      welcome: welcomeTitle(),
      email,
      error: 'Invalid email or password.'
    }),
    401
  );
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
