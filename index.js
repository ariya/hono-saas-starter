const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');
const crypto = require('node:crypto');

const app = new Hono();
const eta = new Eta({ views: __dirname });

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

app.get('/', (c) => c.html(eta.render('signin', { title: pickWelcomeTitle() })));

app.post('/signin', async (c) => {
  const body = await c.req.parseBody();
  const user = verifyCredentials(body.email, body.password);
  if (!user) {
    return c.text('Invalid email or password', 401);
  }
  return c.text('Signed in');
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
