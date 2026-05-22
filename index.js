const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');
const path = require('path');
const crypto = require('crypto');
const { setCookie, getCookie } = require('hono/cookie');

const app = new Hono();

const eta = new Eta({ views: path.join(__dirname, 'templates') });

app.use(secureHeaders());

const users = new Map();

const welcomes = [
  'Welcome back!',
  'Glad to see you again!',
  'Hello! Please sign in',
  'Welcome to Hono SaaS Starter!',
  'Ready to get started? Log in'
];

app.get('/', (c) => {
  const welcome = welcomes[Math.floor(Math.random() * welcomes.length)];
  return c.html(eta.render('./signin', { welcome }));
});

app.post('/signin', async (c) => {
  const body = await c.req.parseBody();
  const email = body.email;
  const password = body.password;
  const user = users.get(email);
  if (!user) {
    const welcome = welcomes[Math.floor(Math.random() * welcomes.length)];
    return c.html(eta.render('./signin', { welcome, error: 'Invalid email or password' }));
  }
  const hash = crypto.scryptSync(password, user.salt, 64).toString('hex');
  if (hash !== user.passwordHash) {
    const welcome = welcomes[Math.floor(Math.random() * welcomes.length)];
    return c.html(eta.render('./signin', { welcome, error: 'Invalid email or password' }));
  }
  setCookie(c, 'session', email);
  return c.redirect('/profile');
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
