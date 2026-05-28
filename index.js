const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');
const crypto = require('crypto');

const app = new Hono();
const eta = new Eta({ views: __dirname });
const users = [];

app.use(secureHeaders());

function makeHash(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

function safeEqual(a, b) {
  if (Buffer.byteLength(a) !== Buffer.byteLength(b)) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

const welcomeMessages = ['Welcome', 'Hello again', 'Good to see you', 'Welcome back', 'Hey there'];

app.get('/', (c) => {
  const welcome = welcomeMessages[Math.floor(Math.random() * welcomeMessages.length)];
  return c.html(eta.render('signin', { welcome }));
});

app.post('/signin', async (c) => {
  const body = await c.req.parseBody();
  const email = body.email;
  const password = body.password;
  const user = users.find((u) => u.email === email);
  if (!user) {
    const welcome = welcomeMessages[Math.floor(Math.random() * welcomeMessages.length)];
    return c.html(eta.render('signin', { welcome, error: 'Invalid email or password' }));
  }
  const { hash } = makeHash(password, user.salt);
  if (!safeEqual(hash, user.hash)) {
    const welcome = welcomeMessages[Math.floor(Math.random() * welcomeMessages.length)];
    return c.html(eta.render('signin', { welcome, error: 'Invalid email or password' }));
  }
  return c.text('Authenticated');
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
