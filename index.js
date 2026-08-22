const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');
const { randomInt, scryptSync, timingSafeEqual } = require('crypto');

const eta = new Eta({ views: 'views' });

const welcomeTitles = ['Welcome back', 'Hello again', 'Good to see you', 'Hey there', 'Greetings'];

const users = new Map();

const isProd = process.env.NODE_ENV === 'production';

function hashPassword(password, salt) {
  return scryptSync(password, salt, 64).toString('hex');
}

function verifyUser(email, password) {
  const user = users.get(
    String(email || '')
      .trim()
      .toLowerCase()
  );
  if (!user) return null;
  const candidate = Buffer.from(hashPassword(password, user.salt), 'hex');
  const stored = Buffer.from(user.hash, 'hex');
  return candidate.length === stored.length && timingSafeEqual(candidate, stored) ? user : null;
}

const app = new Hono();

app.use(secureHeaders());

app.get('/', (c) => {
  const title = welcomeTitles[randomInt(welcomeTitles.length)];
  return c.html(eta.render('signin', { title, error: null }));
});

app.post('/signin', async (c) => {
  const body = await c.req.parseBody();
  const user = verifyUser(body.email, body.password || '');
  if (!user) {
    const title = welcomeTitles[randomInt(welcomeTitles.length)];
    return c.html(eta.render('signin', { title, error: 'Invalid email or password.' }), 401);
  }
  c.cookie('session', user.email, {
    httpOnly: true,
    path: '/',
    secure: isProd,
    maxAge: 7 * 60 * 60
  });
  return c.redirect('/profile');
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
