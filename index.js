const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');
const path = require('path');

const app = new Hono();
const eta = new Eta({ views: path.join(__dirname) });

app.use(secureHeaders());

const users = new Map();

async function verifyPassword(password, hash, salt) {
  const testHash = Buffer.from(password + salt).toString('base64');
  return testHash === hash;
}

const welcomeTitles = ['Welcome back!', 'Good to see you!', 'Hello again!', 'Welcome!', "Glad you're here!"];

app.get('/', async (c) => {
  const title = welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)];
  const html = await eta.renderAsync('signin', { title, error: null });
  return c.html(html);
});

app.post('/', async (c) => {
  const { email, password } = await c.req.parseBody();
  const user = users.get(email);
  const valid = user ? await verifyPassword(password, user.hash, user.salt) : false;
  if (!valid) {
    const title = welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)];
    const html = await eta.renderAsync('signin', { title, error: 'Invalid email or password.' });
    return c.html(html, 401);
  }
  const maxAge = 7 * 60 * 60;
  c.header('Set-Cookie', `session=${email}; Path=/; HttpOnly; Secure; Max-Age=${maxAge}; SameSite=Lax`);
  return c.redirect('/profile');
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
