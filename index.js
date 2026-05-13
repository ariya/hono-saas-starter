const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');
const path = require('path');
const crypto = require('crypto');

const app = new Hono();
const eta = new Eta({ views: path.join(__dirname) });
const isProduction = process.env.NODE_ENV === 'production';

app.use(secureHeaders());

const users = new Map();

async function hashPassword(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, key) => (err ? reject(err) : resolve(key.toString('hex'))));
  });
}

async function verifyPassword(password, hash, salt) {
  const derived = await hashPassword(password, salt);
  return crypto.timingSafeEqual(Buffer.from(derived), Buffer.from(hash));
}

function signSession(email) {
  const hmac = crypto.createHmac('sha256', process.env.HMAC_SECRET || 'dev-secret');
  hmac.update(email);
  return `${email}.${hmac.digest('hex')}`;
}

function verifySession(token) {
  const dot = token.lastIndexOf('.');
  if (dot === -1) return null;
  const email = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const hmac = crypto.createHmac('sha256', process.env.HMAC_SECRET || 'dev-secret');
  hmac.update(email);
  const expected = hmac.digest('hex');
  const match = crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'));
  return match ? email : null;
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
  const secureFlag = isProduction ? '; Secure' : '';
  const token = signSession(email);
  c.header(
    'Set-Cookie',
    `session=${encodeURIComponent(token)}; Path=/; HttpOnly${secureFlag}; Max-Age=${maxAge}; SameSite=Lax`
  );
  return c.redirect('/profile');
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
