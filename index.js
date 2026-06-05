const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');
const path = require('path');
const crypto = require('crypto');

const eta = new Eta({ views: path.join(__dirname, 'views') });

const WELCOME_TITLES = ['Welcome back', 'Good to see you again', 'Hello there', 'Welcome', 'Hey, welcome'];

const HMAC_SECRET = process.env.HMAC_SECRET || crypto.randomBytes(32).toString('hex');
const IS_PROD = process.env.NODE_ENV === 'production';
const SESSION_MAX_AGE = 7 * 60 * 60;
const SCRYPT_KEYLEN = 64;
const SCRYPT_COST = { N: 16384, r: 8, p: 1 };

const users = new Map();

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, SCRYPT_KEYLEN, SCRYPT_COST).toString('hex');
}

function signSession(email) {
  const payload = `${email}.${Date.now()}`;
  const sig = crypto.createHmac('sha256', HMAC_SECRET).update(payload).digest('hex');
  return `${payload}.${sig}`;
}

function verifySession(token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [email, ts, sig] = parts;
  const payload = `${email}.${ts}`;
  const expected = crypto.createHmac('sha256', HMAC_SECRET).update(payload).digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'))) return null;
  if (Date.now() - Number(ts) > SESSION_MAX_AGE * 1000) return null;
  return email;
}

function sessionCookie(token) {
  const parts = [`session=${token}`, 'Path=/', `Max-Age=${SESSION_MAX_AGE}`, 'HttpOnly', 'SameSite=Lax'];
  if (IS_PROD) parts.push('Secure');
  return parts.join('; ');
}

const app = new Hono();

app.use(secureHeaders());

app.get('/', (c) => {
  const title = WELCOME_TITLES[Math.floor(Math.random() * WELCOME_TITLES.length)];
  return c.html(eta.render('sign-in', { title, error: null }));
});

app.post('/', async (c) => {
  const body = await c.req.parseBody();
  const email = (body.email || '').trim().toLowerCase();
  const password = body.password || '';
  const title = WELCOME_TITLES[Math.floor(Math.random() * WELCOME_TITLES.length)];

  const user = users.get(email);
  if (!user || hashPassword(password, user.salt) !== user.hash) {
    return c.html(eta.render('sign-in', { title, error: 'Invalid email or password' }));
  }

  const token = signSession(email);
  c.header('Set-Cookie', sessionCookie(token));
  return c.redirect('/profile');
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
