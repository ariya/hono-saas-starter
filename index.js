const path = require('node:path');
const crypto = require('node:crypto');
const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { setCookie, getCookie, deleteCookie } = require('hono/cookie');
const { Eta } = require('eta');

const app = new Hono();
const eta = new Eta({ views: path.join(__dirname, 'views') });
const isProduction = process.env.NODE_ENV === 'production';

const users = new Map();
const sessionMaxAge = 7 * 60 * 60;
const hmacSecret = process.env.HMAC_SECRET || (isProduction ? null : crypto.randomBytes(32).toString('hex'));
if (!hmacSecret) {
  throw new Error('HMAC_SECRET environment variable is required');
}

const hashPassword = (password, salt) => crypto.scryptSync(password, salt, 64).toString('hex');

const verifyPassword = (password, user) => {
  const expected = Buffer.from(user.passwordHash, 'hex');
  const actual = Buffer.from(hashPassword(password, user.salt), 'hex');
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
};

const signValue = (value) => crypto.createHmac('sha256', hmacSecret).update(value).digest('hex');

const createSessionToken = (email) => {
  const payload = `${email}:${Date.now() + sessionMaxAge * 1000}`;
  return `${Buffer.from(payload).toString('base64url')}.${signValue(payload)}`;
};

const verifySessionToken = (token) => {
  if (!token) return null;
  const [encoded, signature] = token.split('.');
  if (!encoded || !signature) return null;
  const payload = Buffer.from(encoded, 'base64url').toString();
  const expected = signValue(payload);
  if (signature.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
    return null;
  }
  const [email, expiry] = payload.split(':');
  if (!email || !expiry || Number(expiry) < Date.now()) return null;
  return email;
};

const createUser = (email, password) => {
  const normalized = email.trim().toLowerCase();
  const salt = crypto.randomBytes(16).toString('hex');
  const passwordHash = hashPassword(password, salt);
  users.set(normalized, { email: normalized, passwordHash, salt });
  return users.get(normalized);
};

createUser('demo@example.com', 'password123');

app.use(secureHeaders());

const welcomeTitles = ['Welcome', 'Welcome back', 'Hello again', 'Good to see you', 'Sign in to continue'];
const pickWelcome = () => welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)];

app.get('/', (c) => c.html(eta.render('signin', { title: 'Sign In', heading: pickWelcome() })));

app.post('/signin', async (c) => {
  const body = await c.req.parseBody();
  const email = String(body.email || '')
    .trim()
    .toLowerCase();
  const password = String(body.password || '');
  const user = users.get(email);
  if (!user || !verifyPassword(password, user)) {
    return c.html(
      eta.render('signin', { title: 'Sign In', heading: pickWelcome(), error: 'Invalid email or password' }),
      401
    );
  }
  setCookie(c, 'session', createSessionToken(user.email), {
    path: '/',
    httpOnly: true,
    sameSite: 'Lax',
    secure: isProduction,
    maxAge: sessionMaxAge
  });
  return c.redirect('/profile');
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
