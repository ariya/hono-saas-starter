const crypto = require('node:crypto');
const path = require('node:path');
const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { setCookie } = require('hono/cookie');
const { Eta } = require('eta');

const app = new Hono();
const eta = new Eta({ views: path.join(__dirname, 'views') });
const isProduction = process.env.NODE_ENV === 'production';
const sessionSecret = process.env.HMAC_SECRET || crypto.randomBytes(32).toString('hex');
const SESSION_MAX_AGE = 7 * 60 * 60;

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

function encodeSession(email) {
  const payload = Buffer.from(JSON.stringify({ email, exp: Date.now() + SESSION_MAX_AGE * 1000 })).toString(
    'base64url'
  );
  const signature = crypto.createHmac('sha256', sessionSecret).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

function decodeSession(token) {
  if (!token) return null;
  const [payload, signature] = String(token).split('.');
  if (!payload || !signature) return null;
  const expected = crypto.createHmac('sha256', sessionSecret).update(payload).digest('base64url');
  const signatureBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expected);
  if (signatureBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(signatureBuffer, expectedBuffer)) {
    return null;
  }
  let data;
  try {
    data = JSON.parse(Buffer.from(payload, 'base64url').toString());
  } catch {
    return null;
  }
  if (!data || typeof data.email !== 'string' || typeof data.exp !== 'number' || data.exp < Date.now()) {
    return null;
  }
  return getUser(data.email) ? data.email : null;
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
  setCookie(c, 'session', encodeSession(user.email), {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'Lax',
    path: '/',
    maxAge: SESSION_MAX_AGE
  });
  return c.redirect('/profile');
});

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
