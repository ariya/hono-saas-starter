const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');
const crypto = require('crypto');

const eta = new Eta({ views: __dirname });
const app = new Hono();

app.use(secureHeaders());

const users = new Map();

const welcomeTitles = ['Welcome', 'Hello There', 'Good to See You', 'Sign In Below', 'Access Your Account'];

function hashPassword(password) {
  return new Promise((resolve) => {
    const salt = crypto.randomBytes(16).toString('hex');
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) return resolve(null);
      resolve({ salt, hash: derivedKey.toString('hex') });
    });
  });
}

function verifyPassword(password, salt, hash) {
  return new Promise((resolve) => {
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) return resolve(false);
      resolve(crypto.timingSafeEqual(derivedKey, Buffer.from(hash, 'hex')));
    });
  });
}

const hmacSecret = process.env.HMAC_SECRET;
if (!hmacSecret) {
  throw new Error('HMAC_SECRET environment variable is required');
}

function signSession(email) {
  const exp = Date.now() + 7 * 60 * 60 * 1000;
  const payload = Buffer.from(JSON.stringify({ email, exp })).toString('base64url');
  const signature = crypto.createHmac('sha256', hmacSecret).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

function verifySession(token) {
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payload, signature] = parts;
  const expected = crypto.createHmac('sha256', hmacSecret).update(payload).digest('base64url');
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (Date.now() > data.exp) return null;
    return data.email;
  } catch {
    return null;
  }
}

app.get('/', (c) =>
  c.html(eta.render('sign-in.eta', { title: welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)] }))
);

app.post('/', async (c) => {
  const body = await c.req.parseBody();
  const user = users.get(body.email);
  if (!user) {
    return c.html(eta.render('sign-in.eta', { title: welcomeTitles[0], error: 'Invalid credentials' }), 401);
  }
  const valid = await verifyPassword(body.password, user.salt, user.hash);
  if (!valid) {
    return c.html(eta.render('sign-in.eta', { title: welcomeTitles[0], error: 'Invalid credentials' }), 401);
  }
  const token = signSession(body.email);
  const expires = new Date(Date.now() + 7 * 60 * 60 * 1000).toUTCString();
  const secureFlag = process.env.NODE_ENV === 'production' ? 'Secure' : '';
  c.header(
    'Set-Cookie',
    `session=${token}; HttpOnly; Path=/; Expires=${expires}${secureFlag ? `; ${secureFlag}` : ''}`
  );
  return c.redirect('/profile');
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
