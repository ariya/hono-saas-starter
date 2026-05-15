const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');
const crypto = require('crypto');

const eta = new Eta({ views: __dirname });
const app = new Hono();

app.use(secureHeaders());

const users = new Map();

const dummySalt = crypto.randomBytes(16).toString('hex');
const dummyHash = crypto.randomBytes(64).toString('hex');

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

function generateCsrfToken() {
  const nonce = crypto.randomBytes(16).toString('hex');
  const signature = crypto.createHmac('sha256', hmacSecret).update(nonce).digest('hex');
  return `${nonce}.${signature}`;
}

function verifyCsrfToken(token) {
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [nonce, signature] = parts;
  const expected = crypto.createHmac('sha256', hmacSecret).update(nonce).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
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

app.get('/', (c) => {
  const email = getSessionEmail(c);
  if (email) return c.redirect('/profile');
  return c.html(
    eta.render('sign-in.eta', {
      title: welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)],
      csrf: generateCsrfToken()
    })
  );
});

app.post('/', async (c) => {
  const body = await c.req.parseBody();
  if (!verifyCsrfToken(body.csrf)) {
    return c.html(eta.render('sign-in.eta', { title: welcomeTitles[0], error: 'Invalid request' }), 403);
  }
  const user = users.get(body.email);
  const salt = user ? user.salt : dummySalt;
  const hash = user ? user.hash : dummyHash;
  const valid = await verifyPassword(body.password, salt, hash);
  if (!user || !valid) {
    return c.html(eta.render('sign-in.eta', { title: welcomeTitles[0], error: 'Invalid credentials' }), 401);
  }
  const token = signSession(body.email);
  const expires = new Date(Date.now() + 7 * 60 * 60 * 1000).toUTCString();
  const secureFlag = process.env.NODE_ENV === 'production' ? 'Secure' : '';
  c.header(
    'Set-Cookie',
    `session=${token}; HttpOnly; Path=/; SameSite=Strict; Expires=${expires}${secureFlag ? `; ${secureFlag}` : ''}`
  );
  return c.redirect('/profile');
});

function getSessionEmail(c) {
  const cookie = c.req.header('Cookie') || '';
  const match = cookie.match(/session=([^;]+)/);
  if (!match) return null;
  return verifySession(match[1]);
}

app.post('/register', async (c) => {
  const body = await c.req.parseBody();
  if (!verifyCsrfToken(body.csrf)) {
    return c.html(eta.render('register.eta', { csrf: generateCsrfToken(), error: 'Invalid request' }), 403);
  }
  if (!body.password || body.password.length < 8) {
    return c.html(
      eta.render('register.eta', { csrf: generateCsrfToken(), error: 'Password must be at least 8 characters' }),
      400
    );
  }
  if (users.has(body.email)) {
    return c.html(eta.render('register.eta', { csrf: generateCsrfToken(), error: 'Email already registered' }), 409);
  }
  const hashed = await hashPassword(body.password);
  if (!hashed) {
    return c.html(eta.render('register.eta', { csrf: generateCsrfToken(), error: 'Registration failed' }), 500);
  }
  users.set(body.email, { email: body.email, salt: hashed.salt, hash: hashed.hash });
  return c.html(
    `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="2;url=/"><title>Registered</title></head><body><p>Registration successful. Redirecting...</p></body></html>`
  );
});

app.get('/register', (c) => {
  const email = getSessionEmail(c);
  if (email) return c.redirect('/profile');
  return c.html(
    eta.render('register.eta', {
      csrf: generateCsrfToken()
    })
  );
});

app.get('/profile', (c) => {
  const email = getSessionEmail(c);
  if (!email) return c.redirect('/');
  return c.html(eta.render('profile.eta', { email }));
});

app.post('/signout', (c) => {
  const secureFlag = process.env.NODE_ENV === 'production' ? 'Secure' : '';
  c.header(
    'Set-Cookie',
    `session=; HttpOnly; Path=/; SameSite=Strict; Expires=Thu, 01 Jan 1970 00:00:00 GMT${secureFlag ? `; ${secureFlag}` : ''}`
  );
  return c.redirect('/');
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
