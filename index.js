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

const secretKey = process.env.HMAC_SECRET || crypto.randomBytes(32).toString('hex');

const signSession = (email) => {
  const sig = crypto.createHmac('sha256', secretKey).update(email).digest('hex');
  return `${email}:${sig}`;
};

const verifySession = (cookieValue) => {
  if (!cookieValue) return null;
  const parts = cookieValue.split(':');
  if (parts.length !== 2) return null;
  const [email, sig] = parts;
  const expectedSig = crypto.createHmac('sha256', secretKey).update(email).digest('hex');
  if (sig !== expectedSig) return null;
  return email;
};

const generateCsrf = (c) => {
  let csrfSecret = getCookie(c, '_csrf');
  if (!csrfSecret) {
    csrfSecret = crypto.randomBytes(16).toString('hex');
    setCookie(c, '_csrf', csrfSecret, {
      path: '/',
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'Lax'
    });
  }
  const sig = crypto.createHmac('sha256', secretKey).update(csrfSecret).digest('hex');
  return `${csrfSecret}:${sig}`;
};

const verifyCsrf = async (c) => {
  const body = await c.req.parseBody();
  const token = body._csrf;
  if (!token) return false;
  const parts = token.split(':');
  if (parts.length !== 2) return false;
  const [csrfSecret, sig] = parts;
  const cookieSecret = getCookie(c, '_csrf');
  if (!cookieSecret || cookieSecret !== csrfSecret) return false;
  const expectedSig = crypto.createHmac('sha256', secretKey).update(csrfSecret).digest('hex');
  return sig === expectedSig;
};

const welcomes = [
  'Welcome back!',
  'Glad to see you again!',
  'Hello! Please sign in',
  'Welcome to Hono SaaS Starter!',
  'Ready to get started? Log in'
];

app.get('/', (c) => {
  const welcome = welcomes[Math.floor(Math.random() * welcomes.length)];
  const csrfToken = generateCsrf(c);
  return c.html(eta.render('./signin', { welcome, csrfToken }));
});

app.post('/signin', async (c) => {
  if (!(await verifyCsrf(c))) {
    const welcome = welcomes[Math.floor(Math.random() * welcomes.length)];
    const csrfToken = generateCsrf(c);
    return c.html(eta.render('./signin', { welcome, csrfToken, error: 'Invalid or missing CSRF token' }));
  }
  const body = await c.req.parseBody();
  const email = body.email;
  const password = body.password;
  const user = users.get(email);
  if (!user) {
    const welcome = welcomes[Math.floor(Math.random() * welcomes.length)];
    const csrfToken = generateCsrf(c);
    return c.html(eta.render('./signin', { welcome, csrfToken, error: 'Invalid email or password' }));
  }
  const hash = crypto.scryptSync(password, user.salt, 64).toString('hex');
  if (hash !== user.passwordHash) {
    const welcome = welcomes[Math.floor(Math.random() * welcomes.length)];
    const csrfToken = generateCsrf(c);
    return c.html(eta.render('./signin', { welcome, csrfToken, error: 'Invalid email or password' }));
  }
  setCookie(c, 'session', signSession(email), {
    path: '/',
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 25200
  });
  return c.redirect('/profile');
});

app.get('/profile', (c) => {
  const session = getCookie(c, 'session');
  const email = verifySession(session);
  if (!email) {
    return c.redirect('/');
  }
  return c.html(eta.render('./profile', { email }));
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
