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
  const sigBuffer = Buffer.from(sig, 'hex');
  const expectedSigBuffer = Buffer.from(expectedSig, 'hex');
  if (sigBuffer.length !== expectedSigBuffer.length) return null;
  if (!crypto.timingSafeEqual(sigBuffer, expectedSigBuffer)) return null;
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
  const sigBuffer = Buffer.from(sig, 'hex');
  const expectedSigBuffer = Buffer.from(expectedSig, 'hex');
  if (sigBuffer.length !== expectedSigBuffer.length) return false;
  return crypto.timingSafeEqual(sigBuffer, expectedSigBuffer);
};

const welcomes = [
  'Welcome back!',
  'Glad to see you again!',
  'Hello! Please sign in',
  'Welcome to Hono SaaS Starter!',
  'Ready to get started? Log in'
];

app.get('/', (c) => {
  const session = getCookie(c, 'session');
  const email = verifySession(session);
  if (email) {
    return c.redirect('/profile');
  }
  const welcome = welcomes[Math.floor(Math.random() * welcomes.length)];
  const csrfToken = generateCsrf(c);
  const success = c.req.query('success');
  return c.html(eta.render('./signin', { welcome, csrfToken, success }));
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

app.get('/register', (c) => {
  const session = getCookie(c, 'session');
  const email = verifySession(session);
  if (email) {
    return c.redirect('/profile');
  }
  const csrfToken = generateCsrf(c);
  return c.html(eta.render('./register', { csrfToken }));
});

app.post('/register', async (c) => {
  if (!(await verifyCsrf(c))) {
    const csrfToken = generateCsrf(c);
    return c.html(eta.render('./register', { csrfToken, error: 'Invalid or missing CSRF token' }));
  }
  const body = await c.req.parseBody();
  const email = body.email;
  const password = body.password;
  if (!email || !password || password.length < 8) {
    const csrfToken = generateCsrf(c);
    return c.html(eta.render('./register', { csrfToken, error: 'Password must be at least 8 characters long' }));
  }
  if (users.has(email)) {
    const csrfToken = generateCsrf(c);
    return c.html(eta.render('./register', { csrfToken, error: 'User already exists' }));
  }
  const salt = crypto.randomBytes(16).toString('hex');
  const passwordHash = crypto.scryptSync(password, salt, 64).toString('hex');
  users.set(email, { email, passwordHash, salt });
  return c.redirect('/?success=Registration+successful.+Please+sign+in.');
});

app.get('/profile', (c) => {
  const session = getCookie(c, 'session');
  const email = verifySession(session);
  if (!email) {
    return c.redirect('/');
  }
  const csrfToken = generateCsrf(c);
  return c.html(eta.render('./profile', { email, csrfToken }));
});

app.post('/signout', async (c) => {
  if (!(await verifyCsrf(c))) {
    return c.redirect('/profile');
  }
  setCookie(c, 'session', '', {
    path: '/',
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 0
  });
  return c.redirect('/?success=You+have+been+signed+out.');
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
