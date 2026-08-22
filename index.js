const path = require('node:path');
const crypto = require('node:crypto');
const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');

const eta = new Eta({ views: path.join(__dirname, 'views') });

const welcomeTitles = ['Welcome', 'Welcome back', 'Hello there', 'Good to see you', 'Nice to meet you'];

const welcomeTitle = () => welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)];

const users = new Map();

const SESSION_COOKIE = 'session';
const SESSION_MAX_AGE = 25200;
const isLocalDevelopment = process.env.NODE_ENV === 'development';
const hmacSecret = process.env.HMAC_SECRET || (isLocalDevelopment ? crypto.randomBytes(32).toString('hex') : null);

if (!hmacSecret) {
  console.error('HMAC_SECRET environment variable is required');
  process.exit(1);
}

const signSession = (email) => {
  const expiresAt = Date.now() + SESSION_MAX_AGE * 1000;
  const payload = `${Buffer.from(email).toString('base64url')}.${expiresAt}`;
  const signature = crypto.createHmac('sha256', hmacSecret).update(payload).digest('base64url');
  return `${payload}.${signature}`;
};

const verifySession = (cookieValue) => {
  if (!cookieValue) return null;
  const [emailEncoded, expiresAt, signature] = cookieValue.split('.');
  if (!emailEncoded || !expiresAt || !signature) return null;
  const payload = `${emailEncoded}.${expiresAt}`;
  const expected = crypto.createHmac('sha256', hmacSecret).update(payload).digest('base64url');
  const given = Buffer.from(signature);
  const known = Buffer.from(expected);
  if (given.length !== known.length || !crypto.timingSafeEqual(given, known)) return null;
  if (!/^\d+$/.test(expiresAt) || Date.now() > Number(expiresAt)) return null;
  return Buffer.from(emailEncoded, 'base64url').toString('utf8');
};

const sessionCookie = (value) =>
  `${SESSION_COOKIE}=${encodeURIComponent(value)}; Path=/; HttpOnly;${
    isLocalDevelopment ? '' : ' Secure;'
  } Max-Age=${SESSION_MAX_AGE}`;

const hashPassword = (password, salt) =>
  new Promise((resolve, reject) =>
    crypto.scrypt(password, salt, 64, (err, derivedKey) => (err ? reject(err) : resolve(derivedKey.toString('hex'))))
  );

const signCsrfToken = () => {
  const payload = `${crypto.randomBytes(16).toString('base64url')}.${Date.now()}`;
  const signature = crypto.createHmac('sha256', hmacSecret).update(`csrf:${payload}`).digest('base64url');
  return `${payload}.${signature}`;
};

const verifyCsrfToken = (token) => {
  if (typeof token !== 'string') return false;
  const [nonce, issuedAt, signature] = token.split('.');
  if (!nonce || !issuedAt || !signature || !/^\d+$/.test(issuedAt)) return false;
  const payload = `${nonce}.${issuedAt}`;
  const expected = crypto.createHmac('sha256', hmacSecret).update(`csrf:${payload}`).digest('base64url');
  const given = Buffer.from(signature);
  const known = Buffer.from(expected);
  if (given.length !== known.length || !crypto.timingSafeEqual(given, known)) return false;
  return Date.now() - Number(issuedAt) <= SESSION_MAX_AGE * 1000;
};

const saveUser = async (email, password) => {
  const salt = crypto.randomBytes(16).toString('hex');
  const passwordHash = await hashPassword(password, salt);
  users.set(email, { email, passwordHash, salt });
};

const verifyCredentials = async (email, password) => {
  const user = users.get(email);
  if (!user) return false;
  const passwordHash = await hashPassword(password, user.salt);
  return (
    Buffer.byteLength(passwordHash) === Buffer.byteLength(user.passwordHash) &&
    crypto.timingSafeEqual(Buffer.from(passwordHash), Buffer.from(user.passwordHash))
  );
};

const app = new Hono();

app.use(secureHeaders());

app.get('/', (c) =>
  c.html(
    eta.render('signin', {
      welcome: welcomeTitle(),
      csrfToken: signCsrfToken()
    })
  )
);

app.post('/', async (c) => {
  const body = await c.req.parseBody();
  const email = String(body.email || '')
    .trim()
    .toLowerCase();
  const password = String(body.password || '');
  const csrfFailure = () =>
    c.html(
      eta.render('signin', {
        welcome: welcomeTitle(),
        email,
        csrfToken: signCsrfToken(),
        error: 'Your request could not be verified. Please try again.'
      }),
      403
    );
  if (!verifyCsrfToken(body.csrf)) return csrfFailure();
  if (email && password && (await verifyCredentials(email, password))) {
    c.header('Set-Cookie', sessionCookie(signSession(email)));
    return c.redirect('/profile');
  }
  return c.html(
    eta.render('signin', {
      welcome: welcomeTitle(),
      email,
      csrfToken: signCsrfToken(),
      error: 'Invalid email or password.'
    }),
    401
  );
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
