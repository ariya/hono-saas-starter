const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');
const crypto = require('crypto');

const eta = new Eta({ views: __dirname });
const app = new Hono();

app.use(secureHeaders());

const users = new Map();
const sessions = new Map();

const welcomeTitles = ['Welcome', 'Hello There', 'Good to See You', 'Sign In Below', 'Access Your Account'];

function verifyPassword(password, salt, hash) {
  return new Promise((resolve) => {
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) return resolve(false);
      resolve(crypto.timingSafeEqual(derivedKey, Buffer.from(hash, 'hex')));
    });
  });
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
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, body.email);
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
