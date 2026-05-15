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
  if (!user) return c.text('Invalid credentials', 401);
  const valid = await verifyPassword(body.password, user.salt, user.hash);
  if (!valid) return c.text('Invalid credentials', 401);
  return c.text('Authenticated');
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
