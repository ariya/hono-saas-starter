const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');
const path = require('node:path');

const eta = new Eta({ views: path.join(__dirname, 'views'), cache: false });

const WELCOME_TITLES = ['Welcome back', 'Hello again', 'Good to see you', 'We missed you', 'Glad you are here'];

const app = new Hono();

app.use(secureHeaders());

app.get('/', (c) => {
  const welcome = WELCOME_TITLES[Math.floor(Math.random() * WELCOME_TITLES.length)];
  return c.html(eta.render('signin', { welcome }));
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
