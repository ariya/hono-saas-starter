const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');
const path = require('path');

const eta = new Eta({ views: path.join(__dirname, 'views') });

const WELCOME_TITLES = ['Welcome back', 'Good to see you again', 'Hello there', 'Welcome', 'Hey, welcome'];

const app = new Hono();

app.use(secureHeaders());

app.get('/', (c) => {
  const title = WELCOME_TITLES[Math.floor(Math.random() * WELCOME_TITLES.length)];
  return c.html(eta.render('sign-in', { title }));
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
