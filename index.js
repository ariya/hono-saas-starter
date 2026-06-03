const path = require('path');
const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');

const eta = new Eta({ views: path.join(__dirname, 'views'), cache: true });

const users = new Map();

const app = new Hono();

app.use(secureHeaders());

const WELCOME_TITLES = ['Welcome', 'Welcome back', 'Hello again', 'Good to see you', 'Sign in to continue'];

const pickWelcomeTitle = () => WELCOME_TITLES[Math.floor(Math.random() * WELCOME_TITLES.length)];

app.get('/', (c) => {
  return c.html(eta.render('signin', { title: pickWelcomeTitle() }));
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
