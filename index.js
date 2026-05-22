const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');
const path = require('path');

const app = new Hono();

const eta = new Eta({ views: path.join(__dirname, 'templates') });

app.use(secureHeaders());

const welcomes = [
  'Welcome back!',
  'Glad to see you again!',
  'Hello! Please sign in',
  'Welcome to Hono SaaS Starter!',
  'Ready to get started? Log in'
];

app.get('/', (c) => {
  const welcome = welcomes[Math.floor(Math.random() * welcomes.length)];
  return c.html(eta.render('./signin', { welcome }));
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
