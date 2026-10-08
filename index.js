const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');
const path = require('node:path');

const app = new Hono();
const eta = new Eta({ views: path.join(__dirname, 'views') });
const users = new Map();

app.use(secureHeaders());

const welcomeTitles = ['Welcome', 'Welcome back', 'Hello there', 'Good to see you', 'Nice to have you here'];

app.get('/', (c) => {
  const welcome = welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)];
  return c.html(eta.render('signin', { title: 'Sign In', welcome }));
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
