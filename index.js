const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');
const crypto = require('crypto');

const app = new Hono();
const eta = new Eta({ views: __dirname });
const users = [];

app.use(secureHeaders());

const welcomeMessages = ['Welcome', 'Hello again', 'Good to see you', 'Welcome back', 'Hey there'];

app.get('/', (c) => {
  const welcome = welcomeMessages[Math.floor(Math.random() * welcomeMessages.length)];
  return c.html(eta.render('signin', { welcome }));
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
