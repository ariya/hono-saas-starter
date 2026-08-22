const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');
const { randomInt } = require('crypto');

const eta = new Eta({ views: 'views' });

const welcomeTitles = ['Welcome back', 'Hello again', 'Good to see you', 'Hey there', 'Greetings'];

const users = new Map();

const app = new Hono();

app.use(secureHeaders());

app.get('/', (c) => {
  const title = welcomeTitles[randomInt(welcomeTitles.length)];
  return c.html(eta.render('signin', { title }));
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
