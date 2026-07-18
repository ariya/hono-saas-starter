const path = require('path');
const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');

const app = new Hono();
const eta = new Eta({ views: path.join(__dirname, 'views') });

app.use(secureHeaders());

const welcomeTitles = ['Welcome', 'Welcome back', 'Hello', 'Hello again', 'Greetings'];

app.get('/', (c) => {
  const title = welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)];
  return c.html(eta.render('signin', { title }));
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
