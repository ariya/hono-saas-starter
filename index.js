const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');
const path = require('path');

const app = new Hono();
const eta = new Eta({ views: path.join(__dirname) });

app.use(secureHeaders());

const welcomeTitles = ['Welcome back!', 'Good to see you!', 'Hello again!', 'Welcome!', "Glad you're here!"];

app.get('/', async (c) => {
  const title = welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)];
  const html = await eta.renderAsync('signin', { title, error: null });
  return c.html(html);
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
