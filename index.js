const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');

const eta = new Eta({ views: __dirname });
const app = new Hono();

app.use(secureHeaders());

const welcomeTitles = ['Welcome', 'Hello There', 'Good to See You', 'Sign In Below', 'Access Your Account'];

app.get('/', (c) =>
  c.html(eta.render('sign-in.eta', { title: welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)] }))
);

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
