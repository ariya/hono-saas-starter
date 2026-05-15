const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');

const eta = new Eta({ views: __dirname });
const app = new Hono();

app.use(secureHeaders());

app.get('/', (c) => c.html(eta.render('sign-in.eta')));

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
