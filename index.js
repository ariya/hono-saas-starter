const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');

const app = new Hono();
const eta = new Eta({ views: __dirname });

app.use(secureHeaders());

app.get('/', (c) => c.html(eta.render('signin', { welcome: 'Welcome' })));

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
