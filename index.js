const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');
const path = require('path');

const eta = new Eta({ views: path.join(__dirname, 'views') });

const app = new Hono();

app.use(secureHeaders());

app.get('/', (c) => c.html(eta.render('sign-in')));

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
