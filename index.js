const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');
const path = require('path');

const app = new Hono();
const eta = new Eta({ views: path.join(__dirname) });

app.use(secureHeaders());

const render = (template, data = {}) => eta.render(template, data);

app.get('/', (c) => c.html(render('sign-in.eta')));

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
