const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');

const app = new Hono();
const eta = new Eta({ views: __dirname });

app.use(secureHeaders());

const welcomeTitles = ['Welcome', 'Welcome back', 'Good to see you', 'Hello again', 'Great to have you here'];

const pickWelcomeTitle = () => welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)];

app.get('/', (c) => c.html(eta.render('signin', { title: pickWelcomeTitle() })));

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
