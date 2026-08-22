const path = require('node:path');
const crypto = require('node:crypto');
const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');

const eta = new Eta({ views: path.join(__dirname, 'views') });

const welcomeTitles = ['Welcome', 'Welcome back', 'Hello there', 'Good to see you', 'Nice to meet you'];

const welcomeTitle = () => welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)];

const app = new Hono();

app.use(secureHeaders());

app.get('/', (c) => c.html(eta.render('signin', { welcome: welcomeTitle() })));

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
