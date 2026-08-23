const path = require('node:path');
const { randomBytes, scryptSync } = require('node:crypto');
const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');

const app = new Hono();
const eta = new Eta({ views: path.join(__dirname, 'views') });

const users = new Map();

const hashPassword = (password, salt) => scryptSync(password, salt, 64).toString('hex');

const createUser = (email, password) => {
  const normalized = String(email).trim().toLowerCase();
  const salt = randomBytes(16).toString('hex');
  const user = { email: normalized, salt, hash: hashPassword(password, salt) };
  users.set(normalized, user);
  return user;
};

const findUser = (email) => users.get(String(email).trim().toLowerCase());

if (process.env.DEMO_EMAIL && process.env.DEMO_PASSWORD) {
  createUser(process.env.DEMO_EMAIL, process.env.DEMO_PASSWORD);
}

const greetings = ['Welcome', 'Welcome back', 'Good to see you', 'Hello again', 'Nice to have you back'];

const randomGreeting = () => greetings[Math.floor(Math.random() * greetings.length)];

app.use(secureHeaders());

app.get('/', (c) => c.html(eta.render('signin', { heading: randomGreeting() })));

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
