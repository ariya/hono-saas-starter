const path = require('node:path');
const crypto = require('node:crypto');
const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');

const app = new Hono();
const eta = new Eta({ views: path.join(__dirname, 'views') });

const users = new Map();

const hashPassword = (password, salt) =>
  crypto
    .createHash('sha256')
    .update(salt + password)
    .digest('hex');

const createUser = (email, password) => {
  const normalized = email.trim().toLowerCase();
  const salt = crypto.randomBytes(16).toString('hex');
  const passwordHash = hashPassword(password, salt);
  users.set(normalized, { email: normalized, passwordHash, salt });
  return users.get(normalized);
};

createUser('demo@example.com', 'password123');

app.use(secureHeaders());

const welcomeTitles = ['Welcome', 'Welcome back', 'Hello again', 'Good to see you', 'Sign in to continue'];
const pickWelcome = () => welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)];

app.get('/', (c) => c.html(eta.render('signin', { title: 'Sign In', heading: pickWelcome() })));

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
