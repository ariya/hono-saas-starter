const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { setCookie } = require('hono/cookie');
const { secureHeaders } = require('hono/secure-headers');
const { Eta } = require('eta');
const path = require('path');

const app = new Hono();
const eta = new Eta({ views: path.join(__dirname) });
const users = new Map();
const sessionMaxAge = 7 * 60 * 60;
const secureCookies = process.env.NODE_ENV !== 'development';
const welcomeTitles = ['Welcome', 'Welcome back', 'Sign in to continue', 'Good to see you', 'Access your account'];

const saveUser = ({ email, passwordHash, salt }) => {
  users.set(email.toLowerCase(), { email, passwordHash, salt });
};

const findUser = (email) => users.get(email.toLowerCase());

const verifyPassword = (password, user) => user.passwordHash === password;

const createSessionValue = (user) => Buffer.from(user.email).toString('base64url');

app.use(secureHeaders());

const render = (template, data = {}) => eta.render(template, data);

const randomWelcomeTitle = () => welcomeTitles[Math.floor(Math.random() * welcomeTitles.length)];

const renderSignIn = (data = {}) =>
  render('sign-in.eta', { title: randomWelcomeTitle(), error: '', email: '', ...data });

app.get('/', (c) => c.html(renderSignIn()));

app.post('/signin', async (c) => {
  const body = await c.req.parseBody();
  const email = String(body.email || '');
  const password = String(body.password || '');
  const user = findUser(email);

  if (!user || !verifyPassword(password, user)) {
    return c.html(renderSignIn({ error: 'Invalid email or password.', email }), 401);
  }

  setCookie(c, 'session', createSessionValue(user), {
    httpOnly: true,
    maxAge: sessionMaxAge,
    path: '/',
    sameSite: 'Lax',
    secure: secureCookies
  });
  return c.redirect('/profile');
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
