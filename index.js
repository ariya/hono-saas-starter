const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');

const app = new Hono();

app.use(secureHeaders());

const signInPage = () => `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Sign in</title>
    <link rel="stylesheet" href="https://unpkg.com/@knadh/oat/oat.min.css" />
  </head>
  <body>
    <main class="container">
      <article class="card">
        <header>
          <h1>Welcome</h1>
          <p>Sign in to continue.</p>
        </header>
        <form method="post" action="/">
          <label data-field>
            Email
            <input type="email" name="email" autocomplete="email" required />
          </label>
          <label data-field>
            Password
            <input type="password" name="password" autocomplete="current-password" required />
          </label>
          <button type="submit">Sign in</button>
        </form>
      </article>
    </main>
    <script src="https://unpkg.com/@knadh/oat/oat.min.js" defer></script>
  </body>
</html>
`;

app.get('/', (c) => c.html(signInPage()));

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
