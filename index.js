const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');

const app = new Hono();

app.use(secureHeaders());

app.get('/', (c) =>
  c.html(`<!doctype html>
<html lang="en">
  <head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@oat-css/oat@latest/oat.min.css">
    <title>Sign In</title>
  </head>
  <body>
    <main class="container">
      <form method="post" action="/signin">
        <h1>Sign In</h1>
        <label>
          Email
          <input type="email" name="email" autocomplete="email" required>
        </label>
        <label>
          Password
          <input type="password" name="password" autocomplete="current-password" required>
        </label>
        <button type="submit">Sign In</button>
      </form>
    </main>
  </body>
</html>`)
);

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
