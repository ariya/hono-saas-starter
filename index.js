const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');

const app = new Hono();

app.use(secureHeaders());

app.get('/', (c) => {
  return c.html(`<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Sign in</title>
    <link rel="stylesheet" href="https://unpkg.com/@knadh/oat/oat.min.css">
  </head>
  <body>
    <main>
      <h1>Welcome</h1>
      <form method="post" action="/signin">
        <p>
          <label for="email">Email</label>
          <input type="email" id="email" name="email" autocomplete="email" required>
        </p>
        <p>
          <label for="password">Password</label>
          <input type="password" id="password" name="password" autocomplete="current-password" required>
        </p>
        <button type="submit">Sign in</button>
      </form>
    </main>
  </body>
</html>`);
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
