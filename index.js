const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');

const app = new Hono();

app.use(secureHeaders());

const signInPage = `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <link rel="stylesheet" href="https://unpkg.com/@knadh/oat/oat.min.css" />
    <script src="https://unpkg.com/@knadh/oat/oat.min.js" defer></script>
    <title>Sign In</title>
  </head>
  <body>
    <main>
      <h1>Welcome</h1>
      <form method="post" action="/">
        <label>
          Email
          <input type="email" name="email" autocomplete="username" required />
        </label>
        <label>
          Password
          <input
            type="password"
            name="password"
            autocomplete="current-password"
            required
          />
        </label>
        <button type="submit">Sign In</button>
      </form>
    </main>
  </body>
</html>`;

app.get('/', (c) => c.html(signInPage));

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
