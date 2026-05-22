const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');

const app = new Hono();

app.use(secureHeaders());

app.get('/', (c) => {
  return c.html(`<!DOCTYPE html>
<html>
<head>
  <title>Sign In</title>
  <link rel="stylesheet" href="https://unpkg.com/@knadh/oat/oat.min.css">
</head>
<body>
  <main class="container">
    <section>
      <h2>Sign In</h2>
      <form action="/signin" method="POST">
        <label for="email">Email</label>
        <input type="email" id="email" name="email" required>
        <label for="password">Password</label>
        <input type="password" id="password" name="password" required>
        <button type="submit">Sign In</button>
      </form>
    </section>
  </main>
</body>
</html>`);
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
