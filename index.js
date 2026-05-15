const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');

const app = new Hono();

app.use(secureHeaders());

app.get('/', (c) =>
  c.html(`
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sign In</title>
</head>
<body>
<h1>Sign In</h1>
<form method="post" action="/">
<label>Email <input type="email" name="email" required></label>
<label>Password <input type="password" name="password" required></label>
<button type="submit">Sign In</button>
</form>
</body>
</html>
`)
);

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
