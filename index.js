const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');

const app = new Hono();

app.use(secureHeaders());

const signInPage = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign In</title>
<link rel="stylesheet" href="https://unpkg.com/@knadh/oat/oat.min.css">
</head>
<body>
<main>
<article>
<h1>Welcome</h1>
<form method="post" action="/signin">
<label for="email">Email</label>
<input type="email" id="email" name="email" required>
<label for="password">Password</label>
<input type="password" id="password" name="password" required>
<button type="submit">Sign In</button>
</form>
</article>
</main>
</body>
</html>`;

app.get('/', (c) => c.html(signInPage));

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
