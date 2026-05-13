const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');

const app = new Hono();

app.use(secureHeaders());

const signinHtml = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Sign In</title>
<link rel="stylesheet" href="https://unpkg.com/@knadh/oat/oat.min.css">
<script src="https://unpkg.com/@knadh/oat/oat.min.js" defer></script>
</head>
<body>
<main style="max-width:400px;margin:50px auto;padding:20px">
<h1>Welcome</h1>
<form method="POST" action="/">
<label for="email">Email</label>
<input type="email" id="email" name="email" required>
<label for="password">Password</label>
<input type="password" id="password" name="password" required>
<button type="submit">Sign In</button>
</form>
</main>
</body>
</html>`;

app.get('/', (c) => c.html(signinHtml));

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
