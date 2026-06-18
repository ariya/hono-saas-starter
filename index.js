const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { secureHeaders } = require('hono/secure-headers');

const app = new Hono();

app.use(secureHeaders());

app.get('/', (c) => {
  return c.html(
    '<!DOCTYPE html>' +
      '<html lang="en">' +
      '<head>' +
      '<meta charset="UTF-8">' +
      '<title>Sign In</title>' +
      '</head>' +
      '<body>' +
      '<main>' +
      '<h1>Sign In</h1>' +
      '<form method="POST" action="/signin">' +
      '<label>Email<input type="email" name="email" required></label>' +
      '<label>Password<input type="password" name="password" required></label>' +
      '<button type="submit">Sign In</button>' +
      '</form>' +
      '</main>' +
      '</body>' +
      '</html>'
  );
});

app.get('/health', (c) => c.text(`OK ${Date.now()}`));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port });
console.log('Listening on port', port);
