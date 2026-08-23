# Hello, Hono!

A minimal HTTP server built with [Hono](https://hono.dev).

The server listens on `localhost:3000`.

Run with Node.js:

```
npm install
HMAC_SECRET=$(openssl rand -hex 32) npm start
```

`HMAC_SECRET` signs session and CSRF tokens. It is required, must be at least 32
characters, and must be identical across every instance behind a load balancer.

For local development over plain HTTP, use `npm run dev`, which sets
`NODE_ENV=development` so cookies are issued without the `Secure` flag and an
ephemeral `HMAC_SECRET` is generated when none is supplied.

| Variable                      | Purpose                                                         |
| ----------------------------- | --------------------------------------------------------------- |
| `HMAC_SECRET`                 | Required signing key, 32 characters or longer                   |
| `PORT`                        | Listening port, defaults to `3000`                              |
| `NODE_ENV`                    | Set to `development` to relax cookie and secret requirements    |
| `TRUST_PROXY`                 | Set to `true` to read the client address from `X-Forwarded-For` |
| `DEMO_EMAIL`, `DEMO_PASSWORD` | Optional seed account for the in-memory user store              |

Accounts live in memory only and are lost when the process restarts.

New accounts start unverified and cannot sign in until their verification link
is followed. There is no mail transport yet, so the link is written to the
server log; wiring it to a real sender is the remaining piece of that flow.
