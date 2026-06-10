# Hello, Hono!

A minimal HTTP server built with [Hono](https://hono.dev).

The server listens on `localhost:3000`.

Run with Node.js:
```
npm install
npm start
```

## Session management

Sessions are stateless HMAC-signed cookies, so individual tokens cannot be revoked server-side. Two environment variables provide the revocation and rotation levers:

- `SESSION_NOT_BEFORE`: epoch milliseconds; any session issued before this moment is rejected. Set it to the current time to force all users to sign in again.
- `HMAC_SECRET_PREVIOUS`: during secret rotation, move the old `HMAC_SECRET` here and set a new `HMAC_SECRET`. Existing sessions stay valid until expiry while new tokens are signed with the new secret. Remove it to invalidate everything signed with the old secret.

`HMAC_SECRET` (at least 32 bytes) is required in production.

