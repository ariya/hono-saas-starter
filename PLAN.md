- [x] Implement the initial landing page route to display the sign-in screen.
- [x] Ensure a mobile-friendly, responsive viewport.
- [x] Refactor the sign-in page to use the Eta templating engine for backend rendering.
- [x] Implement a dynamic "Welcome" title that selects from 5 randomized options.
- [x] Initialize an in-memory User store (supporting email, password hash, and salt).
- [x] Create a POST handler for sign-in to validate credentials against the User store.
- [x] Implement error handling: Re-render the sign-in page with a clear error message on failure.
- [x] Implement success logic: Set a session cookie and redirect authenticated users to /profile.
- [x] Configure session cookies with the Secure flag and a 7-hour expiration.
- [x] Implement conditional logic to disable the Secure flag during local development.
- [x] Use scrypt for password hashing and HMAC for session cookie validation.
- [x] Secure the HMAC secret, retrieve from the `HMAC_SECRET` env.
- [x] Implement CSRF protection using an HMAC-signed token, passed via a hidden input field.
- [x] Build the /profile route with session validation; redirect unauthenticated users to /.
- [x] Update the landing page to auto-redirect active sessions to /profile.
- [x] Add a "Register for account" link to the sign-in interface.
- [x] Create the /register route and an Eta-rendered registration page.
- [x] Enforce mininum password length (8 chars) on the server in the registration handler.
- [x] Implement registration logic: Save new users, display a success message, and auto-redirect to /.
- [x] Design the /profile skeleton, displaying the user's email in the top-left navigation bar.
- [x] Add a "Sign Out" button in the top-right navigation bar targeting /signout.
- [x] Implement the /signout handler to clear session cookies and redirect to the landing page.

## Security Audit

### Critical

- [x] Upgrade `hono` and `@hono/node-server` to patched releases; the pinned versions are affected by high and moderate advisories, including `parseBody()` memory exhaustion.
- [x] Replace synchronous `scrypt` with asynchronous `scrypt` so password hashing cannot block the event loop and stall the whole server.
- [x] Add rate limiting to `/signin` and `/register` to prevent credential brute forcing and resource-exhaustion abuse.

### High

- [x] Cap the in-memory user store to prevent memory-exhaustion denial of service.
- [x] Force the session cookie `Secure` attribute unless explicitly running in development.
- [x] Validate registration and sign-in input (email format and maximum lengths) on the server.
- [x] Remove account enumeration from the duplicate-email error and the sign-in timing difference.
- [x] Bind CSRF tokens to a session or double-submit cookie so they cannot be replayed across users.
- [x] Remove the unused third-party JavaScript from unpkg or add Subresource Integrity attributes.

### Medium

- [x] Add a Content-Security-Policy header.
- [x] Validate `HMAC_SECRET` presence and entropy at startup and fail closed in production.
- [x] Invalidate the session server-side on sign-out.
- [x] Raise scrypt parameters to current OWASP guidance.
- [x] Enforce a request body size limit.
- [ ] Require POST with a CSRF token for sign-out.

### Low

- [ ] Use the `__Host-` prefix for the session cookie.
- [ ] Remove the timestamp from the public `/health` response.
- [ ] Add a stronger password policy.
- [ ] Document that in-memory state is not shared across instances.
