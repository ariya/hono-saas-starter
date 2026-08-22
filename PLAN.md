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

- [x] Rate-limit the sign-in and registration endpoints to block brute-force, credential stuffing, and mass account creation.
- [x] Enforce a request body size limit and cap email/password lengths to prevent memory and CPU exhaustion (DoS).
- [x] Upgrade hono and @hono/node-server to remediate published high/moderate security advisories.

### High

- [x] Reject weak HMAC secrets by enforcing a 32-character minimum length in production.
- [x] Add a Content-Security-Policy that restricts script and style sources to the Oat CDN.

### Medium

- [ ] Equalize login response timing (constant-work verification) to prevent user enumeration.
- [ ] Add the SameSite=Lax attribute to session cookies for layered CSRF protection.
- [ ] Bind CSRF tokens to the browser via a double-submit cookie to prevent login CSRF.
- [ ] Send Cache-Control: no-store on authenticated pages to prevent intermediary caching.

### Low

- [ ] Store an opaque identifier instead of the raw email inside the signed session cookie (PII exposure).
- [ ] Remove the server clock disclosure from the /health endpoint.
- [ ] Consider a stronger password policy beyond minimum length.
