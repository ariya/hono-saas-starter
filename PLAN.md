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

- [x] Remove the hardcoded demo account seeded with known credentials in all environments.
- [ ] Add rate limiting to /signin and /register to prevent brute-force and credential stuffing.
- [ ] Enforce a maximum request body size to prevent memory-exhaustion denial of service.

### High

- [ ] Add a maximum password length and reject oversized credentials.
- [ ] Use asynchronous scrypt to avoid blocking the event loop during credential checks.
- [ ] Bind CSRF tokens to a session and add an expiry to prevent indefinite replay.
- [ ] Perform a dummy password hash for unknown accounts to prevent timing-based user enumeration.
- [ ] Return an identical registration response whether or not the email already exists.
- [ ] Add server-side email format validation and length limits.

### Medium

- [ ] Configure a strict Content-Security-Policy compatible with the CDN assets.
- [ ] Send Cache-Control: no-store on authenticated pages and credential forms.
- [ ] Cap the number of in-memory user records to prevent memory exhaustion.
- [ ] Prune the rate-limit store so it cannot grow without bound.
- [ ] Run the container as a non-root user.
- [ ] Invalidate server-side session state on sign-out despite the stateless design.

### Low

- [ ] Use the __Host- cookie prefix for the session cookie.
- [ ] Omit the timestamp from the unauthenticated /health response.
- [ ] Derive CSRF signatures with a separate secret/context from session signatures.
- [ ] Store an opaque session identifier instead of embedding the user email.
- [ ] Pin dependency versions exactly to reduce supply-chain drift.
