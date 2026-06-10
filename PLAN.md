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

## Security Audit (2026-06-09)

### Critical

- [x] Add per-IP rate limiting to the sign-in and registration handlers to block credential brute-forcing.
- [ ] Cap email (254 chars) and password (128 chars) input lengths before hashing to prevent scrypt resource-exhaustion DoS.
- [ ] Replace synchronous scrypt calls with the async variant so password hashing no longer blocks the event loop.
- [ ] Enforce a minimum 32-byte HMAC_SECRET in production, refusing to start with a weak secret.

### High

- [ ] Bind CSRF tokens to a random pre-session cookie so attacker-minted tokens cannot be replayed (login CSRF).
- [ ] Add a request body size limit to prevent memory-exhaustion DoS via large POST bodies.
- [ ] Equalize sign-in timing by hashing against a dummy credential when the email is unknown (user enumeration).

### Medium

- [ ] Mitigate non-revocable stateless sessions: embed an issued-at claim and document HMAC secret rotation as the revocation path.
- [ ] Avoid revealing account existence through the registration duplicate-email response.
- [ ] Configure an explicit Content-Security-Policy via the secure headers middleware.

### Low

- [ ] Remove the server timestamp from the /health response.
- [ ] Use the __Host- cookie name prefix for the session cookie in production.
- [ ] Validate email format server-side during registration.
