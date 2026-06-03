- [*] Implement the initial landing page route to display the sign-in screen.
- [*] Ensure a mobile-friendly, responsive viewport.
- [*] Refactor the sign-in page to use the Eta templating engine for backend rendering.
- [*] Implement a dynamic "Welcome" title that selects from 5 randomized options.
- [*] Initialize an in-memory User store (supporting email, password hash, and salt).
- [*] Create a POST handler for sign-in to validate credentials against the User store.
- [*] Implement error handling: Re-render the sign-in page with a clear error message on failure.
- [*] Implement success logic: Set a session cookie and redirect authenticated users to /profile.
- [*] Configure session cookies with the Secure flag and a 7-hour expiration.
- [*] Implement conditional logic to disable the Secure flag during local development.
- [*] Use scrypt for password hashing and HMAC for session cookie validation.
- [*] Secure the HMAC secret, retrieve from the `HMAC_SECRET` env.
- [*] Implement CSRF protection using an HMAC-signed token, passed via a hidden input field.
- [*] Build the /profile route with session validation; redirect unauthenticated users to /.
- [*] Update the landing page to auto-redirect active sessions to /profile.
- [*] Add a "Register for account" link to the sign-in interface.
- [*] Create the /register route and an Eta-rendered registration page.
- [*] Enforce mininum password length (8 chars) on the server in the registration handler.
- [*] Implement registration logic: Save new users, display a success message, and auto-redirect to /.
- [*] Design the /profile skeleton, displaying the user's email in the top-left navigation bar.
- [*] Add a "Sign Out" button in the top-right navigation bar targeting /signout.
- [*] Implement the /signout handler to clear session cookies and redirect to the landing page.

## Security Audit

### Critical

- [*] Remove the duplicate `app.post('/signin', ...)` handler that lacks CSRF verification (dead-code leftover from refactor that bypasses CSRF if ever reached).
- [*] Require `HMAC_SECRET` to be set unconditionally; remove the hardcoded `dev-only-insecure-secret` fallback (or replace with a random ephemeral secret generated at startup with a clear warning).
- [*] Eliminate the username-enumeration timing side channel in `/signin` by always executing a constant-time password comparison (run scrypt against a dummy hash when the user is not found).
- [*] Bind the CSRF token to a per-browser anti-CSRF cookie (double-submit pattern) so attackers cannot mint valid tokens from the public sign-in page and mount login-CSRF.
- [ ] Add an in-process rate limiter on `/signin` and `/register` (per remote address) to mitigate password brute-force and account enumeration.
- [ ] Reject oversized request bodies before `parseBody` to prevent memory-exhaustion DoS (enforce a small Content-Length cap).
- [ ] Define an explicit Content-Security-Policy via `secureHeaders` allowing only `self` and the Oat.ink stylesheet host, blocking inline scripts and arbitrary origins.

### High

- [ ] Use the `__Host-` prefix for the session cookie in production for defense-in-depth (forces Secure + Path=/ + no Domain).
- [ ] Introduce a per-session nonce stored server-side so that `/signout` truly revokes the token instead of relying on the client to delete the cookie.
- [ ] Validate the `Content-Type` of POST requests to ensure the body parser only accepts `application/x-www-form-urlencoded` for these endpoints.

### Medium

- [ ] Tune scrypt parameters (`N`, `r`, `p`, `keylen`) explicitly rather than relying on Node defaults that are now considered low for 2026.
- [ ] Normalize email addresses with Unicode NFKC before storage/lookup to avoid duplicate-effective accounts.

### Low

- [ ] Remove the timestamp from `/health` response (minor information disclosure).
- [ ] Add audit logging for failed sign-in attempts to aid incident response.
