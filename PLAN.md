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

- [x] Session tokens are not time-limited server-side: the signed payload contains only the email, so a captured cookie value is valid forever. The 7-hour `maxAge` is client-controlled and not enforced. Bake an expiry timestamp into the signed session payload and reject expired tokens on validation.

### High

- [ ] Login/registration user enumeration via timing oracle: `verifyPassword` skips the scrypt computation when the user does not exist, leaking account existence through response timing. Always perform a hash comparison against a dummy hash for unknown users.
- [ ] Unbounded password length allows scrypt CPU-exhaustion DoS: cap the accepted password length (e.g. 128 chars) before hashing on both sign-in and registration.
- [ ] No Content-Security-Policy header: configure `secureHeaders()` with a CSP that only permits the required stylesheet origin to harden against XSS.

### Medium

- [ ] No rate limiting or account lockout on `/` (sign-in) and `/register`, allowing credential brute-force and registration abuse.
- [ ] CSRF tokens are not bound to a session: any server-issued token is accepted on any request, so a token harvested from the public sign-in page enables login CSRF. (SameSite=Lax partially mitigates.) Bind the token to the session or use a pre-session double-submit cookie.
- [ ] Email addresses are not normalized (case/whitespace) or format-validated, permitting duplicate and confusable accounts.
- [ ] No request body size limit on `parseBody`, allowing memory-exhaustion via oversized form submissions.

### Low

- [ ] `/health` exposes the server clock via `Date.now()`; return a static status string instead.
