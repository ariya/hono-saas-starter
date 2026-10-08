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

- [x] Cap request body size and password length; unbounded `parseBody` and scrypt input let one unauthenticated request exhaust memory and CPU.

### High

- [x] Add per-IP rate limiting to sign-in and registration to stop credential guessing, account spam, and scrypt thread-pool exhaustion.
- [x] Bind the CSRF token to the browser (double-submit cookie); any valid token currently works for any visitor, so login CSRF is open.
- [x] Make sign-out effective server-side: it only clears the cookie, so a copied session stays valid for up to 7 hours. Add a per-user session version that sign-out increments.
- [x] Require `HMAC_SECRET` to be at least 32 characters at startup; a short secret makes session forgery feasible.

### Medium

- [x] Send a Content-Security-Policy header limiting scripts and styles to `self` and the Oat.ink CDN (inline `style` attributes must move to CSS first).
- [x] Send `Cache-Control: no-store` on authenticated pages and on pages carrying CSRF tokens.
- [x] Raise scrypt cost to N=2^17, r=8, p=1 (OWASP recommendation); the current defaults are N=2^14.
- [x] Cap the in-memory user store so unauthenticated registration cannot grow memory without bound.
- [ ] Registration reveals whether an email is taken ("An account with this email already exists."), enabling account enumeration.

### Low

- [ ] Session cookie payload is readable base64 JSON that includes the user's email; use an opaque subject identifier instead.
- [ ] Use the `__Host-` cookie name prefix for the session cookie.
- [ ] Use separate secrets for CSRF and session signing instead of one `HMAC_SECRET` with domain-separation prefixes.
- [ ] Add a session idle timeout in addition to the absolute 7-hour expiry.
- [ ] Log failed sign-in attempts for monitoring.
- [ ] Add a common-password check to the registration password policy.
