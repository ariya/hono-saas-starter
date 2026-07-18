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

- None identified.

### High

- [x] Add rate limiting to /signin and /register to prevent unlimited online brute-force and credential-stuffing attempts.
- [ ] Enforce a maximum request body size and maximum input lengths (email, password) to prevent memory-exhaustion DoS via unbounded form posts (parseBody buffers the entire body) and CPU abuse through oversized inputs.

### Medium

- [ ] Eliminate timing-based user enumeration on /signin by always running scrypt against a dummy salt when the email is unknown.
- [ ] Remove the account-enumeration oracle on /register (the 409 "already exists" response reveals registered emails).
- [ ] Bind sessions to an existing user record; a stateless session stays valid for users wiped from the ephemeral store while HMAC_SECRET persists.

### Low

- [ ] Add a Content-Security-Policy header (e.g., script-src 'none'); secureHeaders does not set CSP by default.
- [ ] Send Cache-Control: no-store on authenticated responses so shared caches cannot store pages containing PII.
- [ ] Avoid placing the user email (base64) inside the session cookie; use an opaque session identifier instead.
- [ ] Normalize email casing/whitespace at registration and sign-in to prevent duplicate accounts (User@x.com vs user@x.com).
- [ ] Sessions cannot be revoked server-side (stateless design trade-off); a stolen cookie remains valid until its 7-hour expiry.
