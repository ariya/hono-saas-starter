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

### CRITICAL

- [*] Fix timing attack on sign-in endpoint: missing user returns immediately, while invalid password triggers scrypt, enabling user enumeration.
- [*] Add `SameSite=Strict` attribute to session cookies to prevent cross-site cookie transmission and CSRF bypass.
- [*] Implement basic in-memory rate limiting on `/` POST and `/register` POST to mitigate brute-force and account creation abuse.
- [*] Remove user enumeration from registration: "Email already registered" error leaks registered accounts.

### HIGH

- [*] Add server-side email format validation to prevent malformed or oversized inputs.
- [*] Enforce Content Security Policy headers via `secureHeaders` configuration.
- [*] Add HTTPS redirect enforcement in production when requests arrive over HTTP.

### MEDIUM
- [*] Remove inline styles from templates to remain compatible with a strict CSP.
- [*] Bind session tokens to a client fingerprint (e.g., user-agent hash) to reduce token portability if stolen.
- [*] Add account lockout or exponential backoff after repeated failed authentication attempts.

### LOW

- [ ] Add `Max-Age` alongside `Expires` on cookies for consistency.
- [ ] Introduce security event logging for failed logins and suspicious requests.
- [ ] Add expiration (time-bound) to CSRF tokens beyond single-use.
