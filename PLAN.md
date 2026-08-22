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

## Security Audit Findings

### Critical

- [x] Add rate limiting to the authentication endpoints (/signin, /register) to prevent brute-force password guessing and registration flooding.

### High

- [x] Expire and bind CSRF tokens to the browser so leaked tokens cannot be replayed indefinitely.
- [x] Set the SameSite attribute on session cookies to harden against cross-site request forgery.
- [x] Prevent account enumeration: equalize sign-in timing for unknown users and avoid confirming registered emails.
- [ ] Cap request body size and input lengths (email/password) to prevent memory and scrypt CPU exhaustion.

### Medium

- [ ] Validate HMAC_SECRET strength (minimum 32 characters) at startup in every environment.
- [ ] Add a restrictive Content-Security-Policy allowing only self-hosted and Oat CDN assets.
- [ ] Require the CSRF token on /signout to prevent forced-logout cross-site attacks.
- [ ] Track signed-out sessions server-side so stolen tokens cannot outlive logout until natural expiry.

### Low

- [ ] Remove the timestamp from the /health response (minor information disclosure).
- [ ] Use __Host- prefixed session cookies in production.
- [ ] Centralize and tune scrypt cost parameters instead of relying on library defaults.
