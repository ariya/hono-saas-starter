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

## Security Audit — Vulnerabilities

### Critical
- [*] Fix CSRF bypass: `safeEqual(body._csrf || '', cookie ...)` passes when both values are empty/undefined; attacker can submit POST without any CSRF token.
- [ ] Replace hardcoded fallback HMAC secret (`'dev-secret-change-in-production'`) with a cryptographically random fallback generated at startup.
- [ ] Add rate limiting to authentication endpoints (POST /signin, POST /register) to prevent brute-force and enumeration attacks.
- [ ] Enforce TLS/HTTPS in production via HTTP→HTTPS redirect or reject non-TLS connections.

### High
- [ ] Prevent email enumeration on POST /register: return a generic message instead of "Email already registered".
- [ ] Validate email format on server-side registration (basic regex check).

### Medium
- [ ] Add password complexity requirements beyond minimum length (mixed case, numbers, special characters).
- [ ] Generate a cryptographically random HMAC secret at startup when `HMAC_SECRET` is not set, rather than a static fallback.
