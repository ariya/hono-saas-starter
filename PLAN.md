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

- [*] Replace the hardcoded dev fallback HMAC secret with a random per-process secret to prevent session forgery when NODE_ENV is unset.
- [*] Eliminate the sign-in timing oracle that lets attackers enumerate registered emails (verifyPassword runs only for existing users).
- [*] Add rate limiting / brute-force throttling on the POST /signin endpoint.
- [*] Enforce a request body size limit and a maximum password length to prevent memory/CPU DoS via scrypt on oversized inputs.

### High

- [*] Bind the CSRF token to the user session so authenticated POST routes (e.g. /signout) cannot be replayed cross-site.
- [*] Replace blocking scryptSync with asynchronous scrypt to avoid stalling the event loop on every login.

### Medium

- [*] Prevent user enumeration via the registration "already exists" message.
- [*] Validate email format on the server in the registration handler.
- [*] Use an opaque per-user session ID instead of the user's email (PII) as the signed session cookie subject.
- [*] Enable a Content-Security-Policy header via secureHeaders.
- [*] Seed the demo account only in development so production has no hardcoded credentials.

### Low

- [ ] Derive separate keys for session cookies and CSRF tokens instead of reusing HMAC_SECRET.
- [ ] Document the inability to revoke sessions server-side (inherent to the stateless signed-cookie design).
