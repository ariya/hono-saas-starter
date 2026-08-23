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

- [x] Pin the Oat CDN assets to an exact version and add Subresource Integrity hashes, so a compromised CDN cannot inject script into the credential-entry pages.
- [x] Rate limit the sign-in and registration endpoints per client and per account, so unlimited password guessing and credential stuffing are not possible.
- [x] Reject weak `HMAC_SECRET` values (require at least 32 characters) instead of accepting any non-empty string that can be brute-forced to forge session cookies.
- [x] Cap the request body size and the accepted password length, so unauthenticated requests cannot exhaust server memory or CPU.

### High

- [x] Send a Content-Security-Policy header that allowlists only the pinned CDN origin, to contain any future script injection.
- [x] Send `Cache-Control: no-store` on every dynamic HTML response, so CSRF tokens and profile data are never retained by browsers or shared proxies.
- [x] Replace synchronous scrypt with the asynchronous variant so password hashing cannot block the event loop for other requests.
- [x] Raise the scrypt cost parameters to current OWASP guidance instead of relying on the Node defaults.
- [ ] Prefix the session and CSRF cookies with `__Host-` in production, so a compromised sibling subdomain cannot overwrite them.
- [ ] Bind the CSRF token to the active session, so an attacker cannot pair a self-issued token with a tossed cookie.
- [ ] Invalidate issued session tokens on sign out, so a captured cookie stops working before its 7-hour expiry.

### Medium

- [ ] Stop disclosing whether an email address is already registered; return a neutral registration response instead.
- [ ] Restrict the `DEMO_EMAIL` and `DEMO_PASSWORD` seeding to development, and apply the password policy to the seeded account.
- [ ] Bound the number of accounts the in-memory store will hold, so open registration cannot exhaust memory.
- [ ] Require email verification before an account can be used to sign in.
- [ ] Rotate the CSRF nonce after a successful sign-in to prevent pre-authentication token fixation.
- [ ] Log authentication successes, failures, and rate-limit rejections so attacks are detectable.

### Low

- [ ] Stop exposing the server clock from the `/health` endpoint.
- [ ] Validate email addresses more strictly than a bare `@` substring check.
- [ ] Add explicit `onError` and `notFound` handlers so internal details are never surfaced to clients.
- [ ] Reject passwords found in common-password lists in addition to the length minimum.
