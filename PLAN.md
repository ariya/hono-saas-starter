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

## Security Audit: Critical

- [*] Enforce minimum entropy for `HMAC_SECRET` before signing cookies or CSRF tokens.

## Security Audit: High

- [*] Add request throttling for authentication and registration endpoints to reduce brute-force risk.
- [*] Bind CSRF tokens to the intended action and authenticated user context so tokens cannot be reused across forms.

## Security Audit: Medium

- [*] Pin the Oat.ink stylesheet to a fixed version and add an integrity check to reduce CDN supply-chain risk.
- [*] Replace duplicate-account registration errors with a generic response to reduce account enumeration.
- [*] Run a dummy password hash when sign-in email is unknown to reduce timing-based account enumeration.
- [ ] Make CSRF tokens single-purpose and short-lived enough for state-changing form submissions.

## Security Audit: Low

- [ ] Validate email addresses on the server instead of relying on browser input validation.
- [ ] Clear session cookies using the same security attributes used when setting them.
