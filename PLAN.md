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
- [x] [C1] Enforce maximum password length (1024 chars) to prevent scrypt-based DoS via huge input.
- [x] [C2] Wrap `verifySession` in try-catch to prevent unhandled 500 on malformed cookie tokens.
- [x] [C3] Include a creation timestamp in session tokens and reject expired sessions server-side.

### High
- [ ] [H1] Store an opaque random session ID in the cookie instead of the plaintext email.
- [ ] [H2] Add a timestamp to CSRF tokens and reject tokens older than 1 hour.
- [ ] [H3] Add server-side rate limiting on POST /sign-in and POST /register (per-IP).
- [ ] [H4] Return a generic success message on duplicate email registration to prevent user enumeration.

### Medium
- [ ] [M1] Replace GET /signout with a POST form to prevent CSRF-based forced logout.
- [ ] [M2] Validate email format server-side before storing or signing.
