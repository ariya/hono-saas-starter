## Tech Stack

- Frontend: Vanilla HTML
- Styling: [Oat.ink](https://oat.ink/) via CDN
- Backend: Node.js with Hono (Vanilla JavaScript)
- Database: In-memory (Ephemeral/Temporary)

## Project Structure

- Single-File Core: The entire application logic must reside in a single file: `index.js`.
- Templating: Page templates must be stored in individual `*.eta` files.

## Coding Conventions

- Progressive Enhancement: All frontend pages must remain fully functional even if JavaScript is disabled in the browser.
- Server-Side Rendering (SSR): Every page must be rendered on the server using the designated templating engine.
- Stateless Architecture: The backend must remain strictly stateless to support seamless horizontal scaling.
- Minimalist Dependencies: Prioritize lightweight modules; avoid third-party dependencies whenever possible.
- No Code Annotations: Do not include comments, annotations, or JSDoc in the source files.
- Exploratory Phase: Omit unit tests for now. A formal testing suite will be introduced once the initial exploration is complete.
