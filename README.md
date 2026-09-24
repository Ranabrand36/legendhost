# Legend Host — production-ready core

Legend Host is a Cloudflare Workers + D1 platform for hosting user-owned static websites through Cloudflare Pages.

## What is implemented

- Name/email/password signup and login
- Secure HttpOnly/Secure/SameSite session cookies
- PBKDF2-SHA-256 password hashing using Web Crypto
- D1 persistence for users, sessions, projects and deployments
- Project ownership checks
- Project quota (5 per account by default)
- ZIP upload in the browser with safe path checks
- ZIP extraction for Store/Deflate entries in modern browsers
- Static asset validation and limits
- Cloudflare Pages project creation
- Cloudflare Pages Direct Upload asset hashing/upload/deployment flow
- Deployment records and provider deployment lookup
- Project deletion
- GitHub OAuth connection foundation
- GitHub repository listing
- Cloudflare Pages GitHub project creation with automatic deployments
- Responsive dashboard UI

## Important production configuration

The code is production-oriented, but it cannot be live until you connect your own Cloudflare account and secrets. Never put these secrets in frontend files.

### 1. Create Cloudflare resources

Create:

- A D1 database named `legend-host`
- A KV namespace for temporary GitHub OAuth tokens
- A Worker
- A Cloudflare API token with Pages Write access

Cloudflare's Pages API requires Pages Write permission for project/deployment operations. The Pages Direct Upload API uses a short-lived upload JWT for asset uploads. See the official docs:

- https://developers.cloudflare.com/pages/configuration/api/
- https://developers.cloudflare.com/api/resources/pages/subresources/projects/
- https://developers.cloudflare.com/api/resources/pages/subresources/assets/methods/upload/
- https://developers.cloudflare.com/api/resources/pages/subresources/projects/subresources/deployments/methods/create/

### 2. Configure `worker/wrangler.toml`

Replace:

- `REPLACE_WITH_D1_DATABASE_ID`
- `REPLACE_WITH_KV_NAMESPACE_ID`

### 3. Apply the D1 schema

Use Wrangler from the `worker` directory:

```bash
npx wrangler d1 execute legend-host --remote --file=schema.sql
```

### 4. Set secrets

```bash
npx wrangler secret put CLOUDFLARE_API_TOKEN
npx wrangler secret put CLOUDFLARE_ACCOUNT_ID
npx wrangler secret put APP_ORIGIN
```

For GitHub support:

```bash
npx wrangler secret put GITHUB_CLIENT_ID
npx wrangler secret put GITHUB_CLIENT_SECRET
npx wrangler secret put GITHUB_REDIRECT_URI
```

`APP_ORIGIN` should be the exact public URL of Legend Host, for example `https://host.example.com`.

### 5. GitHub OAuth

Create a GitHub OAuth App and set its callback URL to:

```text
https://YOUR-HOST/api/github/callback
```

The app requests `read:user repo` so users can select public/private repositories they authorized.

Cloudflare Pages Git integration must also be authorized/configured in the Cloudflare account for the selected repositories. Cloudflare documents that Git-connected Pages projects use repository source configuration and automatic deployments.

### 6. Deploy

From the `worker` directory:

```bash
npx wrangler deploy
```

The Worker serves the dashboard from `frontend/` and the API from `/api/*`.

## Current hosting scope

The first production release intentionally supports **static sites**:

- HTML
- CSS
- JavaScript
- images
- fonts
- JSON/XML/text assets

It does not execute arbitrary PHP, Python, Node.js server processes, or database-backed applications uploaded by users.

## Upload limits

Defaults are intentionally conservative for the free-tier MVP:

- ZIP selected in browser: 20 MB
- deployment request: 70 MB
- extracted website: 60 MB
- files: 1,000
- individual file: 25 MB
- projects/account: 5

Cloudflare Pages documents a 25 MiB per-file limit for direct-upload methods and supports Pages deployments through its API.

## Security notes

- Passwords are never stored in plaintext.
- Session tokens are stored hashed in D1.
- Cloudflare API tokens remain server-side secrets.
- ZIP paths are rejected if they attempt traversal or absolute paths.
- Uploaded sites are deployed as static assets; Legend Host does not inject its branding into them.
- Keep `APP_ORIGIN` set in production and serve the dashboard/API from the same origin.

## GitHub limitation

Cloudflare's Git-connected Pages flow is different from a Direct Upload Pages project. A project created as Direct Upload cannot later be switched to Git integration. Legend Host therefore creates GitHub-import projects separately from ZIP-upload projects.

## Not included yet

These need additional external infrastructure/configuration and are deliberately left out of the first production core:

- email verification
- password reset emails
- billing/subscriptions
- custom domains per customer
- arbitrary build commands (npm/pnpm/etc.)
- PHP/Python/Node server hosting
- abuse/moderation workflow
