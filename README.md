# Legend Host

Legend Host is a zero-cost-target static hosting starter built on Cloudflare Workers + D1 + Cloudflare Pages.

## What is included

- Name/email/password accounts
- HttpOnly session cookies
- Automatic D1 schema bootstrap for a fresh database
- Mobile-first dashboard
- ZIP deployment for static HTML/CSS/JS sites
- GitHub OAuth import flow (optional)
- Cloudflare Pages deployment engine (requires a Cloudflare API token with the needed Pages permissions)
- Project ownership checks and ZIP path validation
- No Legend Host branding is injected into hosted websites
- No KV namespace is required for signup/login or ZIP deployment

## Cloudflare setup

### 1. D1
Create a D1 database named `legend-host` and put its ID in `worker/wrangler.toml` under the `DB` binding.

The Worker also runs the idempotent schema on first API use. You can still initialize it manually with:

```bash
npx wrangler d1 execute legend-host --remote --file=./worker/schema.sql
```

### 2. Worker build settings

For a GitHub Worker build where `wrangler.toml` is inside `worker/`:

- Root directory: `/worker`
- Build command: empty
- Deploy command: `npx wrangler deploy`
- Preview command: `npx wrangler preview`

### 3. Required secrets for deployment

Set these on the Worker if you want ZIP/GitHub deployments:

- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`

Do not put these values in frontend files or commit them to GitHub.

### 4. Optional GitHub integration

Set:

- `GITHUB_CLIENT_ID`
- `GITHUB_CLIENT_SECRET`
- `GITHUB_REDIRECT_URI`
- `APP_ORIGIN` (for example the Worker URL)

GitHub access tokens are encrypted before being stored in the existing D1 `github_tokens.token_hash` column. The encryption key is derived from `APP_ENCRYPTION_KEY` when present, otherwise from the GitHub client secret. No KV namespace is required.

## Supported websites

The first release is for static websites only:

- HTML
- CSS
- JavaScript
- Images, fonts and other static assets

PHP, MySQL, Node/Python server code and other server-side applications are not executed by this static hosting engine.
