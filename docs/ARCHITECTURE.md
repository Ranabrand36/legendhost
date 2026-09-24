# Legend Host architecture

## Frontend
Static dashboard UI in `frontend/`.

## API
Cloudflare Worker in `worker/`.

## Database
Cloudflare D1. The schema is in `worker/schema.sql`.

## Deployment
The production API should:
1. authenticate the user;
2. create a project record;
3. validate the uploaded static ZIP;
4. create/manage a Cloudflare Pages project;
5. create a deployment;
6. store deployment status and URL in D1.

## GitHub
Use GitHub OAuth on the server side. Never expose a GitHub client secret or Cloudflare API token in browser code.

## Supported first release
HTML/CSS/JS/static assets only.

## Deliberately not included
PHP, MySQL-hosted applications, arbitrary Node/Python server processes, and unlimited hosting. These require different infrastructure and/or paid resources.
