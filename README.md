# IAM Demo Application (real accounts)

One Cloudflare Worker serves the website and a login API. Accounts live in a D1 database.

## Features
- Register with username, email and password (first account becomes admin)
- Log in with email or username, log out, change password
- Server-side protected pages: /dashboard, /profile, /admin
- Admin console: promote/demote, suspend, delete users
- Passwords hashed with PBKDF2-SHA256 + random salt; sessions are random tokens in an HttpOnly cookie
- 5 failed logins locks the account for 10 minutes; CSRF origin check; CSP headers

## Deploy (GitHub -> Cloudflare Workers)
1. Cloudflare dashboard > Storage & Databases > D1 > Create database. Name it iam-demo-db.
2. Copy its Database ID and paste it into wrangler.jsonc (database_id).
3. Keep `name` in wrangler.jsonc equal to your Worker's name.
4. Commit and push this folder to your GitHub repo. Cloudflare redeploys automatically.
5. Open your workers.dev URL and click Register. Tables are created automatically on first request.

Enable the URL first if needed: Worker > Settings > Domains & Routes > workers.dev > Enable.

## Run locally
    npm install
    npx wrangler dev
Then open http://localhost:8787

## Settings
- Close sign-ups after you've made your admin: set ALLOW_REGISTRATION to "false" in wrangler.jsonc.
- Locked out of admin? In the D1 console: UPDATE users SET role='admin' WHERE username='yourname';
