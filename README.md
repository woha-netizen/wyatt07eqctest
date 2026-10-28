# IAM Demo Application

A static site. Cloudflare Pages serves it, so no server is needed.

## Run locally
    python3 -m http.server 8000     # then open http://localhost:8000
Locally you see a demo user, because there is no Access in front.

## Deploy
1. Cloudflare dashboard > Workers & Pages > Create > Pages > Upload assets. Upload this folder.
   (Or: npx wrangler pages deploy . --project-name iam-demo)
2. Zero Trust > Access > Applications > Add > Self-hosted. Use your *.pages.dev domain.
3. Add policies:
   - Allow: emails ending in your domain (or your IdP group "employees")
   - For path /admin*, a separate app: Allow only group "admins"
4. Optional: set the app's block page to /access-denied.html.

## Files
index, dashboard, profile, admin, access-denied, 404 (.html), css/styles.css, js/app.js, _headers
