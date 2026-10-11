# Dunellan Lodge No. 480 website

The public website is hosted on Vercel (project dunellan-lodge). Vercel forwards every /api/ request to the Cloudflare Worker, which talks to the Cloudflare D1 database. All on free plans.

- `public/index.html` is the public website.
- `public/admin.html` is the members area at `/admin`.
- `src/worker.js` handles news posts, newsletter signups, enquiries and sign in.
- The D1 database `dunellan-lodge` is already created and set up in Matt's Cloudflare account.

## Put it online (first time)

In a terminal, inside this folder:

```
npm install
npx wrangler login
npx wrangler deploy
```

`wrangler login` opens a browser to approve access. Skip it if you are already signed in.
The deploy prints the web address, for example `https://dunellan-lodge.<your-subdomain>.workers.dev`.

## Update it later

- Website pages (public folder): `npx vercel deploy --prod`
- API or database code (src folder, wrangler.toml): `npx wrangler deploy`
- Not sure which changed? Run both.

## Members area

Go to `/admin` on the site. Sign in with an approved email and password.
New members get a temporary password and choose their own at first sign in.
Add or remove members from the Members tab.

## Add a domain later

Vercel dashboard > dunellan-lodge > Settings > Domains > Add. Then add the new address to ALLOWED_ORIGINS in wrangler.toml and run `npx wrangler deploy`.

## Backups

On the free plan, D1 keeps 7 days of history automatically (Time Travel). To save a copy as a file:

```
npx wrangler d1 export dunellan-lodge --remote --output backup.sql
```
