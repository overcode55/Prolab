# ProLab on Cloudflare Pages

1. `npx wrangler d1 create prolab` → paste the id into `wrangler.toml`
2. `npx wrangler d1 execute prolab --remote --file=schema.sql`
3. Pages project → Settings → Bindings: add D1 `DB`. Variables:
   - `ADMIN_EMAILS` your email(s), comma separated (these accounts see all orders and can reply)
   - `RESEND_API_KEY`, `MAIL_FROM` (e.g. `ProLab <orders@yourdomain.com>`, domain verified in Resend)
   - `NOTIFY_EMAIL` where customer messages are sent to you
   - `GOOGLE_CLIENT_ID` (Google Cloud → OAuth client, type Web; add your Pages domain to Authorised JavaScript origins)
4. Deploy: `npx wrangler pages deploy .`

## What is GOOGLE_CLIENT_ID?
It is the public ID that tells Google which website is asking for "Sign in with Google". It is free and not secret. Get one at console.cloud.google.com: create a project, APIs & Services → Credentials → Create credentials → OAuth client ID → Web application, then add your `https://<project>.pages.dev` address under Authorised JavaScript origins. If you skip it, the Google button simply does not show and email login still works.

The "past work" items, stats and reviews are placeholder content in the `WORK` array in `index.html`.

## Google sign-in origin
In the OAuth client, under **Authorised JavaScript origins**, add `https://prolabz.pages.dev` (no trailing slash, no path). Leave redirect URIs empty. While the consent screen is in Testing mode, add your Gmail under Test users.

## Assets
```
assets/logo/favicon.png
assets/<folder>/<name>.webp   (dragon, pot, knight, gearbox, dog, cable, chameleon)
assets/<folder>/<name>.stl    (optional, shown in the 3D viewer)
```
Names are listed in the `WORK` array in `index.html`. Missing photos fall back to a drawing, missing STLs to a demo shape.

## File uploads (R2)
Enable R2 in the Cloudflare dashboard (Storage & databases, R2), then `npx wrangler r2 bucket create prolab-files` and re-run `schema.sql`. Remove the `[[r2_buckets]]` block from `wrangler.toml` if you do not want uploads.

## Models catalog
Run once on an existing database: `npx wrangler d1 execute prolab --remote --file=migrate.sql`, then `--file=seed.sql` to add the 7 starter models (run seed only once). Admins add more with the "Add model" link. Views, likes and "made" start at 0: "made" counts shipped or done requests that were started from that model's "Order this model" button.

## Importing a ZIP
Admin menu, Add model, then "Import ZIP" (`#/import`). Each folder in the zip becomes one model (folder name = title) holding its STL files and photos. Loose STL files at the top level become one model each. The unpacking runs in the backend and stores the files in R2. Keep zips under 50 MB.
