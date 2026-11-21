# CHOLLU — Cloudflare Workers project

This ZIP is a reviewed deployment package based on the files you supplied.

## Included
- `src/worker.js`: API Worker
- `public/`: website, service worker, icon, PWA manifest
- `migrations/0001_initial.sql`: clean initial D1 schema
- `wrangler.jsonc`: Workers + Static Assets + D1 configuration

## Deploy (GitHub + Cloudflare)
1. Extract this ZIP and upload the contents (not the ZIP itself) to a new GitHub repository.
2. In Cloudflare, create a D1 database named `chollu-db`.
3. Copy its database ID into `wrangler.jsonc`, replacing `REPLACE_WITH_YOUR_D1_DATABASE_ID`.
4. Install Node.js and run `npm install`.
5. Apply the database migration: `npx wrangler d1 migrations apply chollu-db --remote`.
6. Deploy: `npx wrangler deploy`.

For a Git-connected Worker, use the repository's `package.json` and `wrangler.jsonc`; deploy command `npx wrangler deploy`. This is a Workers project, not a Pages drag-and-drop upload.

## Required Worker bindings / secrets
- D1 binding: `DB` (configured in `wrangler.jsonc`)
- Workers AI binding: `AI` (needed for the built-in CHOLLU AI assistant)
- `VAPID_PUB` (text), `VAPID_JWK` (secret), and optionally `VAPID_SUB` (text) for web push
- `RESEND_KEY` (secret) and `MAIL_FROM` (text) for password reset email
- Optional TURN variables: `TURN_URL`, `TURN_USER`, `TURN_CRED` for more reliable calls

Do not commit secret values to GitHub. Set them in the Cloudflare Worker Settings > Variables and Secrets.

## Important security note
The VAPID private key in the uploaded `vapid-secrets.txt` was exposed in this chat upload. Treat it as compromised: generate a NEW VAPID key pair, update `VAPID_PUB` and `VAPID_JWK` in Cloudflare, and do not reuse the exposed private key. The private key file has intentionally NOT been copied into this ZIP.

## Current limitations — not production complete
- Chat lock / PIN / pattern settings are stored in browser localStorage. They are a convenience feature, not server-enforced security; do not use it to protect highly sensitive chats.
- Message contents are stored in D1 without end-to-end encryption.
- The app stores media as data URLs in message records with size limits; this is not a scalable media-storage design. Use Cloudflare R2 for production media.
- The browser code stores the session token in localStorage. A production release should move to secure, HttpOnly cookie sessions and add CSRF protections.
- The password hashing in this supplied Worker is SHA-256 with a salt, not a deliberately slow password KDF; upgrade to PBKDF2/Argon2 before public launch.
- Add account verification, account recovery hardening, moderation/admin tools, rate limits across all endpoints, privacy policy, terms, backups, and security testing before public release.
- Voice/video calls need TURN configuration for reliable connectivity; the current code only defaults to a public STUN server.
- This package is a web/PWA project. It does not include a signed Android APK.

## Existing database warning
`0001_initial.sql` is for a NEW empty D1 database. If your existing D1 database already has tables or users, do not apply it blindly; take a backup and migrate the existing schema carefully.
