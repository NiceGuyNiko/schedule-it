# Schedule It — private accounts development branch

This is a staged implementation. **Do not merge to main yet.** Existing live calendar remains unchanged.

## Supabase
1. Run `supabase/schema.sql`, then `supabase/security-migration.sql`, then `supabase/registration-migration.sql` in SQL Editor (all are safe to re-run; none delete data).
2. In Authentication settings, **disable public signups**. Accounts will be created only by the server with the admin API.
3. In Netlify environment variables, add `SUPABASE_URL` = `https://greuzjrlifoytmjpqdfm.supabase.co`, `SUPABASE_SECRET_KEY` = your **secret/service-role** API key (never in source control), and `BOOTSTRAP_INVITE_CODE` = a random long secret used **once** for the first administrator signup.
4. Redeploy after setting variables, then open `/api/health` on the deploy: `{"ok":true}` means configuration and database access work. `stage:"config"` means a missing/wrong variable (function log names which); `stage:"database"` means the key cannot read the tables.
5. First admin signs up using bootstrap invitation code. Delete `BOOTSTRAP_INVITE_CODE` from Netlify after successful signup.
6. Generate one-time invitations in the Administration tab (to be built).

## Important
- This branch currently contains database and server groundwork, **not a completed frontend login**.
- The existing browser-local calendar needs explicit migration before enabling authenticated mode.
- Do not publish production registration until frontend integration, cross-user isolation tests, and rate-limit tests are complete.
- Back up local browser schedule data before migration.
- Never commit `sb_secret_...`, database passwords, bootstrap codes, or user schedule exports.
