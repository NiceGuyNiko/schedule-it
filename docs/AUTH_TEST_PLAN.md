# Authentication test plan (development only)

Do not test real passwords or invitation codes on a public preview until the branch is explicitly approved for testing. Never paste credentials into GitHub issues or logs.

## Environment
- Confirm Netlify branch deploy has SUPABASE_URL and SUPABASE_SECRET_KEY available to Functions (production-only variables do not reach branch deploys).
- Run schema.sql, security-migration.sql and registration-migration.sql in the intended Supabase database.
- Confirm public Supabase signup is disabled.
- `GET /api/health` returns `{"ok":true}`.
- Confirm /api/me without a bearer token returns HTTP 401.

## Diagnosing failures
Every 500 response is `{"error":"Server error","stage":"<step>","ref":"<id>"}`. The portal shows the ref. Netlify → Logs → Functions → `api`: search for the ref; the JSON log line holds the Postgres/Auth error `code`, `message` and `hint` (never passwords, tokens or codes).

| stage | usual cause |
|---|---|
| `config` (503) | variable missing in this deploy context, URL not bare `https://<ref>.supabase.co`, or a publishable/anon key in `SUPABASE_SECRET_KEY` |
| `rate limit (...)` | `check_auth_rate` missing or not executable: schema.sql not run in this project, or key is not service_role |
| `complete registration` (`PGRST202`) | registration-migration.sql not run |
| `create auth user` | key lacks admin rights (`not_admin`), or Auth settings reject the user |
| `bootstrap profile count` / `invitation lookup` (`42501`) | service_role lacks table grants: run registration-migration.sql |

## Automated tests
- `npm test` — no network or credentials needed.
  - `tests/sql.test.mjs`: runs the three SQL scripts (twice, to prove re-runnability) in PGlite and checks bootstrap, single-use invitations, rollback, expired/revoked codes, duplicate usernames, user deletion, rate limiting and role privileges.
  - `tests/api.test.mjs`: runs the Netlify handler against a fake Supabase HTTP API and checks config detection, error stages, rollback, status codes, session endpoints, ownership filters and that logs contain no secrets.
- `node scripts/live-auth-test.mjs` — end-to-end against a branch deploy (needs `BASE_URL`, `ADMIN_USERNAME`, `ADMIN_PASSWORD` env vars; refuses production URLs). Covers items 2, 3, 4, 5, 6, 7 and 8 below.

## Required integration tests
1. Bootstrap registration: valid code creates the first admin; repeating the same bootstrap code is rejected.
2. Regular registration: admin issues an invite; registration succeeds once; reuse fails.
3. Race test: two concurrent registrations with one invitation result in exactly one successful account.
4. Bad/expired/revoked invitations are rejected; invalid usernames/passwords are rejected.
5. Login with valid credentials succeeds; wrong password fails; rate limiting returns 429 after repeated attempts.
6. Non-admin invitation creation returns 403.
7. User A creates a calendar block. User B cannot read, update, or delete it.
8. Missing/expired access tokens return 401; logout revokes the refresh token; refresh issues a new session.
9. A failed registration must not leave an orphan auth user or claimed invitation.
10. Verify server logs do not contain passwords, tokens, or invitation codes.

## Cleaning up live-test users
Run in Supabase SQL Editor after reviewing the SELECT output:
```sql
select id, email from auth.users where email like 'zz\_test\_%@accounts.schedule-it.invalid';
-- then, if the list contains only test accounts:
delete from auth.users where email like 'zz\_test\_%@accounts.schedule-it.invalid';
```
Profiles and calendar blocks cascade; used invitations stay consumed (requires registration-migration.sql).

## Release blockers / remaining issues
- Portal is currently a separate preview, not the existing calendar.
- localStorage calendar migration is unfinished.
- Session is kept in sessionStorage (per tab). Persistent "remember me" across browser restarts is not implemented.
- Logout revokes the refresh token; the current access token stays valid until it expires (Supabase default 1 hour). Lower the JWT expiry in Supabase Auth settings if that window matters.
- Administration tab can only generate invitations: no invitation list/revoke and no user list/disable/delete yet.
- The unique admin-role index permits only one administrator; revisit before implementing multiple admins.
- Rate limiting is per client IP only (register 10, login 8, refresh 60 per 15 min). No per-username lockout.
- If the auth-user rollback after a failed registration itself fails, an orphan auth user remains (logged as "orphan auth user" with its id) and blocks that username until deleted.
- Netlify production-only secrets do not automatically apply to development branch deployments.
- Do not merge to main until tests pass against a configured staging deployment.
