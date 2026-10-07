# Authentication test plan (development only)

Do not test real passwords or invitation codes on a public preview until the branch is explicitly approved for testing. Never paste credentials into GitHub issues or logs.

## Environment
- Confirm Netlify branch deploy has SUPABASE_URL and SUPABASE_SECRET_KEY available to Functions (production-only variables do not reach branch deploys).
- Run schema.sql and security-migration.sql in the intended Supabase database.
- Confirm public Supabase signup is disabled.
- Confirm /api/me without a bearer token returns HTTP 401.

## Required integration tests
1. Bootstrap registration: valid code creates the first admin; repeating the same bootstrap code is rejected.
2. Regular registration: admin issues an invite; registration succeeds once; reuse fails.
3. Race test: two concurrent registrations with one invitation result in exactly one successful account.
4. Bad/expired/revoked invitations are rejected; invalid usernames/passwords are rejected.
5. Login with valid credentials succeeds; wrong password fails; rate limiting returns 429 after repeated attempts.
6. Non-admin invitation creation returns 403.
7. User A creates a calendar block. User B cannot read, update, or delete it.
8. Missing/expired access tokens return 401; logout clears the frontend token; refresh/expiration flow needs implementation.
9. A failed registration must not leave an orphan auth user or claimed invitation.
10. Verify server logs do not contain passwords, tokens, or invitation codes.

## Release blockers
- Portal is currently a separate preview, not the existing calendar.
- Session refresh, persistent login, logout invalidation and localStorage migration are unfinished.
- The initial unique admin-role index intentionally permits only one administrator; revisit before implementing multiple admins.
- Netlify production-only secrets do not automatically apply to development branch deployments.
- Do not merge to main until tests pass against a configured staging deployment.

## Deployment trigger
- Branch deploy requested after enabling feature/accounts-platform in Netlify.

- Retried deployment trigger after correcting Netlify's selected branch name.

- Redeploy requested after Branch deploys secrets were populated in Netlify.
