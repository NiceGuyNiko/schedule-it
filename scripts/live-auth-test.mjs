// End-to-end auth checks against a deployed branch. Creates two throwaway users named zz_test_*.
// Usage (PowerShell):  $env:BASE_URL='https://<branch>--<site>.netlify.app'; $env:ADMIN_USERNAME='...'; $env:ADMIN_PASSWORD='...'; node scripts/live-auth-test.mjs
// Prints only PASS/FAIL lines; never prints passwords, tokens or invitation codes.
// Uses about 6 registration and 6 login attempts from your IP (limits: 10 and 8 per 15 minutes).
import { randomBytes } from 'node:crypto';

const { BASE_URL, ADMIN_USERNAME, ADMIN_PASSWORD } = process.env;
if (!BASE_URL || !ADMIN_USERNAME || !ADMIN_PASSWORD) { console.error('Set BASE_URL, ADMIN_USERNAME and ADMIN_PASSWORD'); process.exit(2); }
const base = BASE_URL.replace(/\/$/, '');
if (!/^https:\/\//.test(base) || /^https:\/\/(www\.)?[^-/]+\.netlify\.app$/.test(base)) {
  console.error('BASE_URL must be the HTTPS branch-deploy URL (e.g. https://feature-accounts-platform--<site>.netlify.app), not production');
  process.exit(2);
}

let failures = 0;
const check = (name, cond, detail = '') => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${cond || !detail ? '' : '  -> ' + detail}`); if (!cond) failures++; };
const api = async (route, body, token) => {
  const r = await fetch(`${base}/api/${route}`, { method: 'POST', headers: { 'content-type': 'application/json', ...(token ? { authorization: 'Bearer ' + token } : {}) }, body: JSON.stringify(body ?? {}) });
  const json = await r.json().catch(() => ({}));
  return { status: r.status, json, info: `HTTP ${r.status} ${json.error ?? ''}${json.stage ? ' stage=' + json.stage : ''}${json.ref ? ' ref=' + json.ref : ''}` };
};
const suffix = randomBytes(3).toString('hex');
const pw = () => randomBytes(18).toString('base64url');
const userA = { username: 'zz_test_a_' + suffix, password: pw() };
const userB = { username: 'zz_test_b_' + suffix, password: pw() };

const health = await fetch(base + '/api/health').then(r => r.json()).catch(() => ({}));
check('health endpoint ok', health.ok === true, JSON.stringify(health));
check('/api/me without token is 401', (await api('me')).status === 401);

const admin = await api('login', { username: ADMIN_USERNAME, password: ADMIN_PASSWORD });
check('admin login', admin.status === 200 && !!admin.json.access_token, admin.info);
if (admin.status !== 200) process.exit(1);
const me = await api('me', {}, admin.json.access_token);
check('admin /me reports role admin', me.json.role === 'admin', me.info);

const invite = async () => (await api('invitations', {}, admin.json.access_token)).json.code;
const inv1 = await invite(), inv2 = await invite(), inv3 = await invite();
check('admin can create invitations', !!inv1 && !!inv2 && !!inv3);

let r = await api('register', { ...userA, invite: inv1 });
check('register user A with invitation', r.status === 201 && r.json.role === 'user', r.info);
r = await api('register', { username: 'zz_test_r_' + suffix, password: pw(), invite: inv1 });
check('reused invitation is rejected', r.status === 403, r.info);
r = await api('register', { username: 'zz_test_x_' + suffix, password: pw(), invite: 'not-a-real-invitation' });
check('unknown invitation is rejected', r.status === 403, r.info);

// Race: two different usernames, one invitation, sent concurrently.
const [r1, r2] = await Promise.all([
  api('register', { ...userB, invite: inv2 }),
  api('register', { username: 'zz_test_c_' + suffix, password: pw(), invite: inv2 }),
]);
check('concurrent use of one invitation creates exactly one account', [r1.status, r2.status].filter(s => s === 201).length === 1 && [r1.status, r2.status].filter(s => s === 403 || s === 409).length === 1, `${r1.info} / ${r2.info}`);
const raceWinner = r1.status === 201 ? userB : null;
if (!raceWinner) {
  r = await api('register', { ...userB, invite: inv3 });
  check('register user B with fresh invitation', r.status === 201, r.info);
}

check('wrong password is rejected', (await api('login', { username: userA.username, password: 'wrong-password-123' })).status === 401);
const a = await api('login', userA), b = await api('login', userB);
check('user A and B can log in', a.status === 200 && b.status === 200, `${a.info} / ${b.info}`);
const ta = a.json.access_token, tb = b.json.access_token;
check('non-admin cannot create invitations', (await api('invitations', {}, tb)).status === 403);

const created = await api('blocks', { action: 'upsert', payload: { title: 'isolation probe' } }, ta);
check('user A creates a block', created.status === 201 && !!created.json.id, created.info);
const id = created.json.id;
const listB = await api('blocks', { action: 'list' }, tb);
check('user B cannot list user A blocks', listB.status === 200 && !listB.json.blocks.some(x => x.id === id), listB.info);
check('user B cannot update user A block', (await api('blocks', { action: 'upsert', id, payload: { title: 'hijack' } }, tb)).status === 404);
check('user B cannot delete user A block', (await api('blocks', { action: 'delete', id }, tb)).status === 404);
const listA = await api('blocks', { action: 'list' }, ta);
check('user A block unchanged', listA.json.blocks?.find(x => x.id === id)?.payload?.title === 'isolation probe', listA.info);
check('user A deletes own block', (await api('blocks', { action: 'delete', id }, ta)).status === 200);

const refreshed = await api('refresh', { refresh_token: a.json.refresh_token });
check('refresh token issues a new session', refreshed.status === 200 && !!refreshed.json.access_token, refreshed.info);
check('logout succeeds', (await api('logout', {}, refreshed.json.access_token)).status === 200);
check('refresh after logout is rejected', (await api('refresh', { refresh_token: refreshed.json.refresh_token })).status === 401);
check('invalid access token is rejected', (await api('me', {}, 'invalid.token.value')).status === 401);

console.log(`\n${failures ? failures + ' check(s) FAILED' : 'All checks passed'}. Test users: zz_test_*_${suffix} (see docs/AUTH_TEST_PLAN.md for cleanup).`);
process.exit(failures ? 1 : 0);
