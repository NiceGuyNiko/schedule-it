// Handler tests with Supabase's HTTP APIs replaced by an in-memory fake (no network, no real credentials).
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

const PASSWORD = 'correct horse battery';
const INVITE = 'invite-code-under-test';
const BOOTSTRAP = 'bootstrap-code-under-test';
let routes, calls, logs;

const reply = (status, body, headers = {}) => new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
globalThis.fetch = async (input, init = {}) => {
  const url = new URL(typeof input === 'string' ? input : input.url);
  const method = (init.method || 'GET').toUpperCase();
  const key = `${method} ${url.pathname}`;
  calls.push({ key, body: init.body });
  const route = routes[key];
  if (!route) throw new Error('Unexpected request ' + key);
  return route({ url, init, body: init.body ? JSON.parse(init.body) : undefined });
};
console.error = (...args) => logs.push(args.join(' '));

const { handler } = await import('../netlify/functions/api.mjs');
const call = (route, body, { method = 'POST', token, raw } = {}) => handler({
  httpMethod: method, path: '/.netlify/functions/api/' + route,
  headers: { 'x-nf-client-connection-ip': '203.0.113.9', ...(token ? { authorization: 'Bearer ' + token } : {}) },
  body: raw ?? JSON.stringify(body),
}).then(r => ({ ...r, json: JSON.parse(r.body) }));
const hit = key => calls.filter(c => c.key === key).length;

const ok = {
  rate: () => reply(200, true),
  createUser: () => reply(200, { id: '11111111-1111-4111-8111-111111111111', email: 'x@accounts.schedule-it.invalid' }),
  deleteUser: () => reply(200, {}),
  noProfiles: () => reply(200, undefined, { 'content-range': '*/0' }),
  invitation: () => reply(200, [{ id: 'inv' }]),
};

beforeEach(() => {
  process.env.SUPABASE_URL = 'https://example.supabase.co';
  process.env.SUPABASE_SECRET_KEY = 'sb_secret_test_value';
  process.env.BOOTSTRAP_INVITE_CODE = BOOTSTRAP;
  calls = []; logs = [];
  routes = {
    'POST /rest/v1/rpc/check_auth_rate': ok.rate,
    'POST /auth/v1/admin/users': ok.createUser,
    'DELETE /auth/v1/admin/users/11111111-1111-4111-8111-111111111111': ok.deleteUser,
    'HEAD /rest/v1/profiles': ok.noProfiles,
    'GET /rest/v1/invitations': ok.invitation,
    'POST /rest/v1/rpc/complete_registration': () => reply(200, 'ok'),
  };
});

test('GET is rejected; missing configuration returns 503', async () => {
  assert.equal((await call('me', {}, { method: 'GET' })).statusCode, 405);
  delete process.env.SUPABASE_SECRET_KEY;
  const r = await call('register', {});
  assert.equal(r.statusCode, 503);
  assert.match(logs.join('\n'), /not set/);
});

test('publishable or anon key is detected as misconfiguration before any request', async () => {
  process.env.SUPABASE_SECRET_KEY = 'sb_publishable_abc';
  assert.equal((await call('register', { username: 'abc', password: PASSWORD, invite: INVITE })).statusCode, 503);
  const anonJwt = ['x', Buffer.from(JSON.stringify({ role: 'anon' })).toString('base64url'), 'y'].join('.');
  process.env.SUPABASE_SECRET_KEY = anonJwt;
  assert.equal((await call('register', { username: 'abc', password: PASSWORD, invite: INVITE })).statusCode, 503);
  assert.match(logs.join('\n'), /legacy .*anon.* JWT/);
  assert.equal(calls.length, 0);
});

test('database permission failure reports the failing stage and logs no secrets', async () => {
  routes['POST /rest/v1/rpc/check_auth_rate'] = () => reply(403, { code: '42501', message: 'permission denied for function check_auth_rate' });
  const r = await call('register', { username: 'abc', password: PASSWORD, invite: BOOTSTRAP });
  assert.equal(r.statusCode, 500);
  assert.equal(r.json.stage, 'rate limit (register)');
  assert.match(r.json.ref, /^[0-9a-f]{8}$/);
  const log = logs.join('\n');
  assert.match(log, /42501/);
  assert.match(log, new RegExp(r.json.ref));
  for (const secret of [PASSWORD, BOOTSTRAP, 'sb_secret_test_value']) assert.ok(!log.includes(secret));
});

test('invalid registration input is rejected without touching the database', async () => {
  for (const body of [{}, { username: 'AB', password: PASSWORD, invite: INVITE }, { username: 'abc', password: 'short', invite: INVITE }, { username: 'abc', password: PASSWORD, invite: '' }]) {
    assert.equal((await call('register', body)).statusCode, 400);
  }
  assert.equal((await call('register', null, { raw: '[1]' })).statusCode, 400);
  assert.equal(calls.length, 0);
});

test('bootstrap registration creates an admin', async () => {
  const r = await call('register', { username: 'admin', password: PASSWORD, invite: BOOTSTRAP });
  assert.equal(r.statusCode, 201);
  assert.equal(r.json.role, 'admin');
  const rpc = calls.find(c => c.key === 'POST /rest/v1/rpc/complete_registration');
  assert.deepEqual(JSON.parse(rpc.body), { p_user: '11111111-1111-4111-8111-111111111111', p_username: 'admin', p_invite_hash: null, p_bootstrap: true });
});

test('bootstrap is refused once any profile exists, before creating an auth user', async () => {
  routes['HEAD /rest/v1/profiles'] = () => reply(200, undefined, { 'content-range': '*/1' });
  assert.equal((await call('register', { username: 'admin2', password: PASSWORD, invite: BOOTSTRAP })).statusCode, 403);
  assert.equal(hit('POST /auth/v1/admin/users'), 0);
});

test('unknown invitation is refused before creating an auth user', async () => {
  routes['GET /rest/v1/invitations'] = () => reply(200, []);
  assert.equal((await call('register', { username: 'bob', password: PASSWORD, invite: INVITE })).statusCode, 403);
  assert.equal(hit('POST /auth/v1/admin/users'), 0);
});

test('invitation lookup failure is a server error, not "Invitation invalid"', async () => {
  routes['GET /rest/v1/invitations'] = () => reply(403, { code: '42501', message: 'permission denied for table invitations' });
  const r = await call('register', { username: 'bob', password: PASSWORD, invite: INVITE });
  assert.equal(r.statusCode, 500);
  assert.equal(r.json.stage, 'invitation lookup');
});

test('losing an invitation race rolls back the auth user', async () => {
  routes['POST /rest/v1/rpc/complete_registration'] = () => reply(200, 'invitation_invalid');
  assert.equal((await call('register', { username: 'bob', password: PASSWORD, invite: INVITE })).statusCode, 403);
  assert.equal(hit('DELETE /auth/v1/admin/users/11111111-1111-4111-8111-111111111111'), 1);
});

test('registration RPC failure rolls back and surfaces the stage; failed rollback is logged', async () => {
  routes['POST /rest/v1/rpc/complete_registration'] = () => reply(404, { code: 'PGRST202', message: 'Could not find the function public.complete_registration' });
  routes['DELETE /auth/v1/admin/users/11111111-1111-4111-8111-111111111111'] = () => reply(500, { msg: 'boom' });
  const r = await call('register', { username: 'bob', password: PASSWORD, invite: INVITE });
  assert.equal(r.statusCode, 500);
  assert.equal(r.json.stage, 'complete registration');
  assert.match(logs.join('\n'), /orphan auth user/);
  assert.match(logs.join('\n'), /PGRST202/);
});

test('existing username maps to 409; other auth admin errors are server errors', async () => {
  routes['POST /auth/v1/admin/users'] = () => reply(422, { error_code: 'email_exists', msg: 'exists' });
  assert.equal((await call('register', { username: 'bob', password: PASSWORD, invite: INVITE })).statusCode, 409);
  routes['POST /auth/v1/admin/users'] = () => reply(403, { error_code: 'not_admin', msg: 'User not allowed' });
  const r = await call('register', { username: 'bob', password: PASSWORD, invite: INVITE });
  assert.equal(r.statusCode, 500);
  assert.equal(r.json.stage, 'create auth user');
});

test('login, refresh and logout', async () => {
  const tokens = { access_token: 'at', refresh_token: 'rt', expires_in: 3600, expires_at: 2000000000, token_type: 'bearer', user: { id: 'u' } };
  routes['POST /auth/v1/token'] = ({ url, body }) => url.searchParams.get('grant_type') === 'password'
    ? (body.password === PASSWORD ? reply(200, tokens) : reply(400, { error_code: 'invalid_credentials', msg: 'Invalid login credentials' }))
    : (body.refresh_token === 'rt' ? reply(200, { ...tokens, access_token: 'at2' }) : reply(400, { error_code: 'refresh_token_not_found', msg: 'Invalid Refresh Token' }));
  assert.equal((await call('login', { username: 'bob', password: 'wrong password' })).statusCode, 401);
  const login = await call('login', { username: 'bob', password: PASSWORD });
  assert.deepEqual(login.json, { access_token: 'at', refresh_token: 'rt', expires_at: 2000000000 });
  assert.equal((await call('refresh', { refresh_token: 'rt' })).json.access_token, 'at2');
  assert.equal((await call('refresh', { refresh_token: 'stale' })).statusCode, 401);
  routes['GET /auth/v1/user'] = () => reply(200, { id: 'u' });
  routes['POST /auth/v1/logout'] = ({ url }) => { assert.equal(url.searchParams.get('scope'), 'local'); return reply(204); };
  assert.equal((await call('logout', {}, { token: 'at' })).statusCode, 200);
  assert.equal(hit('POST /auth/v1/logout'), 1);
});

test('login rate limit returns 429', async () => {
  routes['POST /rest/v1/rpc/check_auth_rate'] = () => reply(200, false);
  assert.equal((await call('login', { username: 'bob', password: PASSWORD })).statusCode, 429);
});

test('authenticated routes: 401 without token, admin gate, block ownership filters', async () => {
  assert.equal((await call('me', {})).statusCode, 401);
  routes['GET /auth/v1/user'] = () => reply(200, { id: 'user-b' });
  routes['GET /rest/v1/profiles'] = () => reply(200, [{ username: 'bob', role: 'user' }]);
  assert.equal((await call('invitations', {}, { token: 't' })).statusCode, 403);
  assert.equal((await call('blocks', { action: 'delete', id: 'not-a-uuid' }, { token: 't' })).statusCode, 400);
  routes['DELETE /rest/v1/calendar_blocks'] = ({ url }) => { assert.equal(url.searchParams.get('user_id'), 'eq.user-b'); return reply(200, []); };
  assert.equal((await call('blocks', { action: 'delete', id: '22222222-2222-4222-8222-222222222222' }, { token: 't' })).statusCode, 404);
  routes['PATCH /rest/v1/calendar_blocks'] = ({ url }) => { assert.equal(url.searchParams.get('user_id'), 'eq.user-b'); return reply(200, []); };
  assert.equal((await call('blocks', { action: 'upsert', id: '22222222-2222-4222-8222-222222222222', payload: { a: 1 } }, { token: 't' })).statusCode, 404);
});

test('health endpoint reports config and database status without detail', async () => {
  routes['HEAD /rest/v1/profiles'] = () => reply(200, undefined, { 'content-range': '*/0' });
  assert.deepEqual((await call('health', undefined, { method: 'GET' })).json, { ok: true });
  routes['HEAD /rest/v1/profiles'] = () => reply(401, undefined);
  const r = await call('health', undefined, { method: 'GET' });
  assert.equal(r.statusCode, 503);
  assert.equal(r.json.stage, 'database');
});
