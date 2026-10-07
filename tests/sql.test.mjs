// Runs the real Supabase SQL scripts against an in-process Postgres (PGlite) with a stub auth schema.
// PGlite is single-connection, so true concurrency is not exercised here; see docs/AUTH_TEST_PLAN.md.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { PGlite } from '@electric-sql/pglite';
import { pgcrypto } from '@electric-sql/pglite/contrib/pgcrypto';

const db = new PGlite({ extensions: { pgcrypto } });
const sql = f => readFile(new URL('../supabase/' + f, import.meta.url), 'utf8');
const authUser = async () => { const id = randomUUID(); await db.query('insert into auth.users(id) values ($1)', [id]); return id; };
const register = async (user, username, inviteHash, bootstrap) =>
  (await db.query('select public.complete_registration($1,$2,$3,$4) as r', [user, username, inviteHash, bootstrap])).rows[0].r;
const count = async q => Number((await db.query(q)).rows[0].n);

before(async () => {
  await db.exec(`create role anon; create role authenticated; create role service_role;
    create schema auth; create table auth.users(id uuid primary key);`);
  for (const f of ['schema.sql', 'security-migration.sql', 'registration-migration.sql']) await db.exec(await sql(f));
  // Running the scripts twice must be safe (they are applied to a live database).
  for (const f of ['schema.sql', 'security-migration.sql', 'registration-migration.sql']) await db.exec(await sql(f));
});

test('invitation registration rejected before bootstrap with null hash', async () => {
  assert.equal(await register(await authUser(), 'nohash', null, false), 'invitation_invalid');
});

test('bootstrap creates the single admin, then closes', async () => {
  assert.equal(await register(await authUser(), 'admin_one', null, true), 'ok');
  assert.equal((await db.query(`select role from public.profiles where username='admin_one'`)).rows[0].role, 'admin');
  assert.equal(await register(await authUser(), 'admin_two', null, true), 'bootstrap_closed');
  assert.equal(await count(`select count(*) n from public.profiles where role='admin'`), 1);
});

test('invitation is single use and failed claim leaves no profile', async () => {
  const admin = (await db.query(`select id from public.profiles where username='admin_one'`)).rows[0].id;
  await db.query(`insert into public.invitations(code_hash, created_by, expires_at) values ('h1', $1, now() + interval '1 day')`, [admin]);
  const a = await authUser(), b = await authUser();
  assert.equal(await register(a, 'user_a', 'h1', false), 'ok');
  assert.equal(await register(b, 'user_b', 'h1', false), 'invitation_invalid');
  assert.equal(await count(`select count(*) n from public.profiles where username='user_b'`), 0);
  const inv = (await db.query(`select used_by from public.invitations where code_hash='h1'`)).rows[0];
  assert.equal(inv.used_by, a);
});

test('expired, revoked and unknown invitations are rejected', async () => {
  const admin = (await db.query(`select id from public.profiles where username='admin_one'`)).rows[0].id;
  await db.query(`insert into public.invitations(code_hash, created_by, expires_at) values ('expired', $1, now() - interval '1 second')`, [admin]);
  await db.query(`insert into public.invitations(code_hash, created_by, expires_at, revoked_at) values ('revoked', $1, now() + interval '1 day', now())`, [admin]);
  for (const h of ['expired', 'revoked', 'unknown']) assert.equal(await register(await authUser(), 'user_' + h, h, false), 'invitation_invalid');
  assert.equal(await count(`select count(*) n from public.profiles where username like 'user_%' and username <> 'user_a'`), 0);
});

test('duplicate username does not consume the invitation', async () => {
  const admin = (await db.query(`select id from public.profiles where username='admin_one'`)).rows[0].id;
  await db.query(`insert into public.invitations(code_hash, created_by, expires_at) values ('h2', $1, now() + interval '1 day')`, [admin]);
  assert.equal(await register(await authUser(), 'user_a', 'h2', false), 'username_taken');
  assert.equal((await db.query(`select used_at from public.invitations where code_hash='h2'`)).rows[0].used_at, null);
});

test('deleting a user who used an invitation keeps the invitation consumed', async () => {
  const id = (await db.query(`select id from public.profiles where username='user_a'`)).rows[0].id;
  await db.query('delete from auth.users where id=$1', [id]);
  const inv = (await db.query(`select used_by, used_at from public.invitations where code_hash='h1'`)).rows[0];
  assert.equal(inv.used_by, null);
  assert.notEqual(inv.used_at, null);
  assert.equal(await register(await authUser(), 'user_c', 'h1', false), 'invitation_invalid');
});

test('rate limiter allows exactly p_limit attempts per window', async () => {
  const results = [];
  for (let i = 0; i < 5; i++) results.push((await db.query(`select public.check_auth_rate('b1', 3, 900) as ok`)).rows[0].ok);
  assert.deepEqual(results, [true, true, true, false, false]);
});

test('browser roles cannot execute the security-definer functions', async () => {
  for (const fn of ['complete_registration(uuid,text,text,boolean)', 'check_auth_rate(text,integer,integer)', 'claim_invitation(text,uuid)']) {
    for (const role of ['anon', 'authenticated']) {
      const r = await db.query(`select has_function_privilege($1, 'public.${fn}', 'execute') as ok`, [role]);
      assert.equal(r.rows[0].ok, false, `${role} can execute ${fn}`);
    }
    const s = await db.query(`select has_function_privilege('service_role', 'public.${fn}', 'execute') as ok`);
    assert.equal(s.rows[0].ok, true);
  }
  for (const t of ['profiles', 'invitations', 'calendar_blocks']) {
    assert.equal((await db.query(`select has_table_privilege('anon', 'public.${t}', 'select') as ok`)).rows[0].ok, false);
    assert.equal((await db.query(`select has_table_privilege('service_role', 'public.${t}', 'insert') as ok`)).rows[0].ok, true);
  }
});
