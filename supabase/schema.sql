-- Run in Supabase SQL Editor. Backend uses service-role access only.
create extension if not exists pgcrypto;
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text not null unique check (username ~ '^[a-z0-9_]{3,24}$'),
  role text not null default 'user' check (role in ('user','admin')),
  created_at timestamptz not null default now()
);
create table if not exists public.invitations (
  id uuid primary key default gen_random_uuid(),
  code_hash text not null unique,
  created_by uuid references public.profiles(id),
  used_by uuid references public.profiles(id),
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  used_at timestamptz,
  revoked_at timestamptz
);
create table if not exists public.calendar_blocks (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  payload jsonb not null check (jsonb_typeof(payload) = 'object'),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists calendar_blocks_owner on public.calendar_blocks(user_id);
create table if not exists public.auth_attempts (
  id bigint generated always as identity primary key,
  bucket text not null,
  created_at timestamptz not null default now()
);
create index if not exists auth_attempts_lookup on public.auth_attempts(bucket,created_at);
create or replace function public.check_auth_rate(p_bucket text, p_limit integer, p_window_seconds integer)
returns boolean language plpgsql security definer set search_path = '' as $$
declare n integer;
begin
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext(p_bucket));
  select count(*) into n from public.auth_attempts
   where bucket=p_bucket and created_at > now()-make_interval(secs=>p_window_seconds);
  if n >= p_limit then return false; end if;
  insert into public.auth_attempts(bucket) values (p_bucket);
  return true;
end; $$;
revoke all on function public.check_auth_rate(text,integer,integer) from public, anon, authenticated;
grant execute on function public.check_auth_rate(text,integer,integer) to service_role;
alter table public.profiles enable row level security;
alter table public.invitations enable row level security;
alter table public.calendar_blocks enable row level security;
alter table public.auth_attempts enable row level security;
-- No public policies: browser clients cannot query private data.
revoke all on public.profiles, public.invitations, public.calendar_blocks, public.auth_attempts from anon, authenticated;
