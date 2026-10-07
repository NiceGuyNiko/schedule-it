-- Run AFTER schema.sql and security-migration.sql. Non-destructive: only (re)defines functions and grants.

-- The backend uses the service_role key. Grant it table access explicitly instead of relying on
-- project default privileges, which differ between Supabase projects and caused "permission denied".
grant usage on schema public to service_role;
grant select, insert, update, delete on public.profiles, public.invitations, public.calendar_blocks, public.auth_attempts to service_role;

-- Deleting a user previously failed if they had used or created an invitation. Keep the invitation
-- row (used_at still marks it consumed) and clear the reference instead.
alter table public.invitations drop constraint if exists invitations_used_by_fkey;
alter table public.invitations add constraint invitations_used_by_fkey foreign key (used_by) references public.profiles(id) on delete set null;
alter table public.invitations drop constraint if exists invitations_created_by_fkey;
alter table public.invitations add constraint invitations_created_by_fkey foreign key (created_by) references public.profiles(id) on delete set null;

-- Profile creation and invitation claim in ONE transaction. Concurrent registrations with the same
-- invitation serialize on the invitation row; the loser's profile insert is rolled back with it.
-- Bootstrap registrations serialize on an advisory lock and succeed only while no profile exists.
-- Returns 'ok', 'username_taken', 'invitation_invalid' or 'bootstrap_closed'.
create or replace function public.complete_registration(p_user uuid, p_username text, p_invite_hash text, p_bootstrap boolean)
returns text language plpgsql security definer set search_path = '' as $$
begin
  if p_bootstrap then
    perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('schedule-it:bootstrap'));
    if exists (select 1 from public.profiles) then return 'bootstrap_closed'; end if;
  elsif p_invite_hash is null then
    return 'invitation_invalid';
  end if;
  begin
    insert into public.profiles(id, username, role)
    values (p_user, p_username, case when p_bootstrap then 'admin' else 'user' end);
    if not p_bootstrap then
      update public.invitations set used_by = p_user, used_at = now()
       where code_hash = p_invite_hash and used_at is null and revoked_at is null and expires_at > now();
      if not found then raise exception 'invitation_invalid'; end if;
    end if;
  exception
    when unique_violation then return 'username_taken';
    when raise_exception then return 'invitation_invalid';
  end;
  return 'ok';
end; $$;
revoke all on function public.complete_registration(uuid,text,text,boolean) from public, anon, authenticated;
grant execute on function public.complete_registration(uuid,text,text,boolean) to service_role;

-- Same contract as before; additionally prunes attempts older than a day so the table stays small.
create or replace function public.check_auth_rate(p_bucket text, p_limit integer, p_window_seconds integer)
returns boolean language plpgsql security definer set search_path = '' as $$
declare n integer;
begin
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext(p_bucket));
  delete from public.auth_attempts where created_at < now() - interval '1 day';
  select count(*) into n from public.auth_attempts
   where bucket = p_bucket and created_at > now() - make_interval(secs => p_window_seconds);
  if n >= p_limit then return false; end if;
  insert into public.auth_attempts(bucket) values (p_bucket);
  return true;
end; $$;
revoke all on function public.check_auth_rate(text,integer,integer) from public, anon, authenticated;
grant execute on function public.check_auth_rate(text,integer,integer) to service_role;
