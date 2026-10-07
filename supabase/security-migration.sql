-- Run AFTER schema.sql. Atomic invitation claiming prevents concurrent reuse.
create or replace function public.claim_invitation(p_hash text, p_user uuid)
returns boolean language plpgsql security definer set search_path = '' as $$
declare n integer;
begin
 update public.invitations
 set used_by=p_user, used_at=now()
 where code_hash=p_hash and used_at is null and revoked_at is null and expires_at>now();
 get diagnostics n = row_count;
 return n=1;
end; $$;
revoke all on function public.claim_invitation(text,uuid) from public, anon, authenticated;
grant execute on function public.claim_invitation(text,uuid) to service_role;

-- Bootstrap admin uniqueness, even during concurrent requests.
create unique index if not exists profiles_one_admin_bootstrap on public.profiles ((role)) where role='admin';
