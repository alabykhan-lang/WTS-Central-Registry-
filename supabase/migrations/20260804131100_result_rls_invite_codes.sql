-- Invite-code reads and rotation are served by protected Result RPCs.
alter table public.invite_codes enable row level security;
revoke all on table public.invite_codes from public, anon, authenticated;
drop policy if exists result_invite_codes_server_adapter_only on public.invite_codes;
create policy result_invite_codes_server_adapter_only
  on public.invite_codes for all to anon, authenticated
  using (false) with check (false);
