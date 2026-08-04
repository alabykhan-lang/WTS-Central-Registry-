-- Result profile reads and writes are served by protected Result RPCs.
alter table public.user_profiles enable row level security;
revoke all on table public.user_profiles from public, anon, authenticated;
drop policy if exists result_user_profiles_server_adapter_only on public.user_profiles;
create policy result_user_profiles_server_adapter_only
  on public.user_profiles for all to anon, authenticated
  using (false) with check (false);
