-- Result settings are read and updated by protected server-side adapters.
alter table public.settings enable row level security;
revoke all on table public.settings from public, anon, authenticated;
drop policy if exists result_settings_server_adapter_only on public.settings;
create policy result_settings_server_adapter_only
  on public.settings for all to anon, authenticated
  using (false) with check (false);
