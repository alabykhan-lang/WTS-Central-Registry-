-- Trait reads and writes are served by protected Result RPCs.
alter table public.traits enable row level security;
revoke all on table public.traits from public, anon, authenticated;
drop policy if exists result_traits_server_adapter_only on public.traits;
create policy result_traits_server_adapter_only
  on public.traits for all to anon, authenticated
  using (false) with check (false);
