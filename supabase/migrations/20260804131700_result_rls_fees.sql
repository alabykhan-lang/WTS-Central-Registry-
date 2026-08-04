-- Fee reads and writes are served by protected Result RPCs.
alter table public.fees enable row level security;
revoke all on table public.fees from public, anon, authenticated;
drop policy if exists result_fees_server_adapter_only on public.fees;
create policy result_fees_server_adapter_only
  on public.fees for all to anon, authenticated
  using (false) with check (false);
