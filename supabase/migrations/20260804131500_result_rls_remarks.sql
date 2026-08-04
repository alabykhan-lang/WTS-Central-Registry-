-- Remarks reads and writes are served by protected Result RPCs.
alter table public.remarks enable row level security;
revoke all on table public.remarks from public, anon, authenticated;
drop policy if exists result_remarks_server_adapter_only on public.remarks;
create policy result_remarks_server_adapter_only
  on public.remarks for all to anon, authenticated
  using (false) with check (false);
