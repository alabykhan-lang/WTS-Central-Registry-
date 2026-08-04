-- Student reads and administration are served by protected Result RPCs.
alter table public.students enable row level security;
revoke all on table public.students from public, anon, authenticated;
drop policy if exists result_students_server_adapter_only on public.students;
create policy result_students_server_adapter_only
  on public.students for all to anon, authenticated
  using (false) with check (false);
