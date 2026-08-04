-- Publishing and published-subject reads are served by protected Result RPCs.
alter table public.published_subjects enable row level security;
revoke all on table public.published_subjects from public, anon, authenticated;
drop policy if exists result_published_subjects_server_adapter_only on public.published_subjects;
create policy result_published_subjects_server_adapter_only
  on public.published_subjects for all to anon, authenticated
  using (false) with check (false);
