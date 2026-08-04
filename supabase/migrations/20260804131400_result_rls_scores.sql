-- Score reads and writes are served by protected Result RPCs.
alter table public.scores enable row level security;
revoke all on table public.scores from public, anon, authenticated;
drop policy if exists result_scores_server_adapter_only on public.scores;
create policy result_scores_server_adapter_only
  on public.scores for all to anon, authenticated
  using (false) with check (false);
