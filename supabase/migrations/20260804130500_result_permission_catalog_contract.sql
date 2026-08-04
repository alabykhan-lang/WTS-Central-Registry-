-- Phase 3 Result permission contract.
-- These are named permission definitions, not user grants. Existing grants
-- and identities are preserved; management can assign only catalog entries.

insert into public.school_permission_catalog(
  permission_code, app_code, module_code, module_name, action_code, description
) values
  ('results.manage', 'results', 'results', 'Result administration', 'administer', 'Manage Result configuration and authorised Result administration.'),
  ('results.publish', 'results', 'result_contract', 'Result publishing', 'publish', 'Publish or unpublish approved Result subjects.'),
  ('scores.enter', 'results', 'result_contract', 'Score entry', 'create', 'Enter and update scores within assigned class and subject scope.'),
  ('remarks.enter', 'results', 'result_contract', 'Remarks entry', 'edit', 'Enter and update Result remarks within assigned class scope.'),
  ('results.view_assigned', 'results', 'result_contract', 'Assigned Result access', 'view', 'View Result data only within assigned class and subject scope.'),
  ('results.review', 'results', 'result_contract', 'Result review', 'review', 'Review submitted Result data within authorised scope.'),
  ('results.approve', 'results', 'result_contract', 'Result approval', 'approve', 'Approve Result data within authorised scope.'),
  ('results.export', 'results', 'result_contract', 'Result exports', 'export', 'Export authorised Result summaries and reports.'),
  ('users.manage', 'results', 'user_management', 'Result user administration', 'administer', 'Manage legacy Result profile administration through the central grant.'),
  ('report_cards.generate', 'results', 'report_cards', 'Report cards', 'create', 'Generate report cards within authorised scope.')
on conflict (permission_code) do nothing;

revoke all on table public.school_permission_catalog from public, anon, authenticated;
