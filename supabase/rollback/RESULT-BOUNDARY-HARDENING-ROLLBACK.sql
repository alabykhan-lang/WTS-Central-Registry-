-- Controlled rollback notes for result_boundary_hardening.
-- Review with production owners before execution. This file deliberately does
-- not restore browser-held client credentials or legacy Result administration.

drop trigger if exists result_legacy_role_mutation_guard on public.user_profiles;
drop trigger if exists result_legacy_invite_mutation_guard on public.invite_codes;

revoke all on function public.school_staff_workspace_read_session_api(uuid, text) from public, anon, authenticated;
drop function if exists public.school_staff_workspace_read_session_api(uuid, text);

-- The four catalog rows are definitions, not grants. Only remove them after
-- confirming no active grant contains one of these permission codes.
delete from public.school_permission_catalog c
where c.permission_code in ('traits.enter', 'results.unpublish', 'result_users.manage', 'result_settings.manage')
  and not exists (
    select 1
    from public.school_access_grants g
    where c.permission_code = any(coalesce(g.permissions, array[]::text[]))
  );

-- The deployed Result function definitions must be restored from the exact
-- pre-migration backups captured with pg_get_functiondef before any function
-- rollback. Do not recreate the legacy browser authority from memory.
