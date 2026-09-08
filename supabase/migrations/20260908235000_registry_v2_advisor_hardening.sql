-- Resolve the Registry v2 advisor warning and retire direct execution of the
-- legacy session RPCs now that the corresponding HTTP routes return 410.

alter function wts_internal.school_registry_has_capability(jsonb,text)
  set search_path to 'pg_catalog', 'extensions', 'public';

do $migration$
declare
  v_function regprocedure;
begin
  for v_function in
    select p.oid::regprocedure
    from pg_proc p
    join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public'
      and p.proname in (
        'school_registry_access_write_api',
        'school_registry_admin_read_session_api',
        'school_registry_guardian_write_session_api',
        'school_registry_staff_write_session_api',
        'school_registry_student_write_session_api'
      )
  loop
    execute format('revoke execute on function %s from public, anon, authenticated', v_function);
  end loop;
end
$migration$;
