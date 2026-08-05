-- Central Registry exposes module entry choices, not specialist-module
-- technical permission catalogs.
do $migration$
declare
  v_definition text;
  v_old text := $$      'permissions', coalesce((select jsonb_agg(jsonb_build_object('permission_code', permission_code, 'app_code', app_code, 'module_code', module_code, 'module_name', module_name, 'action_code', action_code, 'description', description) order by app_code, module_name, action_code) from public.school_permission_catalog), '[]'::jsonb),$$;
begin
  select pg_get_functiondef(p.oid)
    into v_definition
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public'
    and p.proname = 'school_access_management_scope_read_session_api'
    and pg_get_function_identity_arguments(p.oid) =
      'p_session_id uuid, p_session_secret text, p_action text, p_payload jsonb';
  if v_definition is null then
    raise exception 'CENTRAL_SCOPE_READ_FUNCTION_NOT_FOUND';
  end if;
  if position(v_old in v_definition) = 0 then
    raise exception 'CENTRAL_SCOPE_READ_PERMISSION_CATALOG_SHAPE_NOT_FOUND';
  end if;
  v_definition := replace(v_definition, v_old, $$      'permissions', '[]'::jsonb,$$);
  execute v_definition;
end;
$migration$;
