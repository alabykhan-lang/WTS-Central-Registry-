-- Specialist action permissions stay inside each specialist module.
-- Central Registry neither returns those permissions to its UI nor accepts a
-- browser-supplied replacement for an existing module's permission set.
do $migration$
declare
  v_definition text;
  v_old text := $$    select to_jsonb(g) into v_before
    from public.school_access_grants g
    where g.person_id = v_person_id and g.app_code = v_app_code;$$;
  v_new text := $$    select to_jsonb(g) into v_before
    from public.school_access_grants g
    where g.person_id = v_person_id and g.app_code = v_app_code;
    if v_app_code <> 'staff_self_service' then
      select coalesce(array_agg(value), array[]::text[])
        into v_permissions
      from jsonb_array_elements_text(coalesce(v_before -> 'permissions', '[]'::jsonb)) value;
    end if;$$;
begin
  select pg_get_functiondef(p.oid)
    into v_definition
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public'
    and p.proname = 'school_access_management_write_session_api'
    and pg_get_function_identity_arguments(p.oid) =
      'p_session_id uuid, p_session_secret text, p_action text, p_payload jsonb';
  if v_definition is null or position(v_old in v_definition) = 0 then
    raise exception 'CENTRAL_ACCESS_WRITE_PERMISSION_PRESERVATION_SHAPE_NOT_FOUND';
  end if;
  execute replace(v_definition, v_old, v_new);
end;
$migration$;
do $migration$
declare
  v_definition text;
  v_old text := $$        'id', g.id, 'app_code', g.app_code, 'access_role', g.access_role, 'permissions', g.permissions,
        'grant_status'$$;
  v_new text := $$        'id', g.id, 'app_code', g.app_code, 'access_role', g.access_role,
        'grant_status'$$;
begin
  select pg_get_functiondef(p.oid)
    into v_definition
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public'
    and p.proname = 'school_access_management_scope_read_session_api'
    and pg_get_function_identity_arguments(p.oid) =
      'p_session_id uuid, p_session_secret text, p_action text, p_payload jsonb';
  if v_definition is null or position(v_old in v_definition) = 0 then
    raise exception 'CENTRAL_SCOPE_READ_MODULE_PERMISSION_SHAPE_NOT_FOUND';
  end if;
  execute replace(v_definition, v_old, v_new);
end;
$migration$;
