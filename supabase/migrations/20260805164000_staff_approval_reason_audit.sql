-- Keep the management approval note in the audit details without changing
-- the existing staff registration table shape.
do $migration$
declare
  v_definition text;
  v_old text := $$  if v_category not in ('teaching','non_teaching','management','contract','casual') then
    return jsonb_build_object('ok', false, 'code', 'STAFF_CATEGORY_INVALID');
  end if;$$;
  v_new text := $$  if v_category not in ('teaching','non_teaching','management','contract','casual') then
    return jsonb_build_object('ok', false, 'code', 'STAFF_CATEGORY_INVALID');
  end if;
  v_reason := nullif(trim(coalesce(p_payload ->> 'reason', '')), '');
  if v_reason is null then v_reason := 'Approved after management review'; end if;$$;
begin
  select pg_get_functiondef(p.oid)
    into v_definition
  from pg_proc p
  join pg_namespace n on n.oid=p.pronamespace
  where n.nspname='public'
    and p.proname='school_staff_registration_management_session_api'
    and pg_get_function_identity_arguments(p.oid) =
      'p_session_id uuid, p_session_secret text, p_action text, p_payload jsonb';
  if v_definition is null or position(v_old in v_definition) = 0 then
    raise exception 'STAFF_APPROVAL_REASON_SHAPE_NOT_FOUND';
  end if;
  execute replace(v_definition, v_old, v_new);
end;
$migration$;
