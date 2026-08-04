-- Expose only session-validated Result adapters to the public REST role.
-- These functions do not trust the caller role; every request validates the
-- WTS identity session, employment, grant, permission and scope first.
grant execute on function public.school_result_read_api(uuid, text, text, jsonb) to anon;
grant execute on function public.school_result_traits_update(uuid, text, uuid, text, text, text, text, text, integer) to anon;
grant execute on function public.school_result_remarks_update(uuid, text, uuid, text, text, text, text, text, text, integer, integer) to anon;

create or replace function public.school_access_management_scope_read_api(
  p_client_code text,
  p_client_secret text,
  p_action text,
  p_payload jsonb default '{}'::jsonb
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_result jsonb;
  v_staff_id uuid;
  v_person_id uuid;
  v_context jsonb;
begin
  if lower(trim(coalesce(p_action, ''))) not in ('catalog', 'staffaccessprofile') then
    return jsonb_build_object('ok', false, 'code', 'UNKNOWN_ACTION');
  end if;

  v_result := public.school_access_management_read_api(p_client_code, p_client_secret, p_action, p_payload);
  if coalesce((v_result ->> 'ok')::boolean, false) is not true then
    return v_result;
  end if;

  select jsonb_build_object(
    'academic_session', (select value from public.settings where key = 'session'),
    'term', (select value from public.settings where key = 'term')
  ) into v_context;

  if lower(trim(coalesce(p_action, ''))) = 'catalog' then
    return v_result || jsonb_build_object('result_context', v_context);
  end if;

  begin
    v_staff_id := (p_payload ->> 'staffId')::uuid;
  exception when others then
    return jsonb_build_object('ok', false, 'code', 'INVALID_STAFF_ID');
  end;
  select central_person_id into v_person_id
  from public.staff_attendance_profiles
  where id = v_staff_id;
  if v_person_id is null then
    return jsonb_build_object('ok', false, 'code', 'STAFF_IDENTITY_NOT_LINKED');
  end if;

  return v_result || jsonb_build_object(
    'result_context', v_context,
    'scopes', coalesce((
      select jsonb_agg(jsonb_build_object(
        'id', s.id,
        'app_code', s.app_code,
        'scope_type', s.scope_type,
        'class_key', s.class_key,
        'display_name', c.display_name,
        'subject_index', s.subject_index,
        'subject_name', r.subject_name,
        'scope_status', s.scope_status,
        'effective_from', s.effective_from,
        'effective_until', s.effective_until,
        'reason', s.reason,
        'revoked_at', s.revoked_at,
        'revocation_reason', s.revocation_reason,
        'academic_session', s.metadata ->> 'academic_session',
        'term', s.metadata ->> 'term'
      ) order by s.app_code, c.display_name, s.subject_index nulls first)
      from public.school_staff_access_scopes s
      join public.school_classes c on c.class_key = s.class_key
      left join public.result_subject_catalog r
        on r.class_key = s.class_key and r.subject_index = s.subject_index
      where s.person_id = v_person_id
    ), '[]'::jsonb)
  );
end;
$function$;

revoke all on function public.school_access_management_scope_read_api(text, text, text, jsonb) from public, authenticated;
grant execute on function public.school_access_management_scope_read_api(text, text, text, jsonb) to anon;

-- Four-argument wrapper used by the existing Central Registry RPC client.
-- The three-argument implementation remains the single write path.
create or replace function public.school_access_management_scope_write_api(
  p_client_code text,
  p_client_secret text,
  p_action text,
  p_payload jsonb default '{}'::jsonb
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
begin
  if lower(trim(coalesce(p_action, ''))) <> 'setscope' then
    return jsonb_build_object('ok', false, 'code', 'UNKNOWN_ACTION');
  end if;
  return public.school_access_management_scope_write_api(p_client_code, p_client_secret, p_payload);
end;
$function$;

revoke all on function public.school_access_management_scope_write_api(text, text, text, jsonb) from public, authenticated;
grant execute on function public.school_access_management_scope_write_api(text, text, text, jsonb) to anon;