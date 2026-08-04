-- Route new Central Registry management actions through the secure identity
-- session. Legacy client-code adapters remain available for rollback only.

create or replace function wts_internal.central_management_actor(
  p_session jsonb
)
returns uuid
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_permissions text[];
  v_actor uuid;
begin
  if coalesce((p_session ->> 'ok')::boolean, false) is not true then
    return null;
  end if;
  select coalesce(array(select jsonb_array_elements_text(p_session -> 'permissions')), array[]::text[])
    into v_permissions;
  if not (v_permissions && array[
    'central_registry.administer',
    'staff_management.administer',
    'system_administration.administer'
  ]::text[]) then
    return null;
  end if;
  begin
    v_actor := (p_session ->> 'person_id')::uuid;
  exception when others then
    return null;
  end;
  return v_actor;
end;
$function$;

revoke all on function wts_internal.central_management_actor(jsonb) from public, anon, authenticated;

create or replace function public.school_access_management_scope_read_session_api(
  p_session_id uuid,
  p_session_secret text,
  p_action text,
  p_payload jsonb default '{}'::jsonb
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_session jsonb;
  v_actor_person_id uuid;
  v_staff_id uuid;
  v_person_id uuid;
  v_search text := lower(trim(coalesce(p_payload ->> 'search', '')));
begin
  v_session := public.school_identity_session_validate(p_session_id, p_session_secret, 'central_registry');
  if coalesce((v_session ->> 'ok')::boolean, false) is not true then
    return v_session;
  end if;
  v_actor_person_id := wts_internal.central_management_actor(v_session);
  if v_actor_person_id is null then
    return jsonb_build_object('ok', false, 'code', 'MANAGEMENT_ACCESS_DENIED');
  end if;

  if p_action = 'catalog' then
    return jsonb_build_object(
      'ok', true,
      'roles', coalesce((select jsonb_agg(jsonb_build_object('role_code', role_code, 'role_name', role_name, 'description', description) order by role_name) from public.school_system_role_catalog where is_assignable), '[]'::jsonb),
      'permissions', coalesce((select jsonb_agg(jsonb_build_object('permission_code', permission_code, 'app_code', app_code, 'module_code', module_code, 'module_name', module_name, 'action_code', action_code, 'description', description) order by app_code, module_name, action_code) from public.school_permission_catalog), '[]'::jsonb),
      'portals', coalesce((select jsonb_agg(jsonb_build_object('app_code', app_code, 'app_name', app_name, 'default_roles', default_roles) order by app_name) from public.school_portal_catalog where is_active), '[]'::jsonb),
      'classes', coalesce((select jsonb_agg(jsonb_build_object('class_key', class_key, 'display_name', display_name, 'sort_order', sort_order) order by sort_order, display_name) from public.school_classes where is_active), '[]'::jsonb),
      'subjects', coalesce((select jsonb_agg(jsonb_build_object('class_key', class_key, 'subject_index', subject_index, 'subject_name', subject_name) order by class_key, subject_index) from public.result_subject_catalog where active), '[]'::jsonb),
      'result_context', jsonb_build_object('academic_session', (select value from public.settings where key = 'session'), 'term', (select value from public.settings where key = 'term'))
    );
  end if;

  if p_action = 'staff' then
    return jsonb_build_object(
      'ok', true,
      'staff', coalesce((
        select jsonb_agg(to_jsonb(x) order by x.full_name) from (
          select s.id as staff_id, s.central_person_id as person_id, s.staff_number,
            s.full_name, s.designation, s.staff_category, s.department,
            s.employment_status, s.registration_status, i.account_status,
            coalesce((select count(*) from public.school_access_grants g
              where g.person_id = s.central_person_id and g.grant_status = 'active'
                and (g.valid_from is null or g.valid_from <= now())
                and (g.valid_until is null or g.valid_until > now())), 0) as active_module_count
          from public.staff_attendance_profiles s
          join public.school_identity_accounts i on i.person_id = s.central_person_id
          where s.central_person_id is not null
            and s.registration_status = 'active' and s.employment_status = 'active'
            and (v_search = '' or lower(s.full_name) like '%' || v_search || '%'
              or lower(coalesce(s.staff_number, '')) like '%' || v_search || '%')
          order by s.full_name
          limit 200
        ) x
      ), '[]'::jsonb)
    );
  end if;

  if p_action = 'staffAccessProfile' then
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
    return jsonb_build_object(
      'ok', true,
      'staff', (select jsonb_build_object(
        'staff_id', s.id, 'person_id', s.central_person_id, 'staff_number', s.staff_number,
        'full_name', s.full_name, 'designation', s.designation, 'staff_category', s.staff_category,
        'department', s.department, 'employment_status', s.employment_status,
        'registration_status', s.registration_status, 'public_visibility_approved', s.public_visibility_approved,
        'public_display_name', s.public_display_name, 'public_display_role', s.public_display_role,
        'public_display_order', s.public_display_order, 'account_status', i.account_status
      ) from public.staff_attendance_profiles s
        join public.school_identity_accounts i on i.person_id = s.central_person_id
        where s.id = v_staff_id),
      'module_grants', coalesce((select jsonb_agg(jsonb_build_object(
        'id', g.id, 'app_code', g.app_code, 'access_role', g.access_role, 'permissions', g.permissions,
        'grant_status', g.grant_status, 'valid_from', g.valid_from, 'valid_until', g.valid_until,
        'granted_by_person_id', g.granted_by_person_id, 'reason', g.reason,
        'revoked_by_person_id', g.revoked_by_person_id, 'revoked_at', g.revoked_at,
        'revocation_reason', g.revocation_reason
      ) order by g.app_code) from public.school_access_grants g where g.person_id = v_person_id), '[]'::jsonb),
      'role_assignments', coalesce((select jsonb_agg(jsonb_build_object(
        'id', r.id, 'role_code', r.role_code, 'role_name', c.role_name, 'assignment_status', r.assignment_status,
        'effective_from', r.effective_from, 'effective_until', r.effective_until, 'assigned_at', r.assigned_at,
        'reason', r.reason, 'revoked_at', r.revoked_at, 'revocation_reason', r.revocation_reason
      ) order by c.role_name) from public.school_staff_role_assignments r
        join public.school_system_role_catalog c on c.role_code = r.role_code where r.person_id = v_person_id), '[]'::jsonb),
      'scopes', coalesce((select jsonb_agg(jsonb_build_object(
        'id', x.id, 'app_code', x.app_code, 'scope_type', x.scope_type, 'class_key', x.class_key,
        'display_name', x.display_name, 'subject_index', x.subject_index, 'subject_name', x.subject_name,
        'scope_status', x.scope_status, 'effective_from', x.effective_from, 'effective_until', x.effective_until,
        'reason', x.reason, 'revoked_at', x.revoked_at, 'revocation_reason', x.revocation_reason,
        'academic_session', x.metadata ->> 'academic_session', 'term', x.metadata ->> 'term'
      ) order by x.app_code, x.display_name, x.subject_index nulls first) from (
        select s.id, s.app_code, s.scope_type, s.class_key, c.display_name, s.subject_index,
          r.subject_name, s.scope_status, s.effective_from, s.effective_until, s.reason,
          s.revoked_at, s.revocation_reason, s.metadata
        from public.school_staff_access_scopes s
        join public.school_classes c on c.class_key = s.class_key
        left join public.result_subject_catalog r on r.class_key = s.class_key and r.subject_index = s.subject_index
        where s.person_id = v_person_id
      ) x), '[]'::jsonb),
      'result_context', jsonb_build_object('academic_session', (select value from public.settings where key = 'session'), 'term', (select value from public.settings where key = 'term')),
      'history', coalesce((select jsonb_agg(jsonb_build_object(
        'id', a.id, 'action', a.action, 'entity_type', a.entity_type, 'created_at', a.created_at, 'details', a.details
      ) order by a.created_at desc) from (
        select * from public.school_registry_audit
        where details ->> 'staff_id' = v_staff_id::text or details ->> 'person_id' = v_person_id::text
        order by created_at desc limit 100
      ) a), '[]'::jsonb)
    );
  end if;

  return jsonb_build_object('ok', false, 'code', 'UNKNOWN_ACTION');
end;
$function$;

create or replace function public.school_access_management_scope_write_session_api(
  p_session_id uuid,
  p_session_secret text,
  p_action text,
  p_payload jsonb default '{}'::jsonb
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_session jsonb;
  v_actor_person_id uuid;
  v_staff_id uuid;
  v_person_id uuid;
  v_id uuid;
  v_request_id uuid := gen_random_uuid();
  v_scope_type text := trim(coalesce(p_payload ->> 'scopeType', ''));
  v_class_key text := trim(coalesce(p_payload ->> 'classKey', ''));
  v_app_code text := trim(coalesce(p_payload ->> 'appCode', 'results'));
  v_reason text := nullif(trim(coalesce(p_payload ->> 'reason', '')), '');
  v_academic_session text := nullif(trim(coalesce(p_payload ->> 'academicSession', '')), '');
  v_term text := nullif(trim(coalesce(p_payload ->> 'term', '')), '');
  v_subject_index integer;
  v_enabled boolean := coalesce((p_payload ->> 'enabled')::boolean, false);
  v_from timestamptz := now();
  v_until timestamptz;
  v_before jsonb;
  v_after jsonb;
begin
  if lower(trim(coalesce(p_action, ''))) <> 'setscope' then
    return jsonb_build_object('ok', false, 'code', 'UNKNOWN_ACTION');
  end if;
  v_session := public.school_identity_session_validate(p_session_id, p_session_secret, 'central_registry');
  if coalesce((v_session ->> 'ok')::boolean, false) is not true then return v_session; end if;
  v_actor_person_id := wts_internal.central_management_actor(v_session);
  if v_actor_person_id is null then return jsonb_build_object('ok', false, 'code', 'MANAGEMENT_ACCESS_DENIED'); end if;
  if v_reason is null or length(v_reason) < 8 then return jsonb_build_object('ok', false, 'code', 'SCOPE_REASON_REQUIRED'); end if;
  begin
    v_staff_id := (p_payload ->> 'staffId')::uuid;
    v_subject_index := nullif(p_payload ->> 'subjectIndex', '')::integer;
    v_from := coalesce(nullif(p_payload ->> 'effectiveFrom', '')::timestamptz, now());
    v_until := nullif(p_payload ->> 'expiresAt', '')::timestamptz;
  exception when others then
    return jsonb_build_object('ok', false, 'code', 'INVALID_SCOPE_OR_DATE');
  end;
  select central_person_id into v_person_id from public.staff_attendance_profiles
  where id = v_staff_id and registration_status = 'active' and employment_status = 'active';
  if v_person_id is null then return jsonb_build_object('ok', false, 'code', 'STAFF_NOT_ACTIVE'); end if;
  if v_app_code <> 'results' or v_scope_type not in ('class', 'subject') then return jsonb_build_object('ok', false, 'code', 'UNSUPPORTED_SCOPE'); end if;
  if not exists(select 1 from public.school_classes where class_key = v_class_key and is_active) then return jsonb_build_object('ok', false, 'code', 'ACTIVE_CLASS_NOT_FOUND'); end if;
  if v_scope_type = 'class' then
    v_subject_index := null;
  elsif not exists(select 1 from public.result_subject_catalog where class_key = v_class_key and subject_index = v_subject_index and active) then
    return jsonb_build_object('ok', false, 'code', 'ACTIVE_RESULT_SUBJECT_NOT_FOUND');
  end if;
  if v_enabled and (v_academic_session is null or v_term is null) then return jsonb_build_object('ok', false, 'code', 'RESULT_SCOPE_CONTEXT_REQUIRED'); end if;
  if v_until is not null and v_until <= v_from then return jsonb_build_object('ok', false, 'code', 'EXPIRY_MUST_FOLLOW_EFFECTIVE_DATE'); end if;
  select id, to_jsonb(s) into v_id, v_before from public.school_staff_access_scopes s
  where s.person_id = v_person_id and s.app_code = v_app_code and s.scope_type = v_scope_type
    and s.class_key = v_class_key and s.subject_index is not distinct from v_subject_index;
  if v_id is null and not v_enabled then return jsonb_build_object('ok', true, 'code', 'SCOPE_ALREADY_NOT_ASSIGNED', 'request_id', v_request_id); end if;
  if v_id is null then
    insert into public.school_staff_access_scopes(
      person_id, app_code, scope_type, class_key, subject_index, scope_status,
      effective_from, effective_until, assigned_by_person_id, assigned_at, reason, metadata
    ) values(
      v_person_id, v_app_code, v_scope_type, v_class_key, v_subject_index, 'active',
      v_from, v_until, v_actor_person_id, now(), v_reason,
      jsonb_build_object('managed_from', 'central_registry_secure_session', 'staff_id', v_staff_id,
        'academic_session', v_academic_session, 'term', v_term)
    ) returning id into v_id;
  else
    update public.school_staff_access_scopes set
      scope_status = case when v_enabled then 'active' else 'revoked' end,
      effective_from = case when v_enabled then v_from else effective_from end,
      effective_until = case when v_enabled then v_until else now() end,
      assigned_by_person_id = case when v_enabled then v_actor_person_id else assigned_by_person_id end,
      assigned_at = case when v_enabled then now() else assigned_at end,
      revoked_by_person_id = case when v_enabled then null else v_actor_person_id end,
      revoked_at = case when v_enabled then null else now() end,
      revocation_reason = case when v_enabled then null else v_reason end,
      reason = v_reason,
      metadata = case when v_enabled then metadata || jsonb_build_object('academic_session', v_academic_session, 'term', v_term, 'managed_from', 'central_registry_secure_session') else metadata end,
      updated_at = now()
    where id = v_id;
  end if;
  select to_jsonb(s) into v_after from public.school_staff_access_scopes s where s.id = v_id;
  insert into public.school_registry_audit(
    actor_type, actor_id, action, entity_type, entity_id, request_id, before_data, after_data, details
  ) values(
    'person', v_actor_person_id::text,
    case when v_enabled then 'staff_access.scope_assigned' else 'staff_access.scope_revoked' end,
    'school_staff_access_scope', v_id::text, v_request_id, v_before, v_after,
    jsonb_build_object('staff_id', v_staff_id, 'person_id', v_person_id, 'app_code', v_app_code,
      'scope_type', v_scope_type, 'class_key', v_class_key, 'subject_index', v_subject_index,
      'academic_session', v_academic_session, 'term', v_term, 'management_session', true)
  );
  return jsonb_build_object('ok', true, 'code', case when v_enabled then 'SCOPE_ASSIGNED' else 'SCOPE_REVOKED' end, 'request_id', v_request_id);
end;
$function$;

create or replace function public.school_identity_management_session_write_api(
  p_session_id uuid,
  p_session_secret text,
  p_action text,
  p_payload jsonb default '{}'::jsonb
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_session jsonb;
  v_actor_person_id uuid;
  v_staff_id uuid;
  v_person_id uuid;
  v_reason text := nullif(trim(coalesce(p_payload ->> 'reason', '')), '');
begin
  if lower(trim(coalesce(p_action, ''))) <> 'issuetemporarycredential' then return jsonb_build_object('ok', false, 'code', 'UNKNOWN_ACTION'); end if;
  v_session := public.school_identity_session_validate(p_session_id, p_session_secret, 'central_registry');
  if coalesce((v_session ->> 'ok')::boolean, false) is not true then return v_session; end if;
  v_actor_person_id := wts_internal.central_management_actor(v_session);
  if v_actor_person_id is null then return jsonb_build_object('ok', false, 'code', 'MANAGEMENT_ACCESS_DENIED'); end if;
  begin v_staff_id := (p_payload ->> 'staffId')::uuid; exception when others then return jsonb_build_object('ok', false, 'code', 'INVALID_STAFF_ID'); end;
  if v_staff_id is null or v_reason is null or length(v_reason) < 8 then return jsonb_build_object('ok', false, 'code', 'RESET_REASON_REQUIRED'); end if;
  select central_person_id into v_person_id from public.staff_attendance_profiles where id = v_staff_id;
  if v_person_id is null then return jsonb_build_object('ok', false, 'code', 'STAFF_IDENTITY_NOT_LINKED'); end if;
  return wts_internal.issue_temporary_credential(v_person_id, left(v_reason, 500), 'identity_session', v_actor_person_id::text, false);
end;
$function$;

revoke all on function public.school_access_management_scope_read_session_api(uuid, text, text, jsonb) from public, authenticated;
revoke all on function public.school_access_management_scope_write_session_api(uuid, text, text, jsonb) from public, authenticated;
revoke all on function public.school_identity_management_session_write_api(uuid, text, text, jsonb) from public, authenticated;
grant execute on function public.school_access_management_scope_read_session_api(uuid, text, text, jsonb) to anon;
grant execute on function public.school_access_management_scope_write_session_api(uuid, text, text, jsonb) to anon;
grant execute on function public.school_identity_management_session_write_api(uuid, text, text, jsonb) to anon;

-- The secure browser adapters supersede direct credential issuance from the
-- legacy management client. Keep the old function for rollback, but do not
-- allow a browser to call it during the secure-session rollout.
revoke all on function public.school_identity_management_write_api(text, text, text, jsonb) from public, anon, authenticated;

