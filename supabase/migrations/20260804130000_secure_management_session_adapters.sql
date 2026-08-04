-- Phase 3 Central Registry transition.
-- These adapters replace browser calls that supplied the reusable
-- attendance-admin client secret. They do not create identities or data.

create or replace function public.school_access_management_write_session_api(
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
  v_request_id uuid := gen_random_uuid();
  v_before jsonb;
  v_after jsonb;
  v_id uuid;
  v_app_code text;
  v_role text;
  v_enabled boolean;
  v_permissions text[] := array[]::text[];
  v_reason text;
  v_from timestamptz := now();
  v_until timestamptz;
  v_status text;
  v_role_code text;
  v_scope_type text;
  v_class_key text;
  v_subject_index integer;
begin
  v_session := public.school_identity_session_validate(p_session_id, p_session_secret, 'central_registry');
  if coalesce((v_session ->> 'ok')::boolean, false) is not true then
    return v_session;
  end if;

  select wts_internal.central_management_actor(v_session) into v_actor_person_id;
  if v_actor_person_id is null then
    return jsonb_build_object('ok', false, 'code', 'MANAGEMENT_ACCESS_DENIED');
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
  v_reason := nullif(trim(coalesce(p_payload ->> 'reason', '')), '');

  if p_action = 'setModuleAccess' then
    v_app_code := trim(coalesce(p_payload ->> 'appCode', ''));
    v_role := trim(coalesce(p_payload ->> 'accessRole', ''));
    v_enabled := coalesce((p_payload ->> 'enabled')::boolean, false);
    if not exists (select 1 from public.school_portal_catalog where app_code = v_app_code and is_active) then
      return jsonb_build_object('ok', false, 'code', 'PORTAL_NOT_FOUND');
    end if;
    if v_role = '' then
      return jsonb_build_object('ok', false, 'code', 'ACCESS_ROLE_REQUIRED');
    end if;
    begin
      v_from := coalesce(nullif(p_payload ->> 'effectiveFrom', '')::timestamptz, now());
      v_until := nullif(p_payload ->> 'expiresAt', '')::timestamptz;
    exception when others then
      return jsonb_build_object('ok', false, 'code', 'INVALID_EFFECTIVE_OR_EXPIRY_DATE');
    end;
    if v_until is not null and v_until <= v_from then
      return jsonb_build_object('ok', false, 'code', 'EXPIRY_MUST_FOLLOW_EFFECTIVE_DATE');
    end if;
    begin
      select coalesce(array_agg(distinct value order by value), array[]::text[])
      into v_permissions
      from jsonb_array_elements_text(coalesce(p_payload -> 'permissions', '[]'::jsonb)) value;
    exception when others then
      return jsonb_build_object('ok', false, 'code', 'PERMISSIONS_PAYLOAD_INVALID');
    end;
    if v_enabled and v_app_code <> 'staff_self_service' and cardinality(v_permissions) = 0 then
      return jsonb_build_object('ok', false, 'code', 'AT_LEAST_ONE_ACTION_PERMISSION_REQUIRED');
    end if;
    if exists (
      select 1 from unnest(v_permissions) permission_code
      where not exists (
        select 1 from public.school_permission_catalog c
        where c.permission_code = permission_code and c.app_code = v_app_code
      )
    ) then
      return jsonb_build_object('ok', false, 'code', 'UNKNOWN_OR_CROSS_PORTAL_PERMISSION');
    end if;
    if v_app_code = 'staff_self_service' and v_enabled then
      v_permissions := array['staff_profile.view', 'staff_profile.edit']::text[];
    end if;
    select to_jsonb(g) into v_before
    from public.school_access_grants g
    where g.person_id = v_person_id and g.app_code = v_app_code;
    if not v_enabled and exists (
      select 1 from public.school_access_grants g
      where g.person_id = v_person_id
        and g.app_code = 'central_registry'
        and g.grant_status = 'active'
        and coalesce((g.metadata ->> 'primary_registry_admin')::boolean, false)
    ) then
      return jsonb_build_object('ok', false, 'code', 'PRIMARY_SUPER_ADMIN_ACCESS_CANNOT_BE_REVOKED_HERE');
    end if;
    insert into public.school_access_grants(
      person_id, app_code, access_role, permissions, grant_status, valid_from,
      valid_until, granted_by_person_id, reason, metadata, revoked_by_person_id,
      revoked_at, revocation_reason
    ) values (
      v_person_id, v_app_code, v_role, v_permissions,
      case when v_enabled then 'active' else 'revoked' end,
      case when v_enabled then v_from else now() end,
      case when v_enabled then v_until else now() end,
      v_actor_person_id,
      coalesce(v_reason, case when v_enabled then 'Assigned through Central Registry access management' else 'Revoked through Central Registry access management' end),
      jsonb_build_object('managed_from', 'central_registry_secure_session', 'staff_id', v_staff_id),
      case when v_enabled then null else v_actor_person_id end,
      case when v_enabled then null else now() end,
      case when v_enabled then null else coalesce(v_reason, 'Revoked through Central Registry access management') end
    )
    on conflict (person_id, app_code) do update set
      access_role = excluded.access_role,
      permissions = excluded.permissions,
      grant_status = excluded.grant_status,
      valid_from = excluded.valid_from,
      valid_until = excluded.valid_until,
      granted_by_person_id = case when excluded.grant_status = 'active' then excluded.granted_by_person_id else public.school_access_grants.granted_by_person_id end,
      reason = excluded.reason,
      metadata = public.school_access_grants.metadata || excluded.metadata,
      revoked_by_person_id = excluded.revoked_by_person_id,
      revoked_at = excluded.revoked_at,
      revocation_reason = excluded.revocation_reason,
      updated_at = now()
    returning id into v_id;
    select to_jsonb(g) into v_after from public.school_access_grants g where g.id = v_id;
    insert into public.school_registry_audit(actor_type, actor_id, action, entity_type, entity_id, request_id, before_data, after_data, details)
    values (
      'person', v_actor_person_id::text,
      case when v_enabled then 'staff_access.module_granted' else 'staff_access.module_revoked' end,
      'school_access_grant', v_id::text, v_request_id, v_before, v_after,
      jsonb_build_object('staff_id', v_staff_id, 'person_id', v_person_id, 'app_code', v_app_code, 'secure_session', true)
    );
    return jsonb_build_object('ok', true, 'code', case when v_enabled then 'MODULE_ACCESS_GRANTED' else 'MODULE_ACCESS_REVOKED' end, 'request_id', v_request_id);
  end if;

  if p_action = 'setSystemRole' then
    v_role_code := trim(coalesce(p_payload ->> 'roleCode', ''));
    v_enabled := coalesce((p_payload ->> 'enabled')::boolean, false);
    if not exists (select 1 from public.school_system_role_catalog where role_code = v_role_code and is_assignable) then
      return jsonb_build_object('ok', false, 'code', 'SYSTEM_ROLE_NOT_FOUND');
    end if;
    begin
      v_from := coalesce(nullif(p_payload ->> 'effectiveFrom', '')::timestamptz, now());
      v_until := nullif(p_payload ->> 'expiresAt', '')::timestamptz;
    exception when others then
      return jsonb_build_object('ok', false, 'code', 'INVALID_EFFECTIVE_OR_EXPIRY_DATE');
    end;
    if v_until is not null and v_until <= v_from then
      return jsonb_build_object('ok', false, 'code', 'EXPIRY_MUST_FOLLOW_EFFECTIVE_DATE');
    end if;
    select to_jsonb(r) into v_before
    from public.school_staff_role_assignments r
    where r.person_id = v_person_id and r.role_code = v_role_code;
    insert into public.school_staff_role_assignments(
      person_id, role_code, assignment_status, effective_from, effective_until,
      assigned_by_person_id, assigned_at, revoked_by_person_id, revoked_at,
      revocation_reason, reason, metadata
    ) values (
      v_person_id, v_role_code, case when v_enabled then 'active' else 'revoked' end,
      case when v_enabled then v_from else now() end,
      case when v_enabled then v_until else now() end,
      v_actor_person_id, now(), case when v_enabled then null else v_actor_person_id end,
      case when v_enabled then null else now() end,
      case when v_enabled then null else coalesce(v_reason, 'Role revoked through Central Registry access management') end,
      v_reason, jsonb_build_object('managed_from', 'central_registry_secure_session', 'staff_id', v_staff_id)
    )
    on conflict (person_id, role_code) do update set
      assignment_status = excluded.assignment_status,
      effective_from = excluded.effective_from,
      effective_until = excluded.effective_until,
      assigned_by_person_id = excluded.assigned_by_person_id,
      assigned_at = excluded.assigned_at,
      revoked_by_person_id = excluded.revoked_by_person_id,
      revoked_at = excluded.revoked_at,
      revocation_reason = excluded.revocation_reason,
      reason = excluded.reason,
      metadata = public.school_staff_role_assignments.metadata || excluded.metadata,
      updated_at = now()
    returning id into v_id;
    select to_jsonb(r) into v_after from public.school_staff_role_assignments r where r.id = v_id;
    insert into public.school_registry_audit(actor_type, actor_id, action, entity_type, entity_id, request_id, before_data, after_data, details)
    values (
      'person', v_actor_person_id::text,
      case when v_enabled then 'staff_access.role_assigned' else 'staff_access.role_revoked' end,
      'school_staff_role_assignment', v_id::text, v_request_id, v_before, v_after,
      jsonb_build_object('staff_id', v_staff_id, 'person_id', v_person_id, 'role_code', v_role_code, 'secure_session', true)
    );
    return jsonb_build_object('ok', true, 'code', case when v_enabled then 'SYSTEM_ROLE_ASSIGNED' else 'SYSTEM_ROLE_REVOKED' end, 'request_id', v_request_id);
  end if;

  if p_action = 'setAccountStatus' then
    v_status := trim(coalesce(p_payload ->> 'accountStatus', ''));
    if v_status not in ('active', 'suspended') then
      return jsonb_build_object('ok', false, 'code', 'INVALID_ACCOUNT_STATUS');
    end if;
    if v_status = 'suspended' and exists (
      select 1 from public.school_access_grants g
      where g.person_id = v_person_id and g.app_code = 'central_registry'
        and g.grant_status = 'active'
        and coalesce((g.metadata ->> 'primary_registry_admin')::boolean, false)
    ) then
      return jsonb_build_object('ok', false, 'code', 'PRIMARY_SUPER_ADMIN_ACCOUNT_CANNOT_BE_SUSPENDED_HERE');
    end if;
    select to_jsonb(i) into v_before from public.school_identity_accounts i where i.person_id = v_person_id;
    update public.school_identity_accounts
    set account_status = v_status, updated_at = now()
    where person_id = v_person_id
    returning id into v_id;
    if not found then
      return jsonb_build_object('ok', false, 'code', 'IDENTITY_ACCOUNT_NOT_FOUND');
    end if;
    select to_jsonb(i) into v_after from public.school_identity_accounts i where i.id = v_id;
    insert into public.school_registry_audit(actor_type, actor_id, action, entity_type, entity_id, request_id, before_data, after_data, details)
    values (
      'person', v_actor_person_id::text,
      case when v_status = 'suspended' then 'staff_access.account_suspended' else 'staff_access.account_restored' end,
      'school_identity_account', v_id::text, v_request_id, v_before, v_after,
      jsonb_build_object('staff_id', v_staff_id, 'person_id', v_person_id, 'reason', v_reason, 'secure_session', true)
    );
    return jsonb_build_object('ok', true, 'code', case when v_status = 'suspended' then 'ACCOUNT_SUSPENDED' else 'ACCOUNT_RESTORED' end, 'request_id', v_request_id);
  end if;

  if p_action = 'setPublicDirectoryVisibility' then
    v_enabled := coalesce((p_payload ->> 'approved')::boolean, false);
    select to_jsonb(s) into v_before from public.staff_attendance_profiles s where s.id = v_staff_id;
    begin
      update public.staff_attendance_profiles
      set public_visibility_approved = v_enabled,
          public_display_name = nullif(trim(p_payload ->> 'displayName'), ''),
          public_display_role = nullif(trim(p_payload ->> 'displayRole'), ''),
          public_display_order = nullif(p_payload ->> 'displayOrder', '')::integer,
          public_visibility_approved_at = case when v_enabled then now() else null end,
          public_visibility_approved_by_person_id = case when v_enabled then v_actor_person_id else null end,
          updated_at = now()
      where id = v_staff_id;
    exception when others then
      return jsonb_build_object('ok', false, 'code', 'DIRECTORY_PAYLOAD_INVALID');
    end;
    select to_jsonb(s) into v_after from public.staff_attendance_profiles s where s.id = v_staff_id;
    insert into public.school_registry_audit(actor_type, actor_id, action, entity_type, entity_id, request_id, before_data, after_data, details)
    values (
      'person', v_actor_person_id::text,
      case when v_enabled then 'staff_directory.visibility_approved' else 'staff_directory.visibility_removed' end,
      'staff_attendance_profile', v_staff_id::text, v_request_id, v_before, v_after,
      jsonb_build_object('staff_id', v_staff_id, 'person_id', v_person_id, 'secure_session', true)
    );
    return jsonb_build_object('ok', true, 'code', 'PUBLIC_DIRECTORY_VISIBILITY_UPDATED', 'request_id', v_request_id);
  end if;

  return jsonb_build_object('ok', false, 'code', 'UNKNOWN_ACTION');
end;
$function$;

create or replace function public.school_identity_admin_read_session_api(
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
  v_search text := lower(trim(coalesce(p_payload ->> 'search', '')));
  v_result jsonb;
begin
  v_session := public.school_identity_session_validate(p_session_id, p_session_secret, 'central_registry');
  if coalesce((v_session ->> 'ok')::boolean, false) is not true then
    return v_session;
  end if;
  select wts_internal.central_management_actor(v_session) into v_actor_person_id;
  if v_actor_person_id is null then
    return jsonb_build_object('ok', false, 'code', 'MANAGEMENT_ACCESS_DENIED');
  end if;
  if p_action <> 'staffAccounts' then
    return jsonb_build_object('ok', false, 'code', 'UNKNOWN_ACTION');
  end if;
  select jsonb_build_object(
    'ok', true,
    'accounts', coalesce(jsonb_agg(to_jsonb(x) order by x.full_name), '[]'::jsonb)
  ) into v_result
  from (
    select s.id as staff_id, s.central_person_id, s.staff_number, s.full_name, s.email,
      s.designation, s.department, s.photo,
      c.id as credential_id, c.login_name, c.credential_status,
      c.must_change_password, c.failed_attempts, c.locked_until,
      c.last_login_at, c.password_changed_at, i.account_status
    from public.staff_attendance_profiles s
    join public.school_identity_accounts i on i.person_id = s.central_person_id
    left join public.school_identity_credentials c on c.identity_account_id = i.id
    where v_search = ''
      or lower(s.full_name) like '%' || v_search || '%'
      or lower(coalesce(s.staff_number, '')) like '%' || v_search || '%'
      or lower(coalesce(s.email, '')) like '%' || v_search || '%'
    order by s.full_name
    limit 250
  ) x;
  return v_result;
end;
$function$;

revoke all on function public.school_access_management_write_session_api(uuid, text, text, jsonb) from public, authenticated;
revoke all on function public.school_identity_admin_read_session_api(uuid, text, text, jsonb) from public, authenticated;
grant execute on function public.school_access_management_write_session_api(uuid, text, text, jsonb) to anon;
grant execute on function public.school_identity_admin_read_session_api(uuid, text, text, jsonb) to anon;

-- Scope edits target an existing row by id when supplied. This preserves the
-- assignment history instead of creating a second scope for a changed class,
-- subject or academic context.
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
  select wts_internal.central_management_actor(v_session) into v_actor_person_id;
  if v_actor_person_id is null then return jsonb_build_object('ok', false, 'code', 'MANAGEMENT_ACCESS_DENIED'); end if;
  if v_reason is null or length(v_reason) < 8 then return jsonb_build_object('ok', false, 'code', 'SCOPE_REASON_REQUIRED'); end if;
  begin
    v_staff_id := (p_payload ->> 'staffId')::uuid;
    v_subject_index := nullif(p_payload ->> 'subjectIndex', '')::integer;
    v_from := coalesce(nullif(p_payload ->> 'effectiveFrom', '')::timestamptz, now());
    v_until := nullif(p_payload ->> 'expiresAt', '')::timestamptz;
    if nullif(p_payload ->> 'scopeId', '') is not null then v_id := (p_payload ->> 'scopeId')::uuid; end if;
  exception when others then
    return jsonb_build_object('ok', false, 'code', 'INVALID_SCOPE_OR_DATE');
  end;
  select central_person_id into v_person_id
  from public.staff_attendance_profiles
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

  if v_id is not null then
    select id, to_jsonb(s) into v_id, v_before
    from public.school_staff_access_scopes s
    where s.id = v_id and s.person_id = v_person_id and s.app_code = v_app_code;
  else
    select id, to_jsonb(s) into v_id, v_before
    from public.school_staff_access_scopes s
    where s.person_id = v_person_id and s.app_code = v_app_code
      and s.scope_type = v_scope_type and s.class_key = v_class_key
      and s.subject_index is not distinct from v_subject_index;
  end if;
  if v_id is null and not v_enabled then return jsonb_build_object('ok', true, 'code', 'SCOPE_ALREADY_NOT_ASSIGNED', 'request_id', v_request_id); end if;
  if v_id is null then
    insert into public.school_staff_access_scopes(
      person_id, app_code, scope_type, class_key, subject_index, scope_status,
      effective_from, effective_until, assigned_by_person_id, assigned_at, reason, metadata
    ) values (
      v_person_id, v_app_code, v_scope_type, v_class_key, v_subject_index, 'active',
      v_from, v_until, v_actor_person_id, now(), v_reason,
      jsonb_build_object('managed_from', 'central_registry_secure_session', 'staff_id', v_staff_id, 'academic_session', v_academic_session, 'term', v_term)
    ) returning id into v_id;
  else
    update public.school_staff_access_scopes set
      scope_type = v_scope_type,
      class_key = v_class_key,
      subject_index = v_subject_index,
      scope_status = case when v_enabled then 'active' else 'revoked' end,
      effective_from = case when v_enabled then v_from else effective_from end,
      effective_until = case when v_enabled then v_until else now() end,
      assigned_by_person_id = case when v_enabled then v_actor_person_id else assigned_by_person_id end,
      assigned_at = case when v_enabled then now() else assigned_at end,
      revoked_by_person_id = case when v_enabled then null else v_actor_person_id end,
      revoked_at = case when v_enabled then null else now() end,
      revocation_reason = case when v_enabled then null else v_reason end,
      reason = v_reason,
      metadata = metadata || jsonb_build_object('academic_session', v_academic_session, 'term', v_term, 'staff_id', v_staff_id, 'managed_from', 'central_registry_secure_session'),
      updated_at = now()
    where id = v_id and person_id = v_person_id and app_code = v_app_code;
    if not found then return jsonb_build_object('ok', false, 'code', 'SCOPE_NOT_FOUND'); end if;
  end if;
  select to_jsonb(s) into v_after from public.school_staff_access_scopes s where s.id = v_id;
  insert into public.school_registry_audit(actor_type, actor_id, action, entity_type, entity_id, request_id, before_data, after_data, details)
  values (
    'person', v_actor_person_id::text,
    case when v_enabled then case when v_before is null then 'staff_access.scope_assigned' else 'staff_access.scope_updated' end else 'staff_access.scope_revoked' end,
    'school_staff_access_scope', v_id::text, v_request_id, v_before, v_after,
    jsonb_build_object('staff_id', v_staff_id, 'person_id', v_person_id, 'app_code', v_app_code, 'scope_type', v_scope_type, 'class_key', v_class_key, 'subject_index', v_subject_index, 'academic_session', v_academic_session, 'term', v_term, 'secure_session', true)
  );
  return jsonb_build_object('ok', true, 'code', case when v_enabled then case when v_before is null then 'SCOPE_ASSIGNED' else 'SCOPE_UPDATED' end else 'SCOPE_REVOKED' end, 'request_id', v_request_id);
end;
$function$;

revoke all on function public.school_access_management_scope_write_session_api(uuid, text, text, jsonb) from public, authenticated;
grant execute on function public.school_access_management_scope_write_session_api(uuid, text, text, jsonb) to anon;

-- The following browser RPCs are no longer part of the active Central UI.
revoke all on function public.school_access_management_read_api(text, text, text, jsonb) from public, anon, authenticated;
revoke all on function public.school_access_management_write_api(text, text, text, jsonb) from public, anon, authenticated;
revoke all on function public.school_access_management_scope_read_api(text, text, text, jsonb) from public, anon, authenticated;
revoke all on function public.school_access_management_scope_write_api(text, text, text, jsonb) from public, anon, authenticated;
revoke all on function public.school_identity_admin_read_api(text, text, text, jsonb) from public, anon, authenticated;
