-- Scope subject assignments also establish the class boundary for the assigned class.

create or replace function public.school_result_authorize(
  p_session_id uuid,
  p_session_secret text,
  p_action text,
  p_class_key text default null,
  p_subject_index integer default null,
  p_academic_session text default null,
  p_term text default null
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_session jsonb;
  v_identity jsonb;
  v_person_id uuid;
  v_identity_account_id uuid;
  v_permissions text[];
  v_access_role text;
  v_action text := lower(trim(coalesce(p_action, '')));
  v_current_session text;
  v_current_term text;
  v_requires_scope boolean := false;
  v_broad_access boolean := false;
  v_class_scope boolean := false;
  v_subject_scope boolean := false;
begin
  v_session := public.school_identity_session_validate(p_session_id, p_session_secret, 'results');
  if coalesce((v_session ->> 'ok')::boolean, false) is not true then return v_session; end if;

  v_person_id := (v_session ->> 'person_id')::uuid;
  v_identity_account_id := (v_session ->> 'identity_account_id')::uuid;
  v_permissions := coalesce(array(select jsonb_array_elements_text(v_session -> 'permissions')), array[]::text[]);
  v_access_role := v_session ->> 'access_role';
  v_identity := public.school_result_identity_resolve(v_person_id, v_identity_account_id);
  if coalesce((v_identity ->> 'ok')::boolean, false) is not true then return v_identity; end if;

  if v_action = 'identity.context' then
    return jsonb_build_object('ok', true, 'code', 'RESULT_AUTHORIZED',
      'person_id', v_person_id, 'identity_account_id', v_identity_account_id,
      'access_role', v_access_role, 'permissions', v_permissions,
      'result_user', v_identity -> 'result_user', 'staff', v_identity -> 'staff',
      'expires_at', v_session -> 'expires_at');
  end if;

  if not public.school_result_permission_allowed(v_permissions, v_action) then
    return jsonb_build_object('ok', false, 'code', 'RESULT_PERMISSION_DENIED', 'required_permission', v_action);
  end if;

  v_broad_access := public.school_result_permission_allowed(v_permissions, 'results.manage');
  v_requires_scope := v_action in ('scores.enter', 'traits.enter', 'remarks.enter', 'results.view_assigned', 'results.review', 'results.approve', 'report_cards.generate', 'results.export');

  if v_action = 'scores.enter' and p_subject_index is null then
    return jsonb_build_object('ok', false, 'code', 'RESULT_SUBJECT_SCOPE_REQUIRED');
  end if;

  if v_requires_scope and not v_broad_access then
    if nullif(trim(coalesce(p_class_key, '')), '') is null then
      return jsonb_build_object('ok', false, 'code', 'RESULT_CLASS_SCOPE_REQUIRED');
    end if;

    select exists(
      select 1 from public.school_staff_access_scopes s
      where s.person_id = v_person_id and s.app_code = 'results'
        and s.scope_type in ('class', 'subject') and s.class_key = trim(p_class_key)
        and s.scope_status = 'active'
        and (s.effective_from is null or s.effective_from <= now())
        and (s.effective_until is null or s.effective_until > now())
        and public.school_result_scope_context_matches(s.metadata, p_academic_session, p_term)
    ) into v_class_scope;
    if not v_class_scope then return jsonb_build_object('ok', false, 'code', 'RESULT_CLASS_SCOPE_DENIED'); end if;

    if p_subject_index is not null then
      select exists(
        select 1 from public.school_staff_access_scopes s
        where s.person_id = v_person_id and s.app_code = 'results'
          and s.scope_type = 'subject' and s.class_key = trim(p_class_key)
          and s.subject_index = p_subject_index and s.scope_status = 'active'
          and (s.effective_from is null or s.effective_from <= now())
          and (s.effective_until is null or s.effective_until > now())
          and public.school_result_scope_context_matches(s.metadata, p_academic_session, p_term)
      ) into v_subject_scope;
      if not v_subject_scope then return jsonb_build_object('ok', false, 'code', 'RESULT_SUBJECT_SCOPE_DENIED'); end if;
    end if;
  end if;

  if v_action in ('results.publish', 'scores.enter', 'traits.enter', 'remarks.enter') then
    if nullif(trim(coalesce(p_academic_session, '')), '') is null or nullif(trim(coalesce(p_term, '')), '') is null then
      return jsonb_build_object('ok', false, 'code', 'RESULT_ACADEMIC_CONTEXT_REQUIRED');
    end if;
    select value into v_current_session from public.settings where key = 'session';
    select value into v_current_term from public.settings where key = 'term';
    if v_current_session is null or v_current_term is null then return jsonb_build_object('ok', false, 'code', 'RESULT_ACADEMIC_CONTEXT_NOT_CONFIGURED'); end if;
    if trim(p_academic_session) <> v_current_session then return jsonb_build_object('ok', false, 'code', 'RESULT_ACADEMIC_SESSION_NOT_ACTIVE'); end if;
    if trim(p_term) <> v_current_term then return jsonb_build_object('ok', false, 'code', 'RESULT_TERM_NOT_ACTIVE'); end if;
  end if;

  return jsonb_build_object('ok', true, 'code', 'RESULT_AUTHORIZED',
    'person_id', v_person_id, 'identity_account_id', v_identity_account_id,
    'access_role', v_access_role, 'permissions', v_permissions,
    'result_user', v_identity -> 'result_user', 'class_scope', v_class_scope,
    'subject_scope', v_subject_scope, 'expires_at', v_session -> 'expires_at');
end;
$function$;

revoke all on function public.school_result_authorize(uuid, text, text, text, integer, text, text) from public, anon, authenticated;

grant execute on function public.school_result_authorize(uuid, text, text, text, integer, text, text) to service_role;

create or replace function public.school_result_read_api(
  p_session_id uuid,
  p_session_secret text,
  p_resource text,
  p_payload jsonb default '{}'::jsonb
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_resource text := lower(trim(coalesce(p_resource, '')));
  v_class_key text := nullif(trim(coalesce(p_payload ->> 'class_key', '')), '');
  v_student_id uuid;
  v_subject_index integer;
  v_term text := nullif(trim(coalesce(p_payload ->> 'term', '')), '');
  v_academic_session text := nullif(trim(coalesce(p_payload ->> 'academic_session', '')), '');
  v_auth jsonb;
  v_permissions text[];
  v_broad boolean;
  v_class_scope boolean;
  v_subject_scope boolean;
  v_rows jsonb;
begin
  begin
    if nullif(p_payload ->> 'student_id', '') is not null then v_student_id := (p_payload ->> 'student_id')::uuid; end if;
    if nullif(p_payload ->> 'subject_index', '') is not null then v_subject_index := (p_payload ->> 'subject_index')::integer; end if;
  exception when others then
    return jsonb_build_object('ok', false, 'code', 'RESULT_READ_FILTER_INVALID');
  end;

  if v_resource not in ('classes', 'subjects', 'students', 'scores', 'traits', 'remarks', 'fees', 'published_subjects', 'result_summary', 'report_card') then
    return jsonb_build_object('ok', false, 'code', 'RESULT_READ_RESOURCE_NOT_ALLOWED');
  end if;

  v_auth := public.school_result_authorize(p_session_id, p_session_secret, 'identity.context');
  if coalesce((v_auth ->> 'ok')::boolean, false) is not true then return v_auth; end if;
  v_permissions := coalesce(array(select jsonb_array_elements_text(v_auth -> 'permissions')), array[]::text[]);
  v_broad := public.school_result_permission_allowed(v_permissions, 'results.manage');
  if not v_broad and not public.school_result_permission_allowed(v_permissions, 'results.view_assigned') then
    return jsonb_build_object('ok', false, 'code', 'RESULT_PERMISSION_DENIED', 'required_permission', 'results.view_assigned');
  end if;

  if v_resource in ('scores', 'traits', 'remarks', 'fees', 'published_subjects', 'result_summary', 'report_card') then
    if v_class_key is null or v_term is null or v_academic_session is null then
      return jsonb_build_object('ok', false, 'code', 'RESULT_ACADEMIC_CONTEXT_REQUIRED');
    end if;
  end if;

  if v_class_key is not null and not v_broad then
    select exists(
      select 1 from public.school_staff_access_scopes s
      where s.person_id = (v_auth ->> 'person_id')::uuid and s.app_code = 'results'
        and s.scope_type in ('class', 'subject') and s.class_key = v_class_key and s.scope_status = 'active'
        and (s.effective_from is null or s.effective_from <= now())
        and (s.effective_until is null or s.effective_until > now())
        and public.school_result_scope_context_matches(s.metadata, v_academic_session, v_term)
    ) into v_class_scope;
    if not v_class_scope and v_resource not in ('classes', 'subjects') then
      return jsonb_build_object('ok', false, 'code', 'RESULT_CLASS_SCOPE_DENIED');
    end if;
  end if;

  if v_resource in ('scores', 'published_subjects', 'result_summary', 'report_card') and not v_broad then
    if v_subject_index is not null then
      select exists(
        select 1 from public.school_staff_access_scopes s
        where s.person_id = (v_auth ->> 'person_id')::uuid and s.app_code = 'results'
          and s.scope_type = 'subject' and s.class_key = v_class_key and s.subject_index = v_subject_index
          and s.scope_status = 'active' and (s.effective_from is null or s.effective_from <= now())
          and (s.effective_until is null or s.effective_until > now())
          and public.school_result_scope_context_matches(s.metadata, v_academic_session, v_term)
      ) into v_subject_scope;
      if not v_subject_scope then return jsonb_build_object('ok', false, 'code', 'RESULT_SUBJECT_SCOPE_DENIED'); end if;
    elsif not exists(
      select 1 from public.school_staff_access_scopes s
      where s.person_id = (v_auth ->> 'person_id')::uuid and s.app_code = 'results'
        and s.scope_type = 'subject' and (v_class_key is null or s.class_key = v_class_key)
        and s.scope_status = 'active' and