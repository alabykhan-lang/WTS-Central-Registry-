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
        and s.scope_status = 'active' and (s.effective_from is null or s.effective_from <= now())
        and (s.effective_until is null or s.effective_until > now())
        and public.school_result_scope_context_matches(s.metadata, v_academic_session, v_term)
    ) then
      return jsonb_build_object('ok', false, 'code', 'RESULT_SUBJECT_SCOPE_REQUIRED');
    end if;
  end if;

  if v_resource = 'classes' then
    select coalesce(jsonb_agg(to_jsonb(x) order by x.sort_order, x.display_name), '[]'::jsonb) into v_rows
    from (
      select c.id, c.class_key, c.display_name, c.section, c.sort_order, c.is_active
      from public.school_classes c
      where c.is_active and (
        v_broad or exists(select 1 from public.school_staff_access_scopes s where s.person_id=(v_auth->>'person_id')::uuid and s.app_code='results' and s.class_key=c.class_key and s.scope_status='active' and (s.effective_from is null or s.effective_from<=now()) and (s.effective_until is null or s.effective_until>now()) and public.school_result_scope_context_matches(s.metadata,v_academic_session,v_term))
      )
    ) x;
    return jsonb_build_object('ok', true, 'code', 'RESULT_CLASSES_READ', 'rows', v_rows);
  end if;

  if v_resource = 'subjects' then
    select coalesce(jsonb_agg(to_jsonb(x) order by x.class_key, x.subject_index), '[]'::jsonb) into v_rows
    from (
      select r.class_key, r.subject_index, r.subject_name, r.aliases, r.active
      from public.result_subject_catalog r
      where r.active and (v_class_key is null or r.class_key=v_class_key) and (
        v_broad or exists(select 1 from public.school_staff_access_scopes s where s.person_id=(v_auth->>'person_id')::uuid and s.app_code='results' and s.scope_type='subject' and s.class_key=r.class_key and s.subject_index=r.subject_index and s.scope_status='active' and (s.effective_from is null or s.effective_from<=now()) and (s.effective_until is null or s.effective_until>now()) and public.school_result_scope_context_matches(s.metadata,v_academic_session,v_term))
      )
    ) x;
    return jsonb_build_object('ok', true, 'code', 'RESULT_SUBJECTS_READ', 'rows', v_rows);
  end if;

  if v_resource = 'students' then
    select coalesce(jsonb_agg(to_jsonb(x) order by x.name), '[]'::jsonb) into v_rows
    from (
      select s.id, s.class_key, s.name, s.gender, s.admno, s.house, s.age, s.photo, s.created_at, s.archived, s.archived_at, s.archived_reason, s.previous_class_key, s.lifecycle_status, s.admission_date, s.admission_source, s.updated_at, s.student_number_status
      from public.students s
      where coalesce(s.archived,false)=false
        and (v_class_key is null or s.class_key=v_class_key)
        and (v_student_id is null or s.id=v_student_id)
        and (v_broad or exists(select 1 from public.school_staff_access_scopes x where x.person_id=(v_auth->>'person_id')::uuid and x.app_code='results' and x.scope_type in ('class','subject') and x.class_key=s.class_key and x.scope_status='active' and (x.effective_from is null or x.effective_from<=now()) and (x.effective_until is null or x.effective_until>now()) and public.school_result_scope_context_matches(x.metadata,v_academic_session,v_term)))
    ) x;
    return jsonb_build_object('ok', true, 'code', 'RESULT_STUDENTS_READ', 'rows', v_rows);
  end if;

  if v_resource = 'scores' then
    select coalesce(jsonb_agg(to_jsonb(x) order by x.student_id, x.subject_index), '[]'::jsonb) into v_rows
    from (
      select s.id, s.student_id, s.class_key, s.subject_index, s.ca1, s.ca2, s.ca3, s.exam, s.term
      from public.scores s
      where s.class_key=v_class_key and s.term=v_term and (v_student_id is null or s.student_id=v_student_id) and (v_subject_index is null or s.subject_index=v_subject_index)
        and (v_broad or exists(select 1 from public.school_staff_access_scopes x where x.person_id=(v_auth->>'person_id')::uuid and x.app_code='results' and x.scope_type='subject' and x.class_key=s.class_key and x.subject_index=s.subject_index and x.scope_status='active' and (x.effective_from is null or x.effective_from<=now()) and (x.effective_until is null or x.effective_until>now()) and public.school_result_scope_context_matches(x.metadata,v_academic_session,v_term)))
    ) x;
    return jsonb_build_object('ok', true, 'code', 'RESULT_SCORES_READ', 'rows', v_rows);
  end if;

  if v_resource = 'traits' then
    select coalesce(jsonb_agg(to_jsonb(x) order by x.student_id, x.trait_type, x.trait_name), '[]'::jsonb) into v_rows
    from (select t.id,t.student_id,t.class_key,t.trait_type,t.trait_name,t.rating,t.term from public.traits t where t.class_key=v_class_key and t.term=v_term and (v_student_id is null or t.student_id=v_student_id) and (v_broad or exists(select 1 from public.school_staff_access_scopes x where x.person_id=(v_auth->>'person_id')::uuid and x.app_code='results' and x.scope_type in ('class','subject') and x.class_key=t.class_key and x.scope_status='active' and (x.effective_from is null or x.effective_from<=now()) and (x.effective_until is null or x.effective_until>now()) and public.school_result_scope_context_matches(x.metadata,v_academic_session,v_term))) ) x;
    return jsonb_build_object('ok', true, 'code', 'RESULT_TRAITS_READ', 'rows', v_rows);
  end if;

  if v_resource = 'remarks' then
    select coalesce(jsonb_agg(to_jsonb(x) order by x.student_id), '[]'::jsonb) into v_rows
    from (select r.id,r.student_id,r.class_key,r.academic,r.form_master,r.principal,r.days_opened,r.days_present,r.term from public.remarks r where r.class_key=v_class_key and r.term=v_term and (v_student_id is null or r.student_id=v_student_id) and (v_broad or exists(select 1 from public.school_staff_access_scopes x where x.person_id=(v_auth->>'person_id')::uuid and x.app_code='results' and x.scope_type in ('class','subject') and x.class_key=r.class_key and x.scope_status='active' and (x.effective_from is null or x.effective_from<=now()) and (x.effective_until is null or x.effective_until>now()) and public.school_result_scope_context_matches(x.metadata,v_academic_session,v_term))) ) x;
    return jsonb_build_object('ok', true, 'code', 'RESULT_REMARKS_READ', 'rows', v_rows);
  end if;

  if v_resource = 'fees' then
    select coalesce(jsonb_agg(to_jsonb(x) order by x.student_id), '[]'::jsonb) into v_rows
    from (select f.id,f.student_id,f.class_key,f.total,f.paid,f.debt,f.next_term,f.resume_date,f.term from public.fees f where f.class_key=v_class_key and f.term=v_term and (v_student_id is null or f.student_id=v_student_id) and (v_broad or exists(select 1 from public.school_staff_access_scopes x where x.person_id=(v_auth->>'person_id')::uuid and x.app_code='results' and x.scope_type in ('class','subject') and x.class_key=f.class_key and x.scope_status='active' and (x.effective_from is null or x.effective_from<=now()) and (x.effective_until is null or x.effective_until>now()) and public.school_result_scope_context_matches(x.metadata,v_academic_session,v_term))) ) x;
    return jsonb_build_object('ok', true, 'code', 'RESULT_FEES_READ', 'rows', v_rows);
  end if;

  if v_resource = 'published_subjects' then
    select coalesce(jsonb_agg(to_jsonb(x) order by x.subject_index), '[]'::jsonb) into v_rows
    from (select p.id,p.class_key,p.term,p.subject_index,p.published_at from public.published_subjects p where p.class_key=v_class_key and p.term=v_term and (v_subject_index is null or p.subject_index=v_subject_index) and (v_broad or exists(select 1 from public.school_staff_access_scopes x where x.person_id=(v_auth->>'person_id')::uuid and x.app_code='results' and x.scope_type='subject' and x.class_key=p.class_key and x.subject_index=p.subject_index and x.scope_status='active' and (x.effective_from is null or x.effective_from<=now()) and (x.effective_until is null or x.effective_until>now()) and public.school_result_scope_context_matches(x.metadata,v_academic_session,v_term))) ) x;
    return jsonb_build_object('ok', true, 'code', 'RESULT_PUBLISHED_SUBJECTS_READ', 'rows', v_rows);
  end if;

  if v_resource = 'result_summary' then
    select jsonb_build_object('students', coalesce((select jsonb_agg(to_jsonb(s) order by s.name) from public.students s where s.class_key=v_class_key and not coalesce(s.archived,false) and (v_broad or exists(select 1 from public.school_staff_access_scopes x where x.person_id=(v_auth->>'person_id')::uuid and x.app_code='results' and x.scope_type in ('class','subject') and x.class_key=s.class_key and x.scope_status='active' and public.school_result_scope_context_matches(x.metadata,v_academic_session,v_term)))), '[]'::jsonb), 'scores', coalesce((select jsonb_agg(to_jsonb(s)) from public.scores s where s.class_key=v_class_key and s.term=v_term and (v_broad or exists(select 1 from public.school_staff_access_scopes x where x.person_id=(v_auth->>'person_id')::uuid and x.app_code='results' and x.scope_type='subject' and x.class_key=s.class_key and x.subject_index=s.subject_index and x.scope_status='active' and public.school_result_scope_context_matches(x.metadata,v_academic_session,v_term)))), '[]'::jsonb)) into v_rows;
    return jsonb_build_object('ok', true, 'code', 'RESULT_SUMMARY_READ', 'summary', v_rows);
  end if;

  if v_resource = 'report_card' then
    return jsonb_build_object('ok', true, 'code', 'RESULT_REPORT_CARD_READ', 'student_id', v_student_id, 'class_key', v_class_key, 'term', v_term, 'academic_session', v_academic_session);
  end if;

  return jsonb_build_object('ok', false, 'code', 'RESULT_READ_RESOURCE_NOT_ALLOWED');
end;
$function$;

revoke all on function public.school_result_read_api(uuid, text, text, jsonb) from public, anon, authenticated;

grant execute on function public.school_result_read_api(uuid, text, text, jsonb) to anon, service_role;