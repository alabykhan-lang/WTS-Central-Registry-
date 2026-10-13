-- ============================================================================
-- MIGRATION V7: Fix Missing Write Gate Function & Restore Score Saving
-- ============================================================================

-- 1. Create the missing write gate check function that school_result_authorize calls
CREATE OR REPLACE FUNCTION public.school_result_write_gate_check(p_operating_mode text, p_hold_exempt boolean)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'pg_catalog', 'extensions', 'public'
AS $function$
begin
  -- Protected actors (Owner / Proprietor / Super Administrator) are exempt from management holds
  if coalesce(p_hold_exempt, false) then
    return jsonb_build_object('ok', true);
  end if;
  
  if lower(trim(coalesce(p_operating_mode, 'read_only'))) = 'read_only' then
    return jsonb_build_object('ok', false, 'code', 'RESULT_OPERATING_MODE_READ_ONLY');
  end if;
  
  return jsonb_build_object('ok', true);
end;
$function$;

GRANT EXECUTE ON FUNCTION public.school_result_write_gate_check(text, boolean) TO anon, authenticated, service_role;

-- 2. Update school_result_authorize to handle write gates and term validations robustly
CREATE OR REPLACE FUNCTION public.school_result_authorize(
  p_session_id uuid,
  p_session_secret text,
  p_action text,
  p_class_key text DEFAULT NULL::text,
  p_subject_index integer DEFAULT NULL::integer,
  p_academic_session text DEFAULT NULL::text,
  p_term text DEFAULT NULL::text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'pg_catalog', 'extensions', 'public'
AS $function$
declare
  v_session jsonb;
  v_identity jsonb;
  v_person_id uuid;
  v_identity_account_id uuid;
  v_permissions text[];
  v_access_role text;
  v_action text := lower(trim(coalesce(p_action, '')));
  v_requires_scope boolean := false;
  v_broad_access boolean := false;
  v_class_scope boolean := false;
  v_subject_scope boolean := false;
  v_context_required boolean := false;
  v_current jsonb;
  v_write_gate jsonb;
  v_operating_mode text := 'read_only';
  v_hold_exempt boolean := false;
  v_write_enabled boolean := false;
  v_can_write boolean := false;
  v_entry_action boolean := false;
begin
  v_session := public.school_identity_session_validate(p_session_id, p_session_secret, 'results');
  if coalesce((v_session ->> 'ok')::boolean, false) is not true then
    return v_session;
  end if;

  v_person_id := (v_session ->> 'person_id')::uuid;
  v_identity_account_id := (v_session ->> 'identity_account_id')::uuid;
  v_permissions := coalesce(array(select jsonb_array_elements_text(v_session -> 'permissions')), array[]::text[]);
  v_access_role := v_session ->> 'access_role';
  
  v_identity := public.school_result_identity_resolve(v_person_id, v_identity_account_id);
  if coalesce((v_identity ->> 'ok')::boolean, false) is not true then
    return v_identity;
  end if;

  select operating_mode into v_operating_mode
  from public.school_module_operating_controls
  where app_code = 'results';
  v_operating_mode := coalesce(v_operating_mode, 'read_only');
  v_hold_exempt := wts_internal.school_registry_is_protected_actor(v_person_id);

  v_entry_action := v_action in (
    'scores.enter', 'smart.sheet.create', 'smart.scores.commit',
    'traits.enter', 'remarks.enter', 'fees.update'
  );
  
  v_write_enabled := v_hold_exempt
    or public.school_result_permission_allowed(v_permissions, 'results.manage')
    or public.school_result_write_enabled(v_person_id);
  
  v_can_write := v_write_enabled and (
    public.school_result_permission_allowed(v_permissions, 'scores.enter')
    or public.school_result_permission_allowed(v_permissions, 'results.manage')
  );

  if not v_can_write then
    v_permissions := array(
      select distinct x.permission
      from unnest(v_permissions) as x(permission)
      where x.permission not in (
        'scores.enter', 'result_entry.create', 'result_entry.edit',
        'result_entry.submit', 'traits.enter', 'remarks.enter', 'fees.update'
      )
    );
  end if;

  if v_action = 'identity.context' then
    return jsonb_build_object(
      'ok', true,
      'code', 'RESULT_AUTHORIZED',
      'person_id', v_person_id,
      'identity_account_id', v_identity_account_id,
      'access_role', v_access_role,
      'permissions', v_permissions,
      'result_user', v_identity -> 'result_user',
      'staff', v_identity -> 'staff',
      'expires_at', v_session -> 'expires_at',
      'operating_mode', v_operating_mode,
      'read_only', not v_can_write,
      'result_write_enabled', v_can_write
    );
  end if;

  if v_entry_action and not v_can_write then
    return jsonb_build_object(
      'ok', false,
      'code', 'RESULT_STAFF_WRITE_DISABLED',
      'operating_mode', v_operating_mode,
      'result_write_enabled', false
    );
  end if;

  if not public.school_result_permission_allowed(v_permissions, v_action) then
    return jsonb_build_object(
      'ok', false,
      'code', 'RESULT_PERMISSION_DENIED',
      'required_permission', v_action
    );
  end if;

  v_broad_access := public.school_result_permission_allowed(v_permissions, 'results.manage')
    or (
      v_can_write
      and coalesce((
        select write_scope
        from public.school_result_staff_write_access
        where app_code = 'results' and person_id = v_person_id
      ), 'default') = 'override'
    );

  v_requires_scope := v_action in (
    'scores.enter', 'traits.enter', 'remarks.enter', 'results.view_assigned',
    'results.review', 'results.approve', 'results.publish', 'results.unpublish',
    'report_cards.generate', 'results.export'
  );

  if v_action = 'scores.enter' and p_subject_index is null then
    return jsonb_build_object('ok', false, 'code', 'RESULT_SUBJECT_SCOPE_REQUIRED');
  end if;

  if v_requires_scope and not v_broad_access then
    if nullif(trim(coalesce(p_class_key, '')), '') is null then
      return jsonb_build_object('ok', false, 'code', 'RESULT_CLASS_SCOPE_REQUIRED');
    end if;

    select exists(
      select 1
      from public.school_staff_access_scopes s
      where s.person_id = v_person_id
        and s.app_code = 'results'
        and s.scope_type in ('class', 'subject')
        and s.class_key = trim(p_class_key)
        and s.scope_status = 'active'
        and (s.effective_from is null or s.effective_from <= now())
        and (s.effective_until is null or s.effective_until > now())
        and public.school_result_scope_context_matches(s.metadata, p_academic_session, p_term)
    ) into v_class_scope;

    if not v_class_scope then
      return jsonb_build_object('ok', false, 'code', 'RESULT_CLASS_SCOPE_DENIED');
    end if;

    if p_subject_index is not null then
      select exists(
        select 1
        from public.school_staff_access_scopes s
        where s.person_id = v_person_id
          and s.app_code = 'results'
          and s.scope_type = 'subject'
          and s.class_key = trim(p_class_key)
          and s.subject_index = p_subject_index
          and s.scope_status = 'active'
          and (s.effective_from is null or s.effective_from <= now())
          and (s.effective_until is null or s.effective_until > now())
          and public.school_result_scope_context_matches(s.metadata, p_academic_session, p_term)
      ) into v_subject_scope;

      if not v_subject_scope then
        return jsonb_build_object('ok', false, 'code', 'RESULT_SUBJECT_SCOPE_DENIED');
      end if;
    end if;
  end if;

  v_context_required := v_entry_action or v_action in (
    'report_cards.generate', 'results.review', 'results.approve',
    'results.publish', 'results.unpublish'
  );

  if v_context_required then
    v_current := public.school_academic_current();
    if nullif(trim(coalesce(p_academic_session, '')), '') is null
       or nullif(trim(coalesce(p_term, '')), '') is null then
      return jsonb_build_object('ok', false, 'code', 'RESULT_CONTEXT_REQUIRED');
    end if;

    if p_academic_session != (v_current ->> 'academic_session')
       or p_term != (v_current ->> 'term') then
      return jsonb_build_object('ok', false, 'code', 'RESULT_HISTORICAL_ENTRY_DENIED');
    end if;

    if v_entry_action then
      v_write_gate := public.school_result_write_gate_check(v_operating_mode, v_hold_exempt);
      if coalesce((v_write_gate ->> 'ok')::boolean, false) is not true then
        return v_write_gate;
      end if;

      v_write_gate := public.school_academic_term_write_gate(trim(p_academic_session), trim(p_term));
      if coalesce((v_write_gate ->> 'ok')::boolean, false) is not true then
        return jsonb_build_object(
          'ok', false,
          'code', 'RESULT_ACADEMIC_TERM_READ_ONLY',
          'term_status', v_write_gate ->> 'term_status'
        );
      end if;
    end if;
  end if;

  return jsonb_build_object(
    'ok', true,
    'code', 'RESULT_AUTHORIZED',
    'person_id', v_person_id,
    'broad_access', v_broad_access,
    'class_scope', v_class_scope,
    'subject_scope', v_subject_scope,
    'operating_mode', v_operating_mode,
    'read_only', not v_can_write,
    'result_write_enabled', v_can_write
  );
end;
$function$;

GRANT EXECUTE ON FUNCTION public.school_result_authorize(uuid, text, text, text, integer, text, text) TO anon, authenticated, service_role;

-- 3. Update school_result_score_update with proper delete support and informative error handling
CREATE OR REPLACE FUNCTION public.school_result_score_update(
  p_session_id uuid,
  p_session_secret text,
  p_student_id uuid,
  p_class_key text,
  p_subject_index integer,
  p_term text,
  p_academic_session text,
  p_ca1 numeric,
  p_ca2 numeric,
  p_ca3 numeric,
  p_exam numeric
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'pg_catalog', 'extensions', 'public'
AS $function$
declare
  v_session jsonb;
  v_auth jsonb;
  v_person_id uuid;
  v_staff_id uuid;
  v_request_id uuid := gen_random_uuid();
  v_before jsonb;
  v_after jsonb;
  v_score_id uuid;
  v_failure_code text;
  v_action_type text;
  v_current_class text;
begin
  v_session := public.school_identity_session_validate(
    p_session_id,
    p_session_secret,
    'results'
  );
  if coalesce((v_session ->> 'ok')::boolean, false) is not true then
    return v_session;
  end if;

  v_person_id := (v_session ->> 'person_id')::uuid;
  select s.id
    into v_staff_id
  from public.staff_attendance_profiles s
  where s.central_person_id = v_person_id
  order by s.id
  limit 1;

  v_auth := public.school_result_authorize(
    p_session_id,
    p_session_secret,
    'scores.enter',
    p_class_key,
    p_subject_index,
    p_academic_session,
    p_term
  );

  if coalesce((v_auth ->> 'ok')::boolean, false) is not true then
    insert into public.school_result_score_audit(
      request_id, actor_person_id, staff_id, student_id, class_key,
      subject_index, academic_session, term, component, action_type,
      source_application, success, failure_code
    ) values (
      v_request_id, v_person_id, v_staff_id, p_student_id, p_class_key,
      p_subject_index, p_academic_session, p_term, 'score_record',
      'score_write_rejected', 'result_portal', false,
      coalesce(v_auth ->> 'code', 'RESULT_SCORE_WRITE_REJECTED')
    );

    insert into public.school_registry_audit(
      actor_type, actor_id, action, entity_type, entity_id, request_id,
      details
    ) values (
      'result_session', v_person_id::text, 'result.score.write_failed',
      'scores', p_student_id::text, v_request_id,
      jsonb_build_object(
        'staff_id', v_staff_id,
        'person_id', v_person_id,
        'class_key', p_class_key,
        'subject_index', p_subject_index,
        'academic_session', p_academic_session,
        'term', p_term,
        'source_application', 'result_portal',
        'success', false,
        'failure_code', coalesce(v_auth ->> 'code', 'RESULT_SCORE_WRITE_REJECTED')
      )
    );

    return v_auth || jsonb_build_object('request_id', v_request_id);
  end if;

  if p_student_id is null
     or nullif(trim(coalesce(p_class_key, '')), '') is null
     or p_subject_index is null
     or p_subject_index < 0
     or nullif(trim(coalesce(p_term, '')), '') is null
     or nullif(trim(coalesce(p_academic_session, '')), '') is null then
    v_failure_code := 'RESULT_SCORE_PAYLOAD_INVALID';
  elsif not exists (
    select 1
    from public.result_subject_catalog r
    where r.class_key = trim(p_class_key)
      and r.subject_index = p_subject_index
  ) then
    v_failure_code := 'RESULT_SUBJECT_NOT_ASSIGNED';
  else
    select s.class_key
      into v_current_class
    from public.students s
    where s.id = p_student_id
      and coalesce(s.archived, false) = false;

    if v_current_class is null or v_current_class <> trim(p_class_key) then
      v_failure_code := 'RESULT_STUDENT_CLASS_MISMATCH';
    elsif (p_ca1 is not null and (p_ca1 < 0 or p_ca1 > 100))
       or (p_ca2 is not null and (p_ca2 < 0 or p_ca2 > 100))
       or (p_ca3 is not null and (p_ca3 < 0 or p_ca3 > 100))
       or (p_exam is not null and (p_exam < 0 or p_exam > 100)) then
      v_failure_code := 'RESULT_SCORE_RANGE_INVALID';
    end if;
  end if;

  if v_failure_code is not null then
    insert into public.school_result_score_audit(
      request_id, actor_person_id, staff_id, student_id, class_key,
      subject_index, academic_session, term, component, action_type,
      source_application, success, failure_code
    ) values (
      v_request_id, v_person_id, v_staff_id, p_student_id, p_class_key,
      p_subject_index, p_academic_session, p_term, 'score_record',
      'score_write_rejected', 'result_portal', false, v_failure_code
    );

    insert into public.school_registry_audit(
      actor_type, actor_id, action, entity_type, entity_id, request_id,
      details
    ) values (
      'result_session', v_person_id::text, 'result.score.write_failed',
      'scores', p_student_id::text, v_request_id,
      jsonb_build_object(
        'staff_id', v_staff_id,
        'person_id', v_person_id,
        'class_key', p_class_key,
        'subject_index', p_subject_index,
        'academic_session', p_academic_session,
        'term', p_term,
        'source_application', 'result_portal',
        'success', false,
        'failure_code', v_failure_code
      )
    );

    return jsonb_build_object(
      'ok', false,
      'code', v_failure_code,
      'request_id', v_request_id
    );
  end if;

  select to_jsonb(s), s.id
    into v_before, v_score_id
  from public.scores s
  where s.student_id = p_student_id
    and s.class_key = trim(p_class_key)
    and s.subject_index = p_subject_index
    and s.academic_session = trim(p_academic_session)
    and s.term = trim(p_term)
  for update;

  begin
    if p_ca1 is null and p_ca2 is null and p_ca3 is null and p_exam is null then
      delete from public.scores
      where student_id = p_student_id
        and class_key = trim(p_class_key)
        and subject_index = p_subject_index
        and academic_session = trim(p_academic_session)
        and term = trim(p_term)
      returning id into v_score_id;
      v_after := null;
    else
      insert into public.scores(
        student_id, class_key, subject_index, academic_session, term, ca1, ca2, ca3, exam
      ) values (
        p_student_id, trim(p_class_key), p_subject_index, trim(p_academic_session), trim(p_term),
        p_ca1, p_ca2, p_ca3, p_exam
      )
      on conflict (student_id, class_key, subject_index, academic_session, term) do update
      set class_key = excluded.class_key,
          ca1 = excluded.ca1,
          ca2 = excluded.ca2,
          ca3 = excluded.ca3,
          exam = excluded.exam
      returning id into v_score_id;

      select to_jsonb(s)
        into v_after
      from public.scores s
      where s.id = v_score_id;
    end if;
  exception when others then
    insert into public.school_result_score_audit(
      request_id, actor_person_id, staff_id, student_id, class_key,
      subject_index, academic_session, term, component, action_type,
      old_record, source_application, success, failure_code
    ) values (
      v_request_id, v_person_id, v_staff_id, p_student_id, p_class_key,
      p_subject_index, p_academic_session, p_term, 'score_record',
      'score_write_failed', v_before, 'result_portal', false,
      'RESULT_SCORE_SAVE_FAILED'
    );

    insert into public.school_registry_audit(
      actor_type, actor_id, action, entity_type, entity_id, request_id,
      before_data, details
    ) values (
      'result_session', v_person_id::text, 'result.score.write_failed',
      'scores', coalesce(v_score_id, p_student_id)::text, v_request_id,
      v_before,
      jsonb_build_object(
        'staff_id', v_staff_id,
        'person_id', v_person_id,
        'class_key', p_class_key,
        'subject_index', p_subject_index,
        'academic_session', p_academic_session,
        'term', p_term,
        'source_application', 'result_portal',
        'success', false,
        'failure_code', 'RESULT_SCORE_SAVE_FAILED',
        'error_detail', SQLERRM
      )
    );

    return jsonb_build_object(
      'ok', false,
      'code', 'RESULT_SCORE_SAVE_FAILED',
      'error_detail', SQLERRM,
      'request_id', v_request_id
    );
  end;

  v_action_type := case
    when v_before is null then 'score_entry'
    when (v_before ->> 'ca1') is distinct from (v_after ->> 'ca1')
      or (v_before ->> 'ca2') is distinct from (v_after ->> 'ca2')
      or (v_before ->> 'ca3') is distinct from (v_after ->> 'ca3')
      or (v_before ->> 'exam') is distinct from (v_after ->> 'exam')
      then 'score_correction'
    else 'score_save_confirmed'
  end;

  insert into public.school_result_score_audit(
    request_id, actor_person_id, staff_id, student_id, class_key,
    subject_index, academic_session, term, component, old_value,
    new_value, old_record, new_record, action_type, source_application,
    success, failure_code
  )
  select
    v_request_id, v_person_id, v_staff_id, p_student_id, trim(p_class_key),
    p_subject_index, trim(p_academic_session), trim(p_term), x.component,
    x.old_value, x.new_value, v_before, v_after, v_action_type,
    'result_portal', true, null
  from (
    values
      ('ca1'::text, nullif(v_before ->> 'ca1', '')::numeric, nullif(v_after ->> 'ca1', '')::numeric),
      ('ca2'::text, nullif(v_before ->> 'ca2', '')::numeric, nullif(v_after ->> 'ca2', '')::numeric),
      ('ca3'::text, nullif(v_before ->> 'ca3', '')::numeric, nullif(v_after ->> 'ca3', '')::numeric),
      ('exam'::text, nullif(v_before ->> 'exam', '')::numeric, nullif(v_after ->> 'exam', '')::numeric)
  ) as x(component, old_value, new_value);

  insert into public.school_registry_audit(
    actor_type, actor_id, action, entity_type, entity_id, request_id,
    before_data, after_data, details
  ) values (
    'result_session', v_person_id::text,
    case when v_action_type = 'score_entry'
      then 'result.score.entered'
      else 'result.score.corrected'
    end,
    'scores', coalesce(v_score_id, (v_before->>'id')::uuid, p_student_id)::text, v_request_id, v_before, v_after,
    jsonb_build_object(
      'staff_id', v_staff_id,
      'person_id', v_person_id,
      'student_id', p_student_id,
      'class_key', trim(p_class_key),
      'subject_index', p_subject_index,
      'academic_session', trim(p_academic_session),
      'term', trim(p_term),
      'source_application', 'result_portal',
      'success', true
    )
  );

  return jsonb_build_object(
    'ok', true,
    'code', 'RESULT_SCORE_SAVED',
    'request_id', v_request_id,
    'persisted', true,
    'student_id', p_student_id,
    'class_key', trim(p_class_key),
    'subject_index', p_subject_index,
    'term', trim(p_term),
    'academic_session', trim(p_academic_session),
    'score', jsonb_build_object(
      'id', coalesce(v_after ->> 'id', v_before ->> 'id'),
      'student_id', p_student_id,
      'class_key', trim(p_class_key),
      'subject_index', p_subject_index,
      'academic_session', trim(p_academic_session),
      'term', trim(p_term),
      'ca1', v_after -> 'ca1',
      'ca2', v_after -> 'ca2',
      'ca3', v_after -> 'ca3',
      'exam', v_after -> 'exam'
    )
  );
exception when others then
  return jsonb_build_object(
    'ok', false,
    'code', 'RESULT_SCORE_SAVE_FAILED',
    'error_detail', SQLERRM,
    'request_id', v_request_id
  );
end;
$function$;

GRANT EXECUTE ON FUNCTION public.school_result_score_update(uuid, text, uuid, text, integer, text, text, numeric, numeric, numeric, numeric) TO anon, authenticated, service_role;
