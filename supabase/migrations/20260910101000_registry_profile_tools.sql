-- Profile-scoped management tools for departments and custom portfolios.
-- The former Portfolio and Portal Access pages are intentionally gone from the
-- Registry shell; this API keeps profile work auditable and server-enforced.

create or replace function public.school_registry_profile_session_api(
  p_session_id uuid,
  p_session_secret text,
  p_action text,
  p_target_type text default null,
  p_target_id uuid default null,
  p_department_code text default null,
  p_portfolio_name text default null,
  p_portfolio_description text default null,
  p_assignment_id uuid default null,
  p_request_id uuid default null
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public', 'wts_internal'
as $function$
declare
  v_auth jsonb;
  v_ent jsonb;
  v_actor uuid;
  v_action text := lower(trim(coalesce(p_action, '')));
  v_target text := lower(trim(coalesce(p_target_type, '')));
  v_request uuid := coalesce(p_request_id, gen_random_uuid());
  v_operation text := 'registry_profile:' || lower(trim(coalesce(p_action, '')));
  v_result jsonb;
  v_existing jsonb;
  v_student public.students%rowtype;
  v_staff public.staff_attendance_profiles%rowtype;
  v_class public.school_classes%rowtype;
  v_current jsonb;
  v_target_class text;
  v_department text := lower(trim(coalesce(p_department_code, '')));
  v_before jsonb;
  v_after jsonb;
  v_holder_person uuid;
  v_portfolio_code text;
  v_name text := left(trim(coalesce(p_portfolio_name, '')), 120);
  v_description text := left(trim(coalesce(p_portfolio_description, '')), 500);
  v_assignment public.school_portfolio_assignments%rowtype;
  v_catalog public.school_portfolio_catalog%rowtype;
  v_row record;
begin
  v_auth := wts_internal.school_registry_session_entitlements(p_session_id, p_session_secret);
  if coalesce((v_auth ->> 'ok')::boolean, false) is not true then return v_auth; end if;
  v_ent := coalesce(v_auth -> 'entitlements', '{}'::jsonb);
  v_actor := nullif(v_auth -> 'actor' ->> 'personId', '')::uuid;

  if v_action not in ('read', 'department.update', 'portfolio.create', 'portfolio.end') then
    return jsonb_build_object('ok', false, 'code', 'PROFILE_ACTION_INVALID');
  end if;
  if v_target not in ('student', 'staff') then
    return jsonb_build_object('ok', false, 'code', 'PROFILE_TARGET_INVALID');
  end if;

  if v_action <> 'read' then
    select outcome into v_existing
    from public.school_registry_request_outcomes
    where request_id = v_request and actor_person_id = v_actor and operation = v_operation;
    if found then return v_existing; end if;
    if exists (select 1 from public.school_registry_request_outcomes where request_id = v_request) then
      return jsonb_build_object('ok', false, 'code', 'IDEMPOTENCY_KEY_REUSED');
    end if;
  end if;

  if v_target = 'student' then
    select s.* into v_student from public.students s where s.id = p_target_id for update;
    if not found then return jsonb_build_object('ok', false, 'code', 'STUDENT_NOT_FOUND'); end if;
    select c.* into v_class from public.school_classes c where c.class_key = v_student.class_key;
    if not (
      wts_internal.school_registry_has_capability(v_ent, 'students.school.read')
      or (wts_internal.school_registry_has_capability(v_ent, 'students.stage.read') and v_class.stage_code in (select value from jsonb_array_elements_text(coalesce(v_ent -> 'stageScopes', '[]'::jsonb))))
      or (wts_internal.school_registry_has_capability(v_ent, 'students.class.read') and v_student.class_key in (select value from jsonb_array_elements_text(coalesce(v_ent -> 'classScopes', '[]'::jsonb))))
    ) then
      return jsonb_build_object('ok', false, 'code', 'REGISTRY_SCOPE_DENIED');
    end if;
    if v_action = 'read' then
      return jsonb_build_object(
        'ok', true,
        'targetType', 'student',
        'profile', jsonb_build_object(
          'id', v_student.id,
          'central_person_id', v_student.central_person_id,
          'name', v_student.name,
          'gender', v_student.gender,
          'admno', v_student.admno,
          'class_key', v_student.class_key,
          'class_label', v_class.display_name,
          'stage_code', v_class.stage_code,
          'department_code', v_student.department_code,
          'archived', v_student.archived,
          'lifecycle_status', v_student.lifecycle_status,
          'photo', v_student.photo
        ),
        'portfolios', case when wts_internal.school_registry_has_capability(v_ent, 'portfolio.manage') then (
          select coalesce(jsonb_agg(jsonb_build_object(
            'assignment_id', a.id,
            'portfolio_code', a.portfolio_code,
            'name', c.portfolio_name,
            'description', c.metadata ->> 'description',
            'custom', coalesce((c.metadata ->> 'custom')::boolean, false),
            'assignment_status', a.assignment_status,
            'academic_session', a.academic_session,
            'office_name', a.office_name,
            'effective_from', a.effective_from,
            'effective_until', a.effective_until
          ) order by a.assignment_status = 'active' desc, a.effective_from desc), '[]'::jsonb)
          from public.school_portfolio_assignments a
          join public.school_portfolio_catalog c on c.portfolio_code = a.portfolio_code
          where a.student_id = v_student.id
            and coalesce(c.metadata ->> 'visibility', 'school') <> 'technical_only'
        ) else '[]'::jsonb end
      );
    end if;
  else
    select s.* into v_staff from public.staff_attendance_profiles s where s.id = p_target_id for update;
    if not found or v_staff.registration_status <> 'active' or v_staff.employment_status <> 'active' then
      return jsonb_build_object('ok', false, 'code', 'STAFF_NOT_FOUND');
    end if;
    if not wts_internal.school_registry_has_capability(v_ent, 'portfolio.manage') then
      return jsonb_build_object('ok', false, 'code', 'REGISTRY_CAPABILITY_DENIED');
    end if;
    if v_action = 'read' then
      return jsonb_build_object(
        'ok', true,
        'targetType', 'staff',
        'profile', jsonb_build_object(
          'id', v_staff.id,
          'central_person_id', v_staff.central_person_id,
          'full_name', v_staff.full_name,
          'staff_number', v_staff.staff_number,
          'designation', case when lower(coalesce(v_staff.designation, '')) ~ '(super[ _-]*administrator|system[ _-]*owner|developer)' then null else v_staff.designation end,
          'department', v_staff.department,
          'staff_category', v_staff.staff_category,
          'employment_status', v_staff.employment_status,
          'photo', v_staff.photo
        ),
        'portfolios', (
          select coalesce(jsonb_agg(jsonb_build_object(
            'assignment_id', a.id,
            'portfolio_code', a.portfolio_code,
            'name', c.portfolio_name,
            'description', c.metadata ->> 'description',
            'custom', coalesce((c.metadata ->> 'custom')::boolean, false),
            'assignment_status', a.assignment_status,
            'academic_session', a.academic_session,
            'office_name', a.office_name,
            'effective_from', a.effective_from,
            'effective_until', a.effective_until
          ) order by a.assignment_status = 'active' desc, a.effective_from desc), '[]'::jsonb)
          from public.school_portfolio_assignments a
          join public.school_portfolio_catalog c on c.portfolio_code = a.portfolio_code
          where a.staff_id = v_staff.id
            and coalesce(c.metadata ->> 'visibility', 'school') <> 'technical_only'
        )
      );
    end if;
  end if;

  if v_action = 'department.update' then
    if v_target <> 'student' then return jsonb_build_object('ok', false, 'code', 'DEPARTMENT_STUDENT_ONLY'); end if;
    if v_department not in ('arts', 'science', 'business') then
      return jsonb_build_object('ok', false, 'code', 'DEPARTMENT_INVALID');
    end if;
    if lower(coalesce(v_student.class_key, '')) !~ '^ss[23](-(arts|science|business|general))?$' then
      return jsonb_build_object('ok', false, 'code', 'DEPARTMENT_SECONDARY_ONLY');
    end if;
    if not (
      wts_internal.school_registry_has_capability(v_ent, 'students.school.manage')
      or (wts_internal.school_registry_has_capability(v_ent, 'students.class.manage') and v_student.class_key in (select value from jsonb_array_elements_text(coalesce(v_ent -> 'classScopes', '[]'::jsonb))))
    ) then
      return jsonb_build_object('ok', false, 'code', 'REGISTRY_CAPABILITY_DENIED');
    end if;
    v_target_class := split_part(v_student.class_key, '-', 1) || '-' || v_department;
    select c.* into v_class from public.school_classes c where c.class_key = v_target_class and c.is_active and c.stage_code = 'secondary';
    if not found then return jsonb_build_object('ok', false, 'code', 'DEPARTMENT_CLASS_NOT_CONFIGURED'); end if;
    v_before := to_jsonb(v_student);
    update public.students
    set class_key = v_target_class,
        department_code = v_department,
        updated_at = now()
    where id = v_student.id;
    for v_row in
      select e.*
      from public.school_student_enrollments e
      where e.student_id = v_student.id and e.enrollment_status = 'active'
        and (e.academic_session = (public.school_academic_current() ->> 'academic_session') or e.class_key = v_student.class_key)
      for update
    loop
      v_before := v_before || jsonb_build_object('enrollment_before', to_jsonb(v_row));
      update public.school_student_enrollments
      set class_key = v_target_class,
          metadata = coalesce(metadata, '{}'::jsonb) || jsonb_build_object(
            'department_change', true,
            'changed_from_class_key', v_student.class_key,
            'changed_to_class_key', v_target_class,
            'changed_by_person_id', v_actor,
            'changed_at', now()
          ),
          updated_at = now()
      where id = v_row.id;
    end loop;
    select to_jsonb(s) into v_after from public.students s where s.id = v_student.id;
    insert into public.school_registry_audit(actor_type, actor_id, action, entity_type, entity_id, request_id, before_data, after_data, details)
    values('person', v_actor::text, 'student.department_updated', 'student', v_student.id::text, v_request, v_before, v_after,
      jsonb_build_object('from_class_key', v_student.class_key, 'to_class_key', v_target_class, 'department', v_department, 'history_preserved', true));
    v_result := jsonb_build_object('ok', true, 'code', 'DEPARTMENT_UPDATED', 'studentId', v_student.id, 'classKey', v_target_class, 'departmentCode', v_department, 'request_id', v_request);
    insert into public.school_registry_request_outcomes(request_id, actor_person_id, operation, outcome) values(v_request, v_actor, v_operation, v_result);
    return v_result;
  end if;

  if v_action = 'portfolio.create' then
    if not wts_internal.school_registry_has_capability(v_ent, 'portfolio.manage') then return jsonb_build_object('ok', false, 'code', 'REGISTRY_CAPABILITY_DENIED'); end if;
    if length(v_name) < 2 then return jsonb_build_object('ok', false, 'code', 'PORTFOLIO_NAME_REQUIRED'); end if;
    if v_target = 'student' then
      if v_student.archived or lower(coalesce(v_class.stage_code, '')) <> 'secondary' or lower(coalesce(v_student.class_key, '')) !~ '^ss[123](-|$)' then
        return jsonb_build_object('ok', false, 'code', 'PORTFOLIO_SENIOR_SECONDARY_ONLY');
      end if;
      v_holder_person := v_student.central_person_id;
    else
      v_holder_person := v_staff.central_person_id;
    end if;
    if v_holder_person is null then return jsonb_build_object('ok', false, 'code', 'PORTFOLIO_HOLDER_NOT_FOUND'); end if;
    if exists (
      select 1 from public.school_portfolio_assignments a
      join public.school_portfolio_catalog c on c.portfolio_code = a.portfolio_code
      where a.holder_person_id = v_holder_person and a.assignment_status = 'active'
        and coalesce(c.metadata ->> 'custom', 'false') = 'true'
        and lower(c.portfolio_name) = lower(v_name)
    ) then return jsonb_build_object('ok', false, 'code', 'PROFILE_CONFLICT'); end if;
    v_portfolio_code := 'custom_' || replace(gen_random_uuid()::text, '-', '');
    insert into public.school_portfolio_catalog(portfolio_code, portfolio_name, holder_type, jurisdiction, is_protected, is_singleton, is_active, sort_order, metadata)
    values(v_portfolio_code, v_name, v_target, 'self', false, false, true, 500,
      jsonb_build_object('custom', true, 'visibility', 'profile_only', 'description', nullif(v_description, ''), 'created_by_person_id', v_actor, 'target_id', p_target_id));
    insert into public.school_portfolio_assignments(portfolio_code, holder_type, staff_id, student_id, holder_person_id, academic_session, scope_type, assigned_by_person_id, reason, metadata)
    values(v_portfolio_code, v_target, case when v_target = 'staff' then v_staff.id else null end, case when v_target = 'student' then v_student.id else null end, v_holder_person, (public.school_academic_current() ->> 'academic_session'), 'self', v_actor, 'Custom profile portfolio created through Central Registry', jsonb_build_object('custom', true, 'request_id', v_request));
    select a.* into v_assignment from public.school_portfolio_assignments a where a.portfolio_code = v_portfolio_code and a.holder_person_id = v_holder_person and a.assignment_status = 'active' order by a.created_at desc limit 1;
    insert into public.school_registry_audit(actor_type, actor_id, action, entity_type, entity_id, request_id, after_data, details)
    values('person', v_actor::text, 'profile.custom_portfolio_created', 'school_portfolio_assignment', v_assignment.id::text, v_request, to_jsonb(v_assignment), jsonb_build_object('holder_type', v_target, 'target_id', p_target_id, 'portfolio_code', v_portfolio_code));
    v_result := jsonb_build_object('ok', true, 'code', 'PROFILE_PORTFOLIO_CREATED', 'assignmentId', v_assignment.id, 'portfolioCode', v_portfolio_code, 'name', v_name, 'request_id', v_request);
    insert into public.school_registry_request_outcomes(request_id, actor_person_id, operation, outcome) values(v_request, v_actor, v_operation, v_result);
    return v_result;
  end if;

  if v_action = 'portfolio.end' then
    if not wts_internal.school_registry_has_capability(v_ent, 'portfolio.manage') then return jsonb_build_object('ok', false, 'code', 'REGISTRY_CAPABILITY_DENIED'); end if;
    select a.* into v_assignment
    from public.school_portfolio_assignments a
    join public.school_portfolio_catalog c on c.portfolio_code = a.portfolio_code
    where a.id = p_assignment_id and a.assignment_status = 'active'
      and coalesce(c.metadata ->> 'custom', 'false') = 'true'
      and ((v_target = 'staff' and a.staff_id = v_staff.id) or (v_target = 'student' and a.student_id = v_student.id))
    for update;
    if not found then return jsonb_build_object('ok', false, 'code', 'PORTFOLIO_ASSIGNMENT_NOT_FOUND'); end if;
    v_before := to_jsonb(v_assignment);
    update public.school_portfolio_assignments
    set assignment_status = 'ended',
        effective_until = greatest(now(), effective_from + interval '1 second'),
        reason = 'Custom profile portfolio removed through Central Registry',
        metadata = coalesce(metadata, '{}'::jsonb) || jsonb_build_object('ended_by_person_id', v_actor, 'ended_at', now(), 'request_id', v_request),
        updated_at = now()
    where id = v_assignment.id;
    update public.school_portfolio_catalog set is_active = false, updated_at = now() where portfolio_code = v_assignment.portfolio_code;
    select to_jsonb(a) into v_after from public.school_portfolio_assignments a where a.id = v_assignment.id;
    insert into public.school_registry_audit(actor_type, actor_id, action, entity_type, entity_id, request_id, before_data, after_data, details)
    values('person', v_actor::text, 'profile.custom_portfolio_ended', 'school_portfolio_assignment', v_assignment.id::text, v_request, v_before, v_after, jsonb_build_object('target_type', v_target, 'target_id', p_target_id));
    v_result := jsonb_build_object('ok', true, 'code', 'PROFILE_PORTFOLIO_ENDED', 'assignmentId', v_assignment.id, 'request_id', v_request);
    insert into public.school_registry_request_outcomes(request_id, actor_person_id, operation, outcome) values(v_request, v_actor, v_operation, v_result);
    return v_result;
  end if;

  return jsonb_build_object('ok', false, 'code', 'PROFILE_ACTION_UNKNOWN');
exception when others then
  return jsonb_build_object('ok', false, 'code', 'PROFILE_OPERATION_FAILED');
end;
$function$;

revoke all on function public.school_registry_profile_session_api(uuid, text, text, text, uuid, text, text, text, uuid, uuid)
  from public, authenticated;
grant execute on function public.school_registry_profile_session_api(uuid, text, text, text, uuid, text, text, text, uuid, uuid)
  to anon;
