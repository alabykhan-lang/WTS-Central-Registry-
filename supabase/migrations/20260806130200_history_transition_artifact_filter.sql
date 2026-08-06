-- The trigger on students() can create a current-session mirror while a
-- transition changes class keys. Those repair rows are marked explicitly and
-- must never appear as historical student records.
create or replace function public.school_result_history_read(
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
  v_auth jsonb;
  v_permissions text[];
  v_action text := lower(trim(coalesce(p_action, '')));
  v_session text := nullif(trim(coalesce(p_payload ->> 'academic_session', '')), '');
  v_term text := nullif(trim(coalesce(p_payload ->> 'term', '')), '');
  v_class_key text := nullif(trim(coalesce(p_payload ->> 'class_key', '')), '');
  v_student_id uuid;
  v_rows jsonb;
begin
  begin
    if nullif(p_payload ->> 'student_id', '') is not null then
      v_student_id := (p_payload ->> 'student_id')::uuid;
    end if;
  exception when others then
    return jsonb_build_object('ok', false, 'code', 'RESULT_HISTORY_FILTER_INVALID');
  end;

  v_auth := public.school_result_authorize(p_session_id, p_session_secret, 'identity.context');
  if coalesce((v_auth ->> 'ok')::boolean, false) is not true then return v_auth; end if;
  v_permissions := coalesce(array(select jsonb_array_elements_text(v_auth -> 'permissions')), array[]::text[]);
  if not public.school_result_permission_allowed(v_permissions, 'results.view_assigned')
     and not public.school_result_permission_allowed(v_permissions, 'results.manage') then
    return jsonb_build_object('ok', false, 'code', 'RESULT_PERMISSION_DENIED', 'required_permission', 'results.view_assigned');
  end if;

  if v_action = 'read' then
    select coalesce(jsonb_agg(to_jsonb(x) order by x.academic_session desc,
      case x.term when '1st Term' then 1 when '2nd Term' then 2 when '3rd Term' then 3 else 9 end), '[]'::jsonb)
      into v_rows
    from (
      select distinct c.academic_session, c.term, c.term_status, c.is_current,
        (select count(*) from public.school_student_enrollments e
          where e.academic_session = c.academic_session
            and coalesce(e.metadata ->> 'transition_artifact', 'false') <> 'true') as enrolled_students,
        (select count(*) from public.school_student_enrollments e
          where e.academic_session = c.academic_session
            and coalesce(e.metadata ->> 'transition_artifact', 'false') <> 'true'
            and e.enrollment_status = 'graduated') as graduating_students
      from (
        select t.academic_session, t.term_name as term, t.term_status, t.is_current
        from public.school_academic_terms t
        union all
        select distinct s.academic_session, s.term, 'archived'::text, false from public.scores s
        union all
        select distinct e.academic_session, '3rd Term', 'archived'::text, false
        from public.school_student_enrollments e
        where coalesce(e.metadata ->> 'transition_artifact', 'false') <> 'true'
      ) c
      where not c.is_current
    ) x;
    return jsonb_build_object(
      'ok', true,
      'code', 'RESULT_HISTORY_READ',
      'read_only', true,
      'contexts', v_rows,
      'transitions', coalesce((select jsonb_agg(to_jsonb(r) order by r.created_at desc) from public.school_academic_transition_runs r), '[]'::jsonb)
    );
  end if;

  if v_session is null then return jsonb_build_object('ok', false, 'code', 'RESULT_HISTORY_SESSION_REQUIRED'); end if;

  if v_action in ('students', 'graduates') then
    if v_action = 'students' and v_class_key is null then
      return jsonb_build_object('ok', false, 'code', 'RESULT_HISTORY_CLASS_REQUIRED');
    end if;
    select coalesce(jsonb_agg(to_jsonb(x) order by x.name), '[]'::jsonb)
      into v_rows
    from (
      select s.id, s.name, s.gender, s.admno, s.house, s.age, s.photo,
             s.created_at, s.archived, s.archived_at, s.archived_reason,
             s.previous_class_key, s.lifecycle_status, s.admission_date,
             s.admission_source, s.updated_at, s.student_number_status,
             e.class_key as historical_class_key, e.enrollment_status,
             e.started_on, e.ended_on, e.metadata
      from public.school_student_enrollments e
      join public.students s on s.id = e.student_id
      where e.academic_session = v_session
        and coalesce(e.metadata ->> 'transition_artifact', 'false') <> 'true'
        and (v_action = 'graduates' and (e.enrollment_status = 'graduated' or e.class_key in ('ss3-arts','ss3-science'))
             or v_action = 'students' and e.class_key = v_class_key)
        and (v_student_id is null or e.student_id = v_student_id)
    ) x;
    return jsonb_build_object('ok', true, 'code', 'RESULT_HISTORY_STUDENTS_READ', 'read_only', true, 'rows', v_rows);
  end if;

  return jsonb_build_object('ok', false, 'code', 'RESULT_HISTORY_ACTION_NOT_ALLOWED');
end;
$function$;

revoke all on function public.school_result_history_read(uuid, text, text, jsonb)
  from public, authenticated;
grant execute on function public.school_result_history_read(uuid, text, text, jsonb)
  to anon, service_role;
