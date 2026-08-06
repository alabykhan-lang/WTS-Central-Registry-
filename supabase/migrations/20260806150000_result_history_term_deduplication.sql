-- Keep the Results archive at one canonical row per academic session and term.
-- Official terms take precedence over archived score-derived history.
-- This changes no student, enrollment, score or archive records.

CREATE OR REPLACE FUNCTION public.school_result_history_read(p_session_id uuid, p_session_secret text, p_action text, p_payload jsonb DEFAULT '{}'::jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'extensions', 'public'
AS $function$
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

  v_auth := public.school_result_authorize(
    p_session_id,
    p_session_secret,
    'identity.context'
  );
  if coalesce((v_auth ->> 'ok')::boolean, false) is not true then
    return v_auth;
  end if;

  v_permissions := coalesce(
    array(select jsonb_array_elements_text(v_auth -> 'permissions')),
    array[]::text[]
  );
  if not public.school_result_permission_allowed(v_permissions, 'results.view_assigned')
     and not public.school_result_permission_allowed(v_permissions, 'results.manage') then
    return jsonb_build_object(
      'ok', false,
      'code', 'RESULT_PERMISSION_DENIED',
      'required_permission', 'results.view_assigned'
    );
  end if;

  if v_action = 'read' then
    select coalesce(
      jsonb_agg(
        to_jsonb(x)
        order by x.academic_session desc,
          case x.term
            when '1st Term' then 1
            when '2nd Term' then 2
            when '3rd Term' then 3
            else 9
          end
      ),
      '[]'::jsonb
    )
    into v_rows
    from (
      select
        c.academic_session,
        c.term,
        c.term_status,
        c.is_current,
        (
          select count(*)
          from public.school_student_enrollments e
          where e.academic_session = c.academic_session
            and coalesce(e.metadata ->> 'transition_artifact', 'false') <> 'true'
        ) as enrolled_students,
        (
          select count(*)
          from public.school_student_enrollments e
          where e.academic_session = c.academic_session
            and coalesce(e.metadata ->> 'transition_artifact', 'false') <> 'true'
            and e.enrollment_status = 'graduated'
        ) as graduating_students
      from (
        select
          raw.academic_session,
          raw.term,
          case
            when bool_or(raw.is_current) then 'open'::text
            when bool_or(raw.term_status = 'closed') then 'closed'::text
            else 'archived'::text
          end as term_status,
          bool_or(raw.is_current) as is_current
        from (
          select t.academic_session, t.term_name as term, t.term_status, t.is_current
          from public.school_academic_terms t
          union all
          select distinct s.academic_session, s.term, 'archived'::text, false
          from public.scores s
        ) raw
        where raw.term in ('1st Term', '2nd Term', '3rd Term')
        group by raw.academic_session, raw.term
      ) c
      where not c.is_current
    ) x;

    return jsonb_build_object(
      'ok', true,
      'code', 'RESULT_HISTORY_READ',
      'read_only', true,
      'contexts', v_rows,
      'transitions', coalesce(
        (select jsonb_agg(to_jsonb(r) order by r.created_at desc)
         from public.school_academic_transition_runs r),
        '[]'::jsonb
      )
    );
  end if;

  if v_session is null then
    return jsonb_build_object('ok', false, 'code', 'RESULT_HISTORY_SESSION_REQUIRED');
  end if;

  if v_action in ('scores', 'traits', 'remarks', 'fees', 'published_subjects') then
    if v_class_key is null or v_term is null then
      return jsonb_build_object('ok', false, 'code', 'RESULT_HISTORY_CONTEXT_REQUIRED');
    end if;

    if v_action = 'scores' then
      select coalesce(jsonb_agg(to_jsonb(x) order by x.student_id, x.subject_index), '[]'::jsonb)
      into v_rows
      from (
        select s.id, s.student_id, s.class_key, s.subject_index,
               s.ca1, s.ca2, s.ca3, s.exam, s.term, s.academic_session
        from public.scores s
        where s.class_key = v_class_key
          and s.academic_session = v_session
          and s.term = v_term
          and (v_student_id is null or s.student_id = v_student_id)
          and exists (
            select 1
            from public.school_student_enrollments e
            where e.student_id = s.student_id
              and e.class_key = v_class_key
              and e.academic_session = v_session
              and coalesce(e.metadata ->> 'transition_artifact', 'false') <> 'true'
          )
      ) x;
    elsif v_action = 'traits' then
      select coalesce(jsonb_agg(to_jsonb(x) order by x.student_id, x.trait_type, x.trait_name), '[]'::jsonb)
      into v_rows
      from (
        select t.id, t.student_id, t.class_key, t.trait_type, t.trait_name,
               t.rating, t.academic_session, t.term
        from public.traits t
        where t.class_key = v_class_key
          and t.academic_session = v_session
          and t.term = v_term
          and (v_student_id is null or t.student_id = v_student_id)
          and exists (
            select 1
            from public.school_student_enrollments e
            where e.student_id = t.student_id
              and e.class_key = v_class_key
              and e.academic_session = v_session
              and coalesce(e.metadata ->> 'transition_artifact', 'false') <> 'true'
          )
      ) x;
    elsif v_action = 'remarks' then
      select coalesce(jsonb_agg(to_jsonb(x) order by x.student_id), '[]'::jsonb)
      into v_rows
      from (
        select r.id, r.student_id, r.class_key, r.academic,
               r.form_master, r.principal, r.days_opened, r.days_present,
               r.academic_session, r.term
        from public.remarks r
        where r.class_key = v_class_key
          and r.academic_session = v_session
          and r.term = v_term
          and (v_student_id is null or r.student_id = v_student_id)
          and exists (
            select 1
            from public.school_student_enrollments e
            where e.student_id = r.student_id
              and e.class_key = v_class_key
              and e.academic_session = v_session
              and coalesce(e.metadata ->> 'transition_artifact', 'false') <> 'true'
          )
      ) x;
    elsif v_action = 'fees' then
      select coalesce(jsonb_agg(to_jsonb(x) order by x.student_id), '[]'::jsonb)
      into v_rows
      from (
        select f.id, f.student_id, f.class_key, f.total, f.paid, f.debt,
               f.next_term, f.resume_date, f.academic_session, f.term
        from public.fees f
        where f.class_key = v_class_key
          and f.academic_session = v_session
          and f.term = v_term
          and (v_student_id is null or f.student_id = v_student_id)
          and exists (
            select 1
            from public.school_student_enrollments e
            where e.student_id = f.student_id
              and e.class_key = v_class_key
              and e.academic_session = v_session
              and coalesce(e.metadata ->> 'transition_artifact', 'false') <> 'true'
          )
      ) x;
    else
      select coalesce(jsonb_agg(to_jsonb(x) order by x.subject_index), '[]'::jsonb)
      into v_rows
      from (
        select p.id, p.class_key, p.academic_session, p.term,
               p.subject_index, p.published_at
        from public.published_subjects p
        where p.class_key = v_class_key
          and p.academic_session = v_session
          and p.term = v_term
      ) x;
    end if;

    return jsonb_build_object(
      'ok', true,
      'code', 'RESULT_HISTORY_DATA_READ',
      'read_only', true,
      'rows', v_rows
    );
  end if;

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
        and (
          (v_action = 'graduates'
            and (e.enrollment_status = 'graduated'
                 or e.class_key in ('ss3-arts', 'ss3-science')))
          or (v_action = 'students' and e.class_key = v_class_key)
        )
        and (v_student_id is null or e.student_id = v_student_id)
    ) x;

    return jsonb_build_object(
      'ok', true,
      'code', 'RESULT_HISTORY_STUDENTS_READ',
      'read_only', true,
      'rows', v_rows
    );
  end if;

  return jsonb_build_object('ok', false, 'code', 'RESULT_HISTORY_ACTION_NOT_ALLOWED');
end;
$function$

