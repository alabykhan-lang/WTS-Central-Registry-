-- Additive, read-only portfolio projection for Staff Portal and Results.
-- Existing authorization functions and grants are intentionally unchanged.

create or replace function public.school_profile_portfolios_read(
  p_session_id uuid, p_session_secret text, p_target_type text,
  p_class_key text default null, p_student_id uuid default null,
  p_academic_session text default null, p_term text default null
)
returns jsonb language plpgsql security definer
set search_path = pg_catalog, extensions, public
as $$
declare
  v_target text := lower(trim(coalesce(p_target_type, '')));
  v_session jsonb; v_visible jsonb; v_person_id uuid; v_staff_id uuid;
  v_ids uuid[] := array[]::uuid[]; v_rows jsonb;
begin
  if v_target = 'staff' then
    v_session := public.school_identity_session_validate(p_session_id, p_session_secret, 'staff_self_service');
    if coalesce((v_session ->> 'ok')::boolean, false) is not true then return v_session; end if;
    v_person_id := (v_session ->> 'person_id')::uuid;
    select id into v_staff_id from public.staff_attendance_profiles
      where central_person_id = v_person_id and registration_status = 'active' and employment_status = 'active' limit 1;
    if v_staff_id is null then return jsonb_build_object('ok', false, 'code', 'STAFF_NOT_ACTIVE'); end if;
    select coalesce(jsonb_agg(row_data order by row_data ->> 'name'), '[]'::jsonb) into v_rows from (
      select jsonb_build_object(
        'assignment_id', a.id, 'portfolio_code', a.portfolio_code,
        'portfolio_name', c.portfolio_name, 'name', coalesce(nullif(a.office_name, ''), c.portfolio_name),
        'office_name', a.office_name, 'assignment_status', a.assignment_status,
        'academic_session', a.academic_session, 'scope_type', a.scope_type,
        'stage_code', a.stage_code, 'class_key', a.class_key,
        'custom', lower(coalesce(c.metadata ->> 'custom', 'false')) = 'true',
        'access_template_code', nullif(a.metadata ->> 'access_template_code', '')
      ) row_data
      from public.school_portfolio_assignments a
      join public.school_portfolio_catalog c on c.portfolio_code = a.portfolio_code and c.is_active
      where a.holder_type = 'staff' and (a.staff_id = v_staff_id or a.holder_person_id = v_person_id)
        and a.assignment_status = 'active' and (a.effective_from is null or a.effective_from <= now())
        and (a.effective_until is null or a.effective_until > now())
    ) active_staff_portfolios;
    return jsonb_build_object('ok', true, 'code', 'STAFF_PORTFOLIOS_READ', 'portfolios', v_rows);
  end if;

  if v_target = 'student' then
    v_visible := public.school_result_read_api(p_session_id, p_session_secret, 'students', jsonb_strip_nulls(jsonb_build_object(
      'class_key', p_class_key, 'student_id', p_student_id,
      'academic_session', p_academic_session, 'term', p_term
    )));
    if coalesce((v_visible ->> 'ok')::boolean, false) is not true then return v_visible; end if;
    select coalesce(array_agg((student ->> 'id')::uuid), array[]::uuid[]) into v_ids
      from jsonb_array_elements(coalesce(v_visible -> 'rows', '[]'::jsonb)) student;
    select coalesce(jsonb_agg(jsonb_build_object('student_id', student_id, 'portfolios', portfolios)), '[]'::jsonb) into v_rows from (
      select s.id student_id, coalesce(jsonb_agg(jsonb_build_object(
        'assignment_id', a.id, 'portfolio_code', a.portfolio_code,
        'portfolio_name', c.portfolio_name, 'name', coalesce(nullif(a.office_name, ''), c.portfolio_name),
        'office_name', a.office_name, 'assignment_status', a.assignment_status,
        'academic_session', a.academic_session, 'scope_type', a.scope_type,
        'stage_code', a.stage_code, 'class_key', a.class_key,
        'custom', lower(coalesce(c.metadata ->> 'custom', 'false')) = 'true'
      ) order by c.sort_order, coalesce(nullif(a.office_name, ''), c.portfolio_name)) filter (where a.id is not null), '[]'::jsonb) portfolios
      from public.students s
      left join public.school_portfolio_assignments a on a.student_id = s.id and a.holder_type = 'student'
        and a.assignment_status = 'active' and (a.effective_from is null or a.effective_from <= now())
        and (a.effective_until is null or a.effective_until > now())
      left join public.school_portfolio_catalog c on c.portfolio_code = a.portfolio_code and c.is_active
      where s.id = any(v_ids) group by s.id
    ) visible_student_portfolios;
    return jsonb_build_object('ok', true, 'code', 'STUDENT_PORTFOLIOS_READ', 'rows', v_rows);
  end if;
  return jsonb_build_object('ok', false, 'code', 'PORTFOLIO_TARGET_INVALID');
end;
$$;

revoke all on function public.school_profile_portfolios_read(uuid, text, text, text, uuid, text, text) from public;
grant execute on function public.school_profile_portfolios_read(uuid, text, text, text, uuid, text, text) to anon, authenticated, service_role;
