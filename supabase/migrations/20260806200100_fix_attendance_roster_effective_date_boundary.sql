-- The Central Registry transition records use an inclusive effective date for
-- the current enrolment snapshot. Attendance must include the record on that
-- date while still excluding it after the recorded end date.

create or replace function public.school_attendance_registry_roster_read_api(
  p_session_id uuid,
  p_session_secret text,
  p_academic_session text default null,
  p_term text default null,
  p_as_of_date date default current_date
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_session jsonb;
  v_context jsonb;
  v_academic_session text;
  v_term text;
  v_as_of_date date := coalesce(p_as_of_date, current_date);
  v_term_row public.school_academic_terms%rowtype;
  v_person_id uuid;
begin
  v_session := public.school_identity_session_validate(p_session_id, p_session_secret, 'attendance');
  if coalesce((v_session ->> 'ok')::boolean, false) is not true then return v_session; end if;
  v_person_id := (v_session ->> 'person_id')::uuid;
  v_context := public.school_academic_current();
  v_academic_session := coalesce(nullif(trim(p_academic_session), ''), v_context ->> 'academic_session');
  v_term := coalesce(nullif(trim(p_term), ''), v_context ->> 'term');
  select * into v_term_row from public.school_academic_terms t where t.academic_session = v_academic_session and t.term_name = v_term;
  if not found then return jsonb_build_object('ok', false, 'code', 'OFFICIAL_ACADEMIC_TERM_NOT_FOUND'); end if;

  return jsonb_build_object(
    'ok', true,
    'code', 'CENTRAL_REGISTRY_ROSTER_READ',
    'requested', jsonb_build_object('academic_session',v_academic_session,'term',v_term,'as_of_date',v_as_of_date),
    'official_context', v_context,
    'classes', coalesce((select jsonb_agg(jsonb_build_object('class_key',c.class_key,'display_name',c.display_name,'sort_order',c.sort_order) order by c.sort_order,c.display_name) from public.school_classes c where c.is_active),'[]'::jsonb),
    'pupils', coalesce((select jsonb_agg(jsonb_build_object('person_id',e.person_id,'student_id',e.student_id,'admission_number',st.admno,'full_name',st.name,'pupil_status',st.lifecycle_status,'class_key',e.class_key,'valid_from',e.started_on,'valid_until',e.ended_on) order by e.class_key,st.name) from public.school_student_enrollments e join public.students st on st.id=e.student_id where e.academic_session=v_academic_session and e.started_on<=v_as_of_date and (e.ended_on is null or e.ended_on>=v_as_of_date) and e.enrollment_status in ('active','promoted','retained') and not coalesce(st.archived,false) and st.lifecycle_status='active'),'[]'::jsonb),
    'staff', coalesce((select jsonb_agg(jsonb_build_object('person_id',s.central_person_id,'staff_id',s.id,'staff_number',s.staff_number,'full_name',s.full_name,'employment_status',s.employment_status,'registration_status',s.registration_status,'valid_from',coalesce(s.activated_at::date,s.created_at::date),'valid_until',s.archived_at::date,'attendance_required',coalesce(p.personal_attendance_required,s.attendance_required)) order by s.full_name) from public.staff_attendance_profiles s join public.school_people p on p.id=s.central_person_id where s.central_person_id is not null and s.registration_status='active' and s.employment_status='active' and coalesce(s.activated_at::date,s.created_at::date)<=v_as_of_date and (s.archived_at is null or s.archived_at::date>=v_as_of_date) and p.person_status='active'),'[]'::jsonb),
    'class_teachers', coalesce((select jsonb_agg(jsonb_build_object('person_id',a.person_id,'staff_id',a.staff_id,'class_key',a.class_key,'responsibility',a.responsibility,'effective_from',a.effective_from::date,'effective_until',a.effective_until::date) order by a.class_key,a.responsibility) from public.school_staff_class_allocations a where a.allocation_status='active' and a.responsibility in ('class_teacher','assistant_class_teacher') and a.effective_from::date<=v_as_of_date and (a.effective_until is null or a.effective_until::date>=v_as_of_date) and (a.academic_session=v_academic_session or a.academic_session is null) and (a.term_name=v_term or a.term_name is null)),'[]'::jsonb),
    'attendance_grants', coalesce((select jsonb_agg(jsonb_build_object('person_id',g.person_id,'access_role',g.access_role,'permissions',g.permissions,'valid_from',g.valid_from::date,'valid_until',g.valid_until::date) order by g.person_id) from public.school_access_grants g where g.app_code='attendance' and g.grant_status='active' and g.valid_from<=now() and (g.valid_until is null or g.valid_until>now())),'[]'::jsonb),
    'requested_by_person_id', v_person_id
  );
end;
$function$;

revoke all on function public.school_attendance_registry_roster_read_api(uuid,text,text,text,date) from public, authenticated;
grant execute on function public.school_attendance_registry_roster_read_api(uuid,text,text,text,date) to anon;
