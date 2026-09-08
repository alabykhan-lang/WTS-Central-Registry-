-- A student may legitimately hold multiple distinct prefect offices in the
-- same session. Preserve overlap protection for duplicate office records.

create or replace function public.school_registry_validate_portfolio_assignment()
returns trigger
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_catalog public.school_portfolio_catalog%rowtype;
  v_holder_person uuid;
begin
  select * into v_catalog from public.school_portfolio_catalog where portfolio_code = new.portfolio_code and is_active;
  if not found then raise exception using errcode = 'P0001', message = 'PORTFOLIO_NOT_FOUND'; end if;
  if v_catalog.holder_type <> new.holder_type then raise exception using errcode = 'P0001', message = 'PORTFOLIO_HOLDER_TYPE_INVALID'; end if;
  if v_catalog.jurisdiction = 'stage' and (new.scope_type <> 'stage' or new.stage_code is null) then raise exception using errcode = 'P0001', message = 'PORTFOLIO_STAGE_SCOPE_REQUIRED'; end if;
  if v_catalog.jurisdiction = 'stage' and not exists (
    select 1 from public.school_portfolio_stage_scopes s
    where s.portfolio_code = new.portfolio_code and s.stage_code = new.stage_code
  ) then raise exception using errcode = 'P0001', message = 'PORTFOLIO_STAGE_NOT_ALLOWED'; end if;
  if v_catalog.jurisdiction = 'class' and (new.scope_type <> 'class' or new.class_key is null) then raise exception using errcode = 'P0001', message = 'PORTFOLIO_CLASS_SCOPE_REQUIRED'; end if;
  if v_catalog.jurisdiction = 'school' and new.scope_type <> 'school' then raise exception using errcode = 'P0001', message = 'PORTFOLIO_SCHOOL_SCOPE_REQUIRED'; end if;
  if v_catalog.jurisdiction = 'self' and new.scope_type <> 'self' then raise exception using errcode = 'P0001', message = 'PORTFOLIO_SELF_SCOPE_REQUIRED'; end if;
  if new.scope_type = 'stage' and (new.stage_code is null or new.class_key is not null) then raise exception using errcode = 'P0001', message = 'PORTFOLIO_STAGE_SCOPE_INVALID'; end if;
  if new.scope_type = 'class' and (new.class_key is null or new.stage_code is not null) then raise exception using errcode = 'P0001', message = 'PORTFOLIO_CLASS_SCOPE_INVALID'; end if;
  if new.scope_type in ('school','self') and (new.stage_code is not null or new.class_key is not null) then raise exception using errcode = 'P0001', message = 'PORTFOLIO_SCOPE_FIELDS_INVALID'; end if;
  if new.portfolio_code='student_executive_council' and new.assignment_status='active'
     and nullif(trim(coalesce(new.office_name,'')),'') is null then
    raise exception using errcode = 'P0001', message = 'PREFECT_OFFICE_REQUIRED';
  end if;
  if new.portfolio_code<>'student_executive_council' and new.office_name is not null then
    raise exception using errcode = 'P0001', message = 'PORTFOLIO_OFFICE_NOT_ALLOWED';
  end if;
  if new.assignment_status = 'active' and new.scope_type = 'class' and not exists (
    select 1 from public.school_classes c
    where c.class_key = new.class_key and c.is_active and lower(c.class_key) not like 'archive-%'
  ) then raise exception using errcode = 'P0001', message = 'PORTFOLIO_CLASS_NOT_ACTIVE'; end if;
  if new.effective_until is not null and new.effective_until <= new.effective_from then raise exception using errcode = 'P0001', message = 'PORTFOLIO_EFFECTIVE_RANGE_INVALID'; end if;

  if new.holder_type = 'staff' then
    select central_person_id into v_holder_person from public.staff_attendance_profiles where id = new.staff_id;
    if new.assignment_status = 'active' and not exists (
      select 1 from public.staff_attendance_profiles s
      where s.id = new.staff_id and s.registration_status = 'active' and s.employment_status = 'active'
    ) then raise exception using errcode = 'P0001', message = 'PORTFOLIO_HOLDER_NOT_ACTIVE'; end if;
  else
    select central_person_id into v_holder_person from public.students where id = new.student_id;
    if new.assignment_status = 'active' and not exists (
      select 1 from public.students s where s.id = new.student_id and not s.archived
    ) then raise exception using errcode = 'P0001', message = 'PORTFOLIO_HOLDER_NOT_ACTIVE'; end if;
  end if;
  if v_holder_person is null then raise exception using errcode = 'P0001', message = 'PORTFOLIO_HOLDER_NOT_FOUND'; end if;
  if new.holder_person_id is null then new.holder_person_id := v_holder_person;
  elsif new.holder_person_id <> v_holder_person then raise exception using errcode = 'P0001', message = 'PORTFOLIO_HOLDER_PERSON_MISMATCH'; end if;

  if v_catalog.is_protected and not wts_internal.school_registry_is_protected_actor(new.assigned_by_person_id) then
    raise exception using errcode = 'P0001', message = 'PROTECTED_PORTFOLIO_RESTRICTED';
  end if;

  if new.assignment_status = 'active' and exists (
    select 1 from public.school_portfolio_assignments a
    where a.id <> coalesce(new.id, gen_random_uuid())
      and a.portfolio_code = new.portfolio_code
      and a.assignment_status = 'active'
      and (a.academic_session is null or new.academic_session is null or a.academic_session = new.academic_session)
      and a.effective_from < coalesce(new.effective_until, 'infinity'::timestamptz)
      and coalesce(a.effective_until, 'infinity'::timestamptz) > new.effective_from
      and (
        (
          v_catalog.is_singleton
          and (
            a.holder_person_id is distinct from new.holder_person_id
            or (
              a.scope_type = new.scope_type
              and a.stage_code is not distinct from new.stage_code
              and a.class_key is not distinct from new.class_key
            )
          )
        )
        or (
          not v_catalog.is_singleton
          and a.holder_person_id is not distinct from new.holder_person_id
          and a.scope_type = new.scope_type
          and a.stage_code is not distinct from new.stage_code
          and a.class_key is not distinct from new.class_key
          and (
            new.portfolio_code <> 'student_executive_council'
            or lower(trim(coalesce(a.office_name,''))) = lower(trim(coalesce(new.office_name,'')))
          )
        )
      )
  ) then
    raise exception using errcode = 'P0001', message = case when v_catalog.is_singleton then 'PORTFOLIO_SINGLETON_OVERLAP' else 'PORTFOLIO_ASSIGNMENT_OVERLAP' end;
  end if;
  new.updated_at := now();
  return new;
end;
$function$;

revoke all on function public.school_registry_validate_portfolio_assignment()
  from public, anon, authenticated;
