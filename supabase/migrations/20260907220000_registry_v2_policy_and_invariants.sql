-- Registry v2 policy materialization and portfolio invariants.

create or replace function wts_internal.school_registry_is_protected_actor(p_person_id uuid)
returns boolean
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_authority jsonb := '{}'::jsonb;
begin
  begin v_authority := coalesce(wts_internal.institutional_authority(p_person_id), '{}'::jsonb); exception when undefined_function then v_authority := '{}'::jsonb; end;
  if coalesce((v_authority ->> 'active')::boolean,false)
     and lower(coalesce(v_authority ->> 'classification','')) in ('developer','system_owner','proprietor') then
    return true;
  end if;
  return exists (
    select 1
    from public.school_portfolio_assignments a
    where a.holder_person_id = p_person_id
      and a.portfolio_code = 'proprietor'
      and a.assignment_status = 'active'
      and a.effective_from <= now()
      and (a.effective_until is null or a.effective_until > now())
  );
end;
$function$;

revoke all on function wts_internal.school_registry_is_protected_actor(uuid) from public, anon, authenticated;

create or replace function wts_internal.school_registry_is_technical_actor(p_person_id uuid)
returns boolean
language plpgsql
security definer
stable
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_authority jsonb := '{}'::jsonb;
begin
  begin v_authority := coalesce(wts_internal.institutional_authority(p_person_id), '{}'::jsonb); exception when undefined_function then v_authority := '{}'::jsonb; end;
  return coalesce((v_authority ->> 'active')::boolean,false)
    and lower(coalesce(v_authority ->> 'classification','')) in ('developer','system_owner');
end;
$function$;

revoke all on function wts_internal.school_registry_is_technical_actor(uuid) from public, anon, authenticated;

create or replace function wts_internal.school_portal_entry_allowed(p_person_id uuid, p_app_code text)
returns boolean
language plpgsql
security definer
stable
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_mode text;
begin
  if not exists (select 1 from public.school_portal_catalog c where c.app_code=lower(trim(coalesce(p_app_code,''))) and c.is_active) then return false; end if;
  select operating_mode into v_mode from public.school_module_operating_controls where app_code=lower(trim(coalesce(p_app_code,'')));
  if v_mode is null or v_mode='disabled' then return false; end if;
  if v_mode='pilot' then return wts_internal.school_registry_is_technical_actor(p_person_id); end if;
  return true;
end;
$function$;

revoke all on function wts_internal.school_portal_entry_allowed(uuid,text) from public, anon, authenticated;

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

drop trigger if exists school_registry_validate_portfolio_assignment_trigger on public.school_portfolio_assignments;
create trigger school_registry_validate_portfolio_assignment_trigger
before insert or update on public.school_portfolio_assignments
for each row execute function public.school_registry_validate_portfolio_assignment();

revoke all on function public.school_registry_validate_portfolio_assignment()
  from public, anon, authenticated;

create or replace function public.school_registry_materialize_module_grants(p_actor_person_id uuid default null)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_staff record;
  v_policy record;
  v_id uuid;
  v_default_permissions text[];
  v_count integer := 0;
  v_request_id uuid := gen_random_uuid();
begin
  if p_actor_person_id is not null and not wts_internal.school_registry_is_protected_actor(p_actor_person_id) then
    return jsonb_build_object('ok',false,'code','REGISTRY_CAPABILITY_DENIED');
  end if;
  for v_policy in select * from public.school_portal_access_policy where is_active and automatic_entry loop
    for v_staff in
      select s.central_person_id as person_id
      from public.staff_attendance_profiles s
      join public.school_people p on p.id = s.central_person_id
      where s.registration_status = 'active' and s.employment_status = 'active'
        and s.central_person_id is not null and p.person_status = 'active'
    loop
      if not exists (select 1 from public.school_access_grants g where g.person_id = v_staff.person_id and g.app_code = v_policy.app_code) then
        v_default_permissions := case v_policy.app_code
          when 'results' then array['result_entry.view']::text[]
          when 'attendance' then array['dashboard.read']::text[]
          when 'staff_self_service' then array['profile.self.read','profile.self.update']::text[]
          else array[]::text[]
        end;
        insert into public.school_access_grants(person_id,app_code,access_role,permissions,grant_status,valid_from,granted_by_person_id,reason,metadata)
        values(v_staff.person_id,v_policy.app_code,v_policy.default_access_role,v_default_permissions,'active',now(),p_actor_person_id,'Automatic Registry policy entry',jsonb_build_object('managed_from','portal_policy','policy_version',v_policy.policy_version,'request_id',v_request_id))
        returning id into v_id;
        v_count := v_count + 1;
      end if;
    end loop;
  end loop;
  return jsonb_build_object('ok',true,'code','MODULE_GRANTS_MATERIALIZED','created',v_count,'request_id',v_request_id);
end;
$function$;

revoke all on function public.school_registry_materialize_module_grants(uuid) from public, anon, authenticated;

create or replace function public.school_registry_materialize_staff_grants_trigger()
returns trigger
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
begin
  if new.registration_status = 'active' and new.employment_status = 'active' and new.central_person_id is not null then
    perform public.school_registry_materialize_module_grants(null);
  end if;
  return new;
end;
$function$;

drop trigger if exists school_registry_materialize_staff_grants on public.staff_attendance_profiles;
create trigger school_registry_materialize_staff_grants
after insert or update of registration_status, employment_status on public.staff_attendance_profiles
for each row execute function public.school_registry_materialize_staff_grants_trigger();

revoke all on function public.school_registry_materialize_staff_grants_trigger() from public, anon, authenticated;

-- Backfill only missing automatic module-entry grants for currently active
-- identities. Existing explicit grants, permissions, revocations and validity
-- windows are never overwritten.
select public.school_registry_materialize_module_grants(null);
