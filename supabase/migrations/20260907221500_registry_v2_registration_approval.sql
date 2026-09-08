-- Registry v2 registration approval helper.
-- The legacy management adapter expects its old permission-array session
-- shape. Registry v2 intentionally authorizes with the v2 entitlement
-- snapshot, so approval is performed here with the already-authorized actor.

create or replace function wts_internal.school_registry_approve_registration_v2(
  p_registration_id uuid,
  p_actor_person_id uuid,
  p_payload jsonb default '{}'::jsonb
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_registration public.school_staff_registrations%rowtype;
  v_person_id uuid;
  v_staff_id uuid;
  v_staff_number text;
  v_reason text := nullif(trim(coalesce(p_payload ->> 'reason','')), '');
  v_category text := lower(trim(coalesce(p_payload ->> 'staffCategory','teaching')));
  v_department text := nullif(trim(coalesce(p_payload ->> 'department','')), '');
  v_designation text := nullif(trim(coalesce(p_payload ->> 'designation','')), '');
  v_school_section text := nullif(trim(coalesce(p_payload ->> 'schoolSection','')), '');
  v_request_id uuid;
begin
  begin v_request_id := nullif(p_payload->>'requestId','')::uuid; exception when others then v_request_id := null; end;
  v_request_id := coalesce(v_request_id,gen_random_uuid());
  if p_actor_person_id is null or not exists (
    select 1 from public.school_people p where p.id=p_actor_person_id and p.person_status='active'
  ) then
    return jsonb_build_object('ok',false,'code','REGISTRY_IDENTITY_NOT_ACTIVE');
  end if;
  if p_registration_id is null then
    return jsonb_build_object('ok',false,'code','REGISTRATION_ID_REQUIRED');
  end if;

  select * into v_registration
  from public.school_staff_registrations
  where id=p_registration_id
  for update;
  if not found then
    return jsonb_build_object('ok',false,'code','STAFF_REGISTRATION_NOT_FOUND');
  end if;
  if v_registration.registration_status='approved' then
    select id,staff_number,central_person_id into v_staff_id,v_staff_number,v_person_id
    from public.staff_attendance_profiles where id=v_registration.approved_staff_id;
    return jsonb_build_object(
      'ok',true,'code','STAFF_REGISTRATION_ALREADY_APPROVED',
      'staff_id',v_staff_id,'staff_number',v_staff_number,'person_id',v_person_id
    );
  end if;
  if v_registration.registration_status not in ('pending','under_review') then
    return jsonb_build_object('ok',false,'code','REGISTRATION_NOT_APPROVABLE');
  end if;
  if v_category not in ('teaching','non_teaching','management','contract','casual') then
    return jsonb_build_object('ok',false,'code','STAFF_CATEGORY_INVALID');
  end if;
  if v_designation is null or length(v_designation)>160 then
    return jsonb_build_object('ok',false,'code','STAFF_POSITION_REQUIRED');
  end if;
  if lower(v_designation) ~ '(super[ _-]*administrator|system[ _-]*owner)'
     or lower(v_designation)='developer' then
    return jsonb_build_object('ok',false,'code','STAFF_DESIGNATION_TECHNICAL_PRIVILEGE_FORBIDDEN');
  end if;
  if v_department is not null and length(v_department)>160 then
    return jsonb_build_object('ok',false,'code','STAFF_DEPARTMENT_INVALID');
  end if;
  if v_school_section is not null and length(v_school_section)>160 then
    return jsonb_build_object('ok',false,'code','STAFF_SECTION_INVALID');
  end if;
  if v_reason is null or length(v_reason)<8 then
    v_reason := 'Approved through Central Registry v2';
  end if;

  perform pg_advisory_xact_lock(hashtext(
    coalesce(v_registration.email,'') || '|' ||
    coalesce(v_registration.phone,'') || '|' ||
    coalesce(v_registration.whatsapp_number,'')
  ));
  if exists (
    select 1 from public.staff_attendance_profiles s
    where s.registration_status in ('active','pending','suspended')
      and (
        (v_registration.email is not null and lower(coalesce(s.email,''))=lower(v_registration.email))
        or (v_registration.phone is not null and s.phone=v_registration.phone)
        or (v_registration.whatsapp_number is not null and s.whatsapp_number=v_registration.whatsapp_number)
      )
  ) then
    return jsonb_build_object('ok',false,'code','DUPLICATE_STAFF_IDENTITY');
  end if;

  insert into public.school_people(
    full_name,primary_email,primary_phone,photo_path,person_status,metadata
  ) values (
    v_registration.full_name,v_registration.email,v_registration.phone,
    v_registration.photo_data,'active',
    jsonb_build_object('created_from','staff_self_registration','registration_id',v_registration.id)
  ) returning id into v_person_id;

  insert into public.staff_attendance_profiles(
    full_name,email,phone,address,staff_category,department,designation,
    photo,school_section,emergency_contact,employment_status,attendance_required,metadata,
    registration_source,registration_status,activated_at,central_person_id,
    whatsapp_number,preferred_language
  ) values (
    v_registration.full_name,v_registration.email,v_registration.phone,
    v_registration.address,v_category,v_department,v_designation,
    v_registration.photo_data,v_school_section,v_registration.emergency_contact,'active',true,
    jsonb_build_object('created_from','staff_self_registration','registration_id',v_registration.id,'emergency_contact',v_registration.emergency_contact),
    'self_registration','active',now(),v_person_id,v_registration.whatsapp_number,'en'
  ) returning id,staff_number into v_staff_id,v_staff_number;

  insert into public.school_identity_accounts(
    person_id,login_email,account_status,identity_source,metadata
  ) values (
    v_person_id,v_registration.email,'active','central_registry',
    jsonb_build_object('approved_from','staff_self_registration','registration_id',v_registration.id)
  )
  on conflict (person_id) do update set
    login_email=excluded.login_email,
    account_status='active',
    identity_source='central_registry',
    metadata=public.school_identity_accounts.metadata || excluded.metadata,
    updated_at=now();

  update public.school_staff_registrations
  set registration_status='approved',reviewed_by_person_id=p_actor_person_id,
      reviewed_at=now(),approved_staff_id=v_staff_id,updated_at=now()
  where id=v_registration.id;

  insert into public.school_registry_audit(
    actor_type,actor_id,action,entity_type,entity_id,request_id,
    before_data,after_data,details
  ) values (
    'person',p_actor_person_id::text,'staff.registration_approved',
    'staff_attendance_profile',v_staff_id::text,v_request_id,
    jsonb_build_object('registration_id',v_registration.id,'registration_status',v_registration.registration_status),
    jsonb_build_object('staff_id',v_staff_id,'staff_number',v_staff_number,'person_id',v_person_id),
    jsonb_build_object('registration_id',v_registration.id,'reason',v_reason,
      'position_assigned',v_designation,'department_assigned',v_department,
      'school_section_assigned',v_school_section,
      'module_access_requires_separate_management_decision',true)
  );
  return jsonb_build_object(
    'ok',true,'code','STAFF_REGISTRATION_APPROVED',
    'staff_id',v_staff_id,'staff_number',v_staff_number,'person_id',v_person_id,
    'request_id',v_request_id
  );
exception when unique_violation then
  return jsonb_build_object('ok',false,'code','DUPLICATE_STAFF_IDENTITY');
end;
$function$;

revoke all on function wts_internal.school_registry_approve_registration_v2(uuid,uuid,jsonb)
  from public,anon,authenticated;
