CREATE OR REPLACE FUNCTION public.school_staff_public_registration_submit(p_payload jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'extensions', 'public'
AS $function$
declare
  v_name text := trim(coalesce(p_payload ->> 'fullName', ''));
  v_email text := lower(trim(coalesce(p_payload ->> 'email', '')));
  v_phone text := nullif(trim(coalesce(p_payload ->> 'phone', '')), '');
  v_whatsapp text := nullif(trim(coalesce(p_payload ->> 'whatsappNumber', '')), '');
  v_address text := nullif(trim(coalesce(p_payload ->> 'address', '')), '');
  v_emergency text := nullif(trim(coalesce(p_payload ->> 'emergencyContact', '')), '');
  v_photo text := nullif(trim(coalesce(p_payload ->> 'photo', '')), '');
  v_password text := coalesce(p_payload ->> 'password', '');
  v_fingerprint text;
  v_registration_id uuid;
  v_result_user_id uuid;
  v_person_id uuid;
  v_staff_id uuid;
  v_staff_number text;
  v_account_id uuid;
begin
  if v_name is null or length(v_name) < 2 or length(v_name) > 160 then return jsonb_build_object('ok',false,'code','FULL_NAME_REQUIRED'); end if;
  if v_email is null or length(v_email) > 254 or v_email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$' then return jsonb_build_object('ok',false,'code','VALID_EMAIL_REQUIRED'); end if;
  if v_phone is null or length(v_phone) < 7 or length(v_phone) > 40 then return jsonb_build_object('ok',false,'code','PHONE_REQUIRED'); end if;
  if v_whatsapp is not null and length(v_whatsapp) > 40 then return jsonb_build_object('ok',false,'code','WHATSAPP_NUMBER_INVALID'); end if;
  if v_photo is not null and (length(v_photo) > 260000 or v_photo !~ '^data:image/[a-zA-Z0-9.+-]+;base64,') then return jsonb_build_object('ok',false,'code','PHOTOGRAPH_INVALID'); end if;
  if length(v_password) < 10 or length(v_password) > 512 or v_password !~ '[A-Z]' or v_password !~ '[a-z]' or v_password !~ '[0-9]' then
    return jsonb_build_object('ok',false,'code','PASSWORD_REQUIREMENTS_NOT_MET');
  end if;
  v_fingerprint := md5(lower(v_name)||'|'||coalesce(v_email,'')||'|'||coalesce(v_phone,'')||'|'||coalesce(v_whatsapp,''));
  
  perform pg_advisory_xact_lock(hashtext(v_fingerprint));

  if exists (
    select 1 from public.staff_attendance_profiles s
    where s.registration_status in ('active','pending','suspended')
      and (lower(coalesce(s.email,''))=v_email or s.phone=v_phone or (v_whatsapp is not null and s.whatsapp_number=v_whatsapp))
  ) or exists (
    select 1 from public.school_staff_registrations r
    where r.registration_status in ('pending','under_review','approved')
      and (lower(coalesce(r.email,''))=v_email or r.phone=v_phone or (v_whatsapp is not null and r.whatsapp_number=v_whatsapp))
  ) then return jsonb_build_object('ok',true,'code','STAFF_REGISTRATION_ALREADY_ON_FILE'); end if;

  insert into public.school_staff_registrations(
    full_name,email,phone,whatsapp_number,address,emergency_contact,photo_data,
    initial_password_hash,registration_status,request_fingerprint
  ) values (
    v_name,v_email,v_phone,v_whatsapp,v_address,v_emergency,v_photo,
    crypt(v_password,gen_salt('bf',12)),'approved',v_fingerprint
  ) returning id into v_registration_id;

  insert into public.school_people(
    full_name,primary_email,primary_phone,photo_path,person_status,metadata
  ) values (
    v_name,v_email,v_phone,v_photo,'active',
    jsonb_build_object('created_from','staff_self_registration','registration_id',v_registration_id)
  ) returning id into v_person_id;

  insert into public.staff_attendance_profiles(
    full_name,email,phone,address,staff_category,department,designation,
    photo,emergency_contact,employment_status,attendance_required,metadata,
    registration_source,registration_status,activated_at,central_person_id,
    whatsapp_number,preferred_language
  ) values (
    v_name,v_email,v_phone,v_address,'teaching',null,'Teacher',
    v_photo,v_emergency,'active',true,
    jsonb_build_object('created_from','staff_self_registration','registration_id',v_registration_id,'emergency_contact',v_emergency),
    'self_registration','active',now(),v_person_id,v_whatsapp,'en'
  ) returning id,staff_number into v_staff_id,v_staff_number;

  insert into public.user_profiles(email, full_name, role)
  values (v_email, v_name, 'teacher')
  returning id into v_result_user_id;

  update public.staff_attendance_profiles
  set user_profile_id=v_result_user_id, updated_at=now()
  where id=v_staff_id;

  update public.school_staff_registrations
  set approved_staff_id=v_staff_id, updated_at=now()
  where id=v_registration_id;

  insert into public.school_identity_accounts(
    person_id,login_email,account_status,identity_source,metadata
  ) values (
    v_person_id,v_email,'active','central_registry',
    jsonb_build_object('approved_from','staff_self_registration','registration_id',v_registration_id)
  ) returning id into v_account_id;

  insert into public.school_identity_credentials(
    identity_account_id,person_id,login_name,password_hash,credential_status,
    must_change_password,failed_attempts,locked_until,password_changed_at,updated_at
  ) values (
    v_account_id,v_person_id,v_staff_number,crypt(v_password,gen_salt('bf',12)),'active',
    false,0,null,now(),now()
  );

  insert into public.school_registry_audit(
    actor_type,actor_id,action,entity_type,entity_id,details
  ) values (
    'person','system','staff.registration_auto_approved',
    'staff_attendance_profile',v_staff_id::text,
    jsonb_build_object('registration_id',v_registration_id,'staff_number',v_staff_number,'person_id',v_person_id)
  );

  return jsonb_build_object('ok',true,'code','STAFF_REGISTRATION_SUBMITTED','registration_id',v_registration_id,'staff_number',v_staff_number,'result_user_created',v_result_user_id is not null);
end;
$function$;

-- Keep Results module permissions in step with the access role.
-- A promotion to teacher must carry scoring rights, not keep stale view-only ones.
create or replace function wts_internal.school_access_grants_results_permissions()
returns trigger
language plpgsql
security definer
set search_path to 'pg_catalog', 'public'
as $trig$
begin
  if new.app_code = 'results' and new.grant_status = 'active' then
    if new.access_role in ('teacher','results_teacher') then
      new.permissions := array['scores.enter','remarks.enter','results.view_assigned']::text[];
    end if;
  end if;
  return new;
end;
$trig$;

drop trigger if exists school_access_grants_results_permissions_sync on public.school_access_grants;
create trigger school_access_grants_results_permissions_sync
before insert or update of access_role, grant_status on public.school_access_grants
for each row execute function wts_internal.school_access_grants_results_permissions();

-- lock down the helper
revoke execute on function wts_internal.school_access_grants_results_permissions() from public, anon, authenticated;

-- backfill: any existing active results teacher still carrying view-only permissions
update public.school_access_grants
set permissions = array['scores.enter','remarks.enter','results.view_assigned']::text[], updated_at = now()
where app_code = 'results' and grant_status = 'active'
  and access_role in ('teacher','results_teacher')
  and not ('scores.enter' = any(permissions));
