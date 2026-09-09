-- Remove activation-key and email-confirmation dependencies.
-- New registrants choose a password before management approval. Existing
-- active staff may set/reset a password by matching their staff number and
-- registered email or phone. Staff identity creation still requires management review.

alter table public.school_staff_registrations
  add column if not exists initial_password_hash text;

revoke all (initial_password_hash) on table public.school_staff_registrations
  from public, anon, authenticated;

create or replace function public.school_staff_public_registration_submit(p_payload jsonb)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_name text := nullif(trim(coalesce(p_payload ->> 'fullName', '')), '');
  v_email text := lower(nullif(trim(coalesce(p_payload ->> 'email', '')), ''));
  v_phone text := nullif(trim(coalesce(p_payload ->> 'phone', '')), '');
  v_whatsapp text := nullif(trim(coalesce(p_payload ->> 'whatsappNumber', '')), '');
  v_address text := nullif(trim(coalesce(p_payload ->> 'address', '')), '');
  v_emergency text := nullif(trim(coalesce(p_payload ->> 'emergencyContact', '')), '');
  v_photo text := nullif(trim(coalesce(p_payload ->> 'photo', '')), '');
  v_password text := coalesce(p_payload ->> 'password', '');
  v_fingerprint text;
  v_registration_id uuid;
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
    crypt(v_password,gen_salt('bf',12)),'pending',v_fingerprint
  ) returning id into v_registration_id;
  return jsonb_build_object('ok',true,'code','STAFF_REGISTRATION_SUBMITTED','registration_id',v_registration_id);
end;
$function$;

revoke all on function public.school_staff_public_registration_submit(jsonb) from public, authenticated;
grant execute on function public.school_staff_public_registration_submit(jsonb) to anon;

create or replace function wts_internal.school_staff_registration_password_finalize()
returns trigger
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_staff public.staff_attendance_profiles%rowtype;
  v_account public.school_identity_accounts%rowtype;
begin
  if new.registration_status in ('rejected','withdrawn') then
    update public.school_staff_registrations set initial_password_hash=null where id=new.id and initial_password_hash is not null;
    return new;
  end if;
  if new.registration_status<>'approved' or old.registration_status='approved' or new.initial_password_hash is null then return new; end if;
  select * into v_staff from public.staff_attendance_profiles where id=new.approved_staff_id;
  if not found or v_staff.central_person_id is null then raise exception using errcode='P0001',message='APPROVED_STAFF_IDENTITY_NOT_FOUND'; end if;
  select * into v_account from public.school_identity_accounts where person_id=v_staff.central_person_id and account_status='active';
  if not found then raise exception using errcode='P0001',message='APPROVED_STAFF_ACCOUNT_NOT_FOUND'; end if;
  insert into public.school_identity_credentials(
    identity_account_id,person_id,login_name,password_hash,credential_status,
    must_change_password,failed_attempts,locked_until,password_changed_at,updated_at
  ) values (
    v_account.id,v_account.person_id,v_staff.staff_number,new.initial_password_hash,'active',
    false,0,null,now(),now()
  )
  on conflict(identity_account_id) do update set
    person_id=excluded.person_id,login_name=excluded.login_name,password_hash=excluded.password_hash,
    credential_status='active',must_change_password=false,failed_attempts=0,locked_until=null,
    password_changed_at=now(),updated_at=now();
  update public.school_staff_registrations set initial_password_hash=null where id=new.id;
  insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,details)
  values('person',coalesce(new.reviewed_by_person_id::text,'system'),'identity.registration_password_activated',
    'staff_attendance_profile',v_staff.id::text,jsonb_build_object('registration_id',new.id,'email_confirmation_required',false,'activation_key_required',false));
  return new;
end;
$function$;

drop trigger if exists school_staff_registration_password_finalize_trigger on public.school_staff_registrations;
create trigger school_staff_registration_password_finalize_trigger
after update of registration_status on public.school_staff_registrations
for each row execute function wts_internal.school_staff_registration_password_finalize();
revoke all on function wts_internal.school_staff_registration_password_finalize() from public,anon,authenticated;

create or replace function public.school_identity_password_reset_by_staff_record(
  p_login text,
  p_contact text,
  p_new_password text
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_login text := lower(trim(coalesce(p_login,'')));
  v_contact text := lower(trim(coalesce(p_contact,'')));
  v_phone text := regexp_replace(coalesce(p_contact,''),'[^0-9]','','g');
  v_staff public.staff_attendance_profiles%rowtype;
  v_account public.school_identity_accounts%rowtype;
  v_credential public.school_identity_credentials%rowtype;
  v_request_id uuid := gen_random_uuid();
begin
  if v_login='' or length(v_login)>254 or v_contact='' or length(v_contact)>254 then
    return jsonb_build_object('ok',false,'code','STAFF_RECORD_VERIFICATION_FAILED');
  end if;
  if length(coalesce(p_new_password,''))<10 or length(coalesce(p_new_password,''))>512
     or p_new_password !~ '[A-Z]' or p_new_password !~ '[a-z]' or p_new_password !~ '[0-9]' then
    return jsonb_build_object('ok',false,'code','PASSWORD_REQUIREMENTS_NOT_MET');
  end if;
  perform pg_advisory_xact_lock(hashtext(v_login||'|'||v_contact));
  select s.* into v_staff
  from public.staff_attendance_profiles s
  join public.school_people p on p.id=s.central_person_id
  join public.school_identity_accounts i on i.person_id=s.central_person_id
  where (lower(coalesce(s.staff_number,''))=v_login or lower(coalesce(s.email,''))=v_login or lower(coalesce(i.login_email,''))=v_login)
    and (
      lower(coalesce(s.email,''))=v_contact
      or (length(v_phone)>=10 and right(regexp_replace(coalesce(s.phone,''),'[^0-9]','','g'),10)=right(v_phone,10))
    )
    and s.registration_status='active' and s.employment_status='active'
    and p.person_status='active' and i.account_status='active'
  limit 1;
  if not found or v_staff.central_person_id is null then return jsonb_build_object('ok',false,'code','STAFF_RECORD_VERIFICATION_FAILED'); end if;
  select * into v_account from public.school_identity_accounts where person_id=v_staff.central_person_id and account_status='active' for update;
  select * into v_credential from public.school_identity_credentials where identity_account_id=v_account.id for update;
  if found and v_credential.locked_until is not null and v_credential.locked_until>now() then return jsonb_build_object('ok',false,'code','ACCOUNT_TEMPORARILY_LOCKED'); end if;
  insert into public.school_identity_credentials(
    identity_account_id,person_id,login_name,password_hash,credential_status,
    must_change_password,failed_attempts,locked_until,password_changed_at,updated_at
  ) values (
    v_account.id,v_account.person_id,v_staff.staff_number,crypt(p_new_password,gen_salt('bf',12)),
    'active',false,0,null,now(),now()
  )
  on conflict(identity_account_id) do update set
    person_id=excluded.person_id,login_name=excluded.login_name,password_hash=excluded.password_hash,
    credential_status='active',must_change_password=false,failed_attempts=0,locked_until=null,
    password_changed_at=now(),updated_at=now();
  perform wts_internal.revoke_identity_sessions(v_account.person_id,'DIRECT_STAFF_PASSWORD_RESET');
  insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,request_id,details)
  values('self_service',v_staff.staff_number,'identity.direct_password_reset','identity_account',v_account.id::text,v_request_id,
    jsonb_build_object('staff_id',v_staff.id,'registered_contact_matched',true,'email_confirmation_sent',false,'activation_key_required',false));
  return jsonb_build_object('ok',true,'code','PASSWORD_RESET_COMPLETED','staff_number',v_staff.staff_number);
exception when others then
  return jsonb_build_object('ok',false,'code','PASSWORD_RESET_FAILED');
end;
$function$;

revoke all on function public.school_identity_password_reset_by_staff_record(text,text,text) from public,authenticated;
grant execute on function public.school_identity_password_reset_by_staff_record(text,text,text) to anon;

do $migration$
declare v_function regprocedure;
begin
  for v_function in
    select p.oid::regprocedure from pg_proc p join pg_namespace n on n.oid=p.pronamespace
    where n.nspname='public' and p.proname in (
      'school_identity_shared_teacher_code_consume',
      'school_identity_management_code_consume',
      'school_identity_recovery_request',
      'school_identity_recovery_consume'
    )
  loop execute format('revoke execute on function %s from public, anon, authenticated',v_function); end loop;
end
$migration$;
