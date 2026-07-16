-- Designate the account holder's existing staff identity as the primary
-- Central Registry administrator. Password activation is intentionally kept
-- out of this migration so no temporary credential enters source control.

create or replace function public.school_sync_person_admin_client(p_person_id uuid)
returns uuid
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_permissions text[]:=array[]::text[];
  v_attendance_role text;
  v_notification_role text;
  v_registry_role text;
  v_self_service_role text;
  v_client_id uuid;
  v_client_code text;
  v_name text;
begin
  select access_role into v_attendance_role
  from public.school_access_grants
  where person_id=p_person_id and app_code='attendance' and grant_status='active'
    and (valid_from is null or valid_from<=now()) and (valid_until is null or valid_until>now());
  if v_attendance_role is not null then
    v_permissions:=v_permissions||array['dashboard.read','staff.read','reports.read','credentials.manage','staff.manage']::text[];
    if v_attendance_role='attendance_admin' then
      v_permissions:=v_permissions||array['devices.manage','staff.rules.manage','settings.manage','corrections.create','corrections.review','manual_entries.create','manual_entries.review']::text[];
    end if;
  end if;

  select access_role into v_notification_role
  from public.school_access_grants
  where person_id=p_person_id and app_code='notifications' and grant_status='active'
    and (valid_from is null or valid_from<=now()) and (valid_until is null or valid_until>now());
  if v_notification_role is not null then
    v_permissions:=v_permissions||array['notifications.manage']::text[];
    if v_notification_role='notification_admin' then
      v_permissions:=v_permissions||array['settings.manage']::text[];
    end if;
  end if;

  select access_role into v_registry_role
  from public.school_access_grants
  where person_id=p_person_id and app_code='central_registry' and grant_status='active'
    and (valid_from is null or valid_from<=now()) and (valid_until is null or valid_until>now());
  if v_registry_role is not null then
    v_permissions:=v_permissions||array['registry.read','registry.manage']::text[];
    if v_registry_role in ('registry_admin','admissions_officer') then
      v_permissions:=v_permissions||array['admissions.manage']::text[];
    end if;
    if v_registry_role='registry_admin' then
      v_permissions:=v_permissions||array['access.manage']::text[];
    end if;
  end if;

  select access_role into v_self_service_role
  from public.school_access_grants
  where person_id=p_person_id and app_code='staff_self_service' and grant_status='active'
    and (valid_from is null or valid_from<=now()) and (valid_until is null or valid_until>now());
  if v_self_service_role is not null then
    v_permissions:=v_permissions||array['profile.self.read','profile.self.update']::text[];
  end if;

  select coalesce(array_agg(distinct permission order by permission),array[]::text[])
  into v_permissions from unnest(v_permissions) permission;

  select id into v_client_id from public.attendance_admin_clients where central_person_id=p_person_id;
  if cardinality(v_permissions)=0 then
    if v_client_id is not null then
      update public.attendance_admin_clients
      set permissions=array[]::text[],status='suspended',session_expires_at=null,updated_at=now()
      where id=v_client_id;
    end if;
    return v_client_id;
  end if;

  select full_name into v_name from public.school_people where id=p_person_id;
  v_client_code:='WTS-ID-'||upper(substr(replace(p_person_id::text,'-',''),1,12));
  if v_client_id is null then
    insert into public.attendance_admin_clients(
      client_code,client_name,secret_hash,status,permissions,central_person_id,session_source,metadata
    ) values(
      v_client_code,coalesce(v_name,'Central staff')||' — Central Access',
      encode(digest(encode(gen_random_bytes(32),'hex'),'sha256'),'hex'),'suspended',v_permissions,p_person_id,
      'central_identity',jsonb_build_object('central_identity',true)
    ) returning id into v_client_id;
  else
    update public.attendance_admin_clients
    set client_name=coalesce(v_name,client_name)||' — Central Access',permissions=v_permissions,
        status=case when status='active' and session_expires_at>now() then 'active' else 'suspended' end,
        session_source='central_identity',metadata=metadata||jsonb_build_object('central_identity',true),updated_at=now()
    where id=v_client_id;
  end if;
  return v_client_id;
end;
$function$;

do $migration$
declare
  v_person_id uuid;
  v_staff_id uuid;
  v_grant_id uuid;
  v_before jsonb;
  v_after jsonb;
  v_request_id uuid:=gen_random_uuid();
begin
  select p.id,s.id
  into v_person_id,v_staff_id
  from public.school_people p
  join public.staff_attendance_profiles s on s.central_person_id=p.id
  join public.school_identity_accounts i on i.person_id=p.id
  where s.staff_number='WTS/STF/000008'
    and p.full_name='Alabi Mubarak Omololu'
    and lower(i.login_email)='alabykhan@gmail.com'
    and p.person_status='active'
    and s.registration_status='active'
    and s.employment_status='active'
    and i.account_status='active';

  if v_person_id is null then
    raise exception 'Expected active primary Registry administrator identity was not found';
  end if;

  select to_jsonb(g) into v_before
  from public.school_access_grants g
  where g.person_id=v_person_id and g.app_code='central_registry';

  insert into public.school_access_grants(
    person_id,app_code,access_role,permissions,grant_status,valid_from,valid_until,
    granted_by_person_id,reason,metadata
  ) values(
    v_person_id,'central_registry','registry_admin',
    array['registry.read','registry.manage','access.manage','admissions.manage']::text[],
    'active',now(),null,v_person_id,
    'Primary Central Registry administrator designated by the account holder',
    jsonb_build_object('managed_from','owner_approved_bootstrap','primary_registry_admin',true,'staff_id',v_staff_id)
  )
  on conflict(person_id,app_code) do update
  set access_role=excluded.access_role,
      permissions=excluded.permissions,
      grant_status='active',
      valid_from=now(),
      valid_until=null,
      granted_by_person_id=excluded.granted_by_person_id,
      reason=excluded.reason,
      metadata=public.school_access_grants.metadata||excluded.metadata,
      updated_at=now()
  returning id into v_grant_id;

  perform public.school_sync_person_admin_client(v_person_id);

  select to_jsonb(g) into v_after
  from public.school_access_grants g where g.id=v_grant_id;

  insert into public.school_registry_audit(
    actor_type,actor_id,action,entity_type,entity_id,request_id,before_data,after_data,details
  ) values(
    'person',v_person_id::text,'portal_access.primary_admin_designated',
    'school_access_grant',v_grant_id::text,v_request_id,v_before,v_after,
    jsonb_build_object('staff_id',v_staff_id,'app_code','central_registry','approved_by_account_holder',true)
  );
end;
$migration$;

revoke execute on function public.school_sync_person_admin_client(uuid) from public, anon, authenticated;
