-- Preserve the existing Result/Attendance PKCE clients and add the Registry
-- client used when staff enter from the School Workspace.

insert into public.school_sso_clients(
  client_id,target_app_code,approved_origin,redirect_uri,post_logout_uri,scope
)
values (
  'central_registry','central_registry',
  'https://wts-central-registry.vercel.app',
  'https://wts-central-registry.vercel.app/',
  'https://wts-school-platform.vercel.app/workspace',
  'central_registry'
)
on conflict (client_id) do update set
  target_app_code=excluded.target_app_code,
  approved_origin=excluded.approved_origin,
  redirect_uri=excluded.redirect_uri,
  post_logout_uri=excluded.post_logout_uri,
  scope=excluded.scope,
  code_challenge_methods=excluded.code_challenge_methods,
  is_active=true,
  updated_at=now();

do $migration$
begin
  begin
    alter table public.school_sso_authorization_codes
      drop constraint school_sso_authorization_codes_client_chk;
  exception when undefined_object then null;
  end;
  begin
    alter table public.school_sso_authorization_codes
      drop constraint school_sso_authorization_codes_target_chk;
  exception when undefined_object then null;
  end;
  begin
    alter table public.school_sso_authorization_codes
      drop constraint school_sso_authorization_codes_redirect_chk;
  exception when undefined_object then null;
  end;

  alter table public.school_sso_authorization_codes
    add constraint school_sso_authorization_codes_client_chk
    check (client_id in ('result_portal','attendance','central_registry','notifications'));
  alter table public.school_sso_authorization_codes
    add constraint school_sso_authorization_codes_target_chk
    check (target_app_code in ('results','attendance','central_registry','notifications'));
  alter table public.school_sso_authorization_codes
    add constraint school_sso_authorization_codes_redirect_chk
    check (redirect_uri in (
      'https://wts-result-system.vercel.app/portal_core.html',
      'https://wts-attendance-system.vercel.app/',
      'https://wts-central-registry.vercel.app/',
      'https://wts-notification-system.vercel.app/'
    ));
end
$migration$;

-- Re-apply the latest shared-client implementation from the Attendance SSO
-- foundation, with the central-registry branch included. This preserves
-- Results and Attendance behaviour while making the Registry client dynamic
-- through school_sso_clients instead of hard-coding a third portal path.
create or replace function public.school_sso_authorization_code_issue(
  p_session_id uuid,
  p_session_secret text,
  p_client_id text,
  p_target_app_code text,
  p_redirect_uri text,
  p_code_hash text,
  p_code_challenge text,
  p_code_challenge_method text,
  p_state_hash text,
  p_nonce_hash text
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, extensions, public
as $function$
declare
  v_context jsonb;
  v_client public.school_sso_clients%rowtype;
  v_person_id uuid;
  v_identity_account_id uuid;
  v_authority jsonb := '{}'::jsonb;
  v_code_id uuid;
  v_created_at timestamptz := now();
  v_expires_at timestamptz := v_created_at + interval '5 minutes';
  v_target text;
begin
  select c.* into v_client
  from public.school_sso_clients c
  where c.client_id = lower(trim(coalesce(p_client_id, ''))) and c.is_active;
  if not found or v_client.target_app_code <> lower(trim(coalesce(p_target_app_code, ''))) or v_client.redirect_uri <> trim(coalesce(p_redirect_uri, '')) then
    return jsonb_build_object('ok', false, 'code', 'SSO_CLIENT_OR_REDIRECT_INVALID');
  end if;
  v_target := v_client.target_app_code;
  if coalesce(trim(p_code_hash), '') !~ '^[0-9a-f]{64}$'
     or coalesce(trim(p_code_challenge), '') !~ '^[A-Za-z0-9_-]{43,128}$'
     or trim(coalesce(p_code_challenge_method, '')) <> 'S256'
     or coalesce(trim(p_state_hash), '') !~ '^[0-9a-f]{64}$'
     or coalesce(trim(p_nonce_hash), '') !~ '^[0-9a-f]{64}$' then
    return jsonb_build_object('ok', false, 'code', 'SSO_REQUEST_INVALID');
  end if;

  v_context := public.school_identity_session_validate(p_session_id, p_session_secret, 'staff_self_service');
  if coalesce((v_context ->> 'ok')::boolean, false) is not true then return jsonb_build_object('ok', false, 'code', 'WTS_SESSION_NOT_ACTIVE'); end if;
  v_person_id := nullif(v_context ->> 'person_id', '')::uuid;
  v_identity_account_id := nullif(v_context ->> 'identity_account_id', '')::uuid;
  if v_person_id is null or v_identity_account_id is null then return jsonb_build_object('ok', false, 'code', 'WTS_SESSION_NOT_ACTIVE'); end if;
  if not wts_internal.school_portal_entry_allowed(v_person_id, v_target) then
    return jsonb_build_object('ok', false, 'code', case when v_target='attendance' then 'ATTENDANCE_PILOT_RESTRICTED' when v_target='notifications' then 'NOTIFICATIONS_DISABLED' else 'PORTAL_OPERATING_MODE_RESTRICTED' end);
  end if;

  begin v_authority := coalesce(wts_internal.institutional_authority(v_person_id), '{}'::jsonb); exception when undefined_function then v_authority := '{}'::jsonb; end;
  if coalesce((v_authority ->> 'active')::boolean, false) is not true
     and not exists (
       select 1 from public.school_access_grants g
       where g.person_id = v_person_id and g.app_code = v_target and g.grant_status = 'active'
         and (g.valid_from is null or g.valid_from <= now()) and (g.valid_until is null or g.valid_until > now())
     ) then
    if v_target = 'central_registry' and not exists (
      select 1 from public.school_access_grants g
      where g.person_id=v_person_id and g.app_code='central_registry'
    ) and exists (
      select 1 from public.school_people p
      join public.staff_attendance_profiles s on s.central_person_id=p.id
      join public.school_identity_accounts i on i.person_id=p.id
      join public.school_identity_credentials cr on cr.identity_account_id=i.id and cr.person_id=p.id and cr.credential_status='active'
      where p.id=v_person_id and i.id=v_identity_account_id and p.person_status='active' and i.account_status='active' and s.registration_status='active' and s.employment_status='active'
    ) then
      null;
    else
      return jsonb_build_object('ok', false, 'code', case when v_target = 'attendance' then 'ATTENDANCE_ACCESS_NOT_GRANTED' when v_target = 'notifications' then 'NOTIFICATIONS_ACCESS_NOT_GRANTED' when v_target = 'central_registry' then 'REGISTRY_ACCESS_NOT_GRANTED' else 'RESULT_ACCESS_NOT_GRANTED' end);
    end if;
  end if;
  if v_target = 'results' and coalesce((v_authority ->> 'active')::boolean, false) is not true then
    if coalesce((public.school_result_identity_resolve(v_person_id, v_identity_account_id) ->> 'ok')::boolean, false) is not true then return jsonb_build_object('ok', false, 'code', 'RESULT_IDENTITY_NOT_RESOLVED'); end if;
  end if;

  insert into public.school_sso_authorization_codes(code_hash,client_id,target_app_code,redirect_uri,person_id,identity_account_id,source_session_id,code_challenge,code_challenge_method,state_hash,nonce_hash,created_at,expires_at)
  values(lower(trim(p_code_hash)),v_client.client_id,v_client.target_app_code,v_client.redirect_uri,v_person_id,v_identity_account_id,p_session_id,trim(p_code_challenge),'S256',lower(trim(p_state_hash)),lower(trim(p_nonce_hash)),v_created_at,v_expires_at)
  returning id into v_code_id;
  insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,details)
  values('staff_session',v_person_id::text,'identity.sso.authorization_code.issued','school_sso_authorization_codes',v_code_id::text,jsonb_build_object('client_id',v_client.client_id,'target_app_code',v_target,'redirect_uri',v_client.redirect_uri,'code_challenge_method','S256','expires_at',v_expires_at));
  return jsonb_build_object('ok',true,'code','SSO_AUTHORIZATION_CODE_ISSUED','authorization_code_id',v_code_id,'person_id',v_person_id,'identity_account_id',v_identity_account_id,'expires_at',v_expires_at);
exception when unique_violation then return jsonb_build_object('ok',false,'code','SSO_CODE_ISSUE_RETRY');
end;
$function$;

create or replace function public.school_sso_authorization_code_exchange(
  p_code text,
  p_client_id text,
  p_redirect_uri text,
  p_code_verifier text,
  p_state text,
  p_nonce text
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, extensions, public
as $function$
declare
  v_code public.school_sso_authorization_codes%rowtype;
  v_source_session public.school_identity_sessions%rowtype;
  v_client public.school_sso_clients%rowtype;
  v_person public.school_people%rowtype;
  v_staff public.staff_attendance_profiles%rowtype;
  v_account public.school_identity_accounts%rowtype;
  v_grant public.school_access_grants%rowtype;
  v_authority jsonb := '{}'::jsonb;
  v_permissions text[] := array[]::text[];
  v_access_role text := 'staff';
  v_session_id uuid;
  v_session_secret text;
  v_attendance_client public.attendance_admin_clients%rowtype;
  v_attendance_client_secret text;
  v_expires_at timestamptz;
  v_verifier_challenge text;
begin
  select c.* into v_client from public.school_sso_clients c where c.client_id = lower(trim(coalesce(p_client_id, ''))) and c.is_active;
  if not found or v_client.redirect_uri <> trim(coalesce(p_redirect_uri, '')) then return jsonb_build_object('ok',false,'code','SSO_CLIENT_OR_REDIRECT_INVALID'); end if;
  if coalesce(trim(p_code), '') = '' or coalesce(trim(p_code_verifier), '') !~ '^[A-Za-z0-9._~-]{43,128}$' or coalesce(trim(p_state), '') !~ '^[A-Za-z0-9._~-]{16,512}$' or coalesce(trim(p_nonce), '') !~ '^[A-Za-z0-9._~-]{16,512}$' then return jsonb_build_object('ok',false,'code','SSO_REQUEST_INVALID'); end if;

  select c.* into v_code from public.school_sso_authorization_codes c where c.code_hash = encode(digest(trim(p_code), 'sha256'), 'hex') for update;
  if not found then return jsonb_build_object('ok',false,'code','SSO_CODE_INVALID'); end if;
  if v_code.client_id <> v_client.client_id or v_code.target_app_code <> v_client.target_app_code then return jsonb_build_object('ok',false,'code','SSO_AUDIENCE_INVALID'); end if;
  if v_code.redirect_uri <> v_client.redirect_uri or trim(p_redirect_uri) <> v_code.redirect_uri then return jsonb_build_object('ok',false,'code','SSO_REDIRECT_URI_MISMATCH'); end if;
  if v_code.consumed_at is not null then return jsonb_build_object('ok',false,'code','SSO_CODE_REUSED'); end if;
  if v_code.expires_at <= now() then return jsonb_build_object('ok',false,'code','SSO_CODE_EXPIRED'); end if;
  if encode(digest(trim(p_state), 'sha256'), 'hex') <> v_code.state_hash or encode(digest(trim(p_nonce), 'sha256'), 'hex') <> v_code.nonce_hash then return jsonb_build_object('ok',false,'code','SSO_STATE_OR_NONCE_INVALID'); end if;
  v_verifier_challenge := rtrim(replace(replace(encode(digest(trim(p_code_verifier), 'sha256'), 'base64'), '+', '-'), '/', '_'), '=');
  if v_code.code_challenge_method <> 'S256' or v_verifier_challenge <> v_code.code_challenge then return jsonb_build_object('ok',false,'code','SSO_PKCE_INVALID'); end if;

  select s.* into v_source_session from public.school_identity_sessions s where s.id=v_code.source_session_id and s.person_id=v_code.person_id and s.identity_account_id=v_code.identity_account_id and s.target_app_code='staff_self_service' and s.revoked_at is null and s.expires_at>now() for update;
  if not found then update public.school_sso_authorization_codes set consumed_at=now(),consumed_by='source_session_inactive' where id=v_code.id and consumed_at is null; return jsonb_build_object('ok',false,'code','WTS_SESSION_NOT_ACTIVE'); end if;
  select p.* into v_person from public.school_people p where p.id=v_code.person_id for update;
  select i.* into v_account from public.school_identity_accounts i where i.id=v_code.identity_account_id and i.person_id=v_code.person_id for update;
  select s.* into v_staff from public.staff_attendance_profiles s where s.central_person_id=v_code.person_id and s.registration_status='active' and s.employment_status='active' order by s.created_at limit 1;
  if v_person.id is null or v_person.person_status<>'active' or v_account.id is null or v_account.account_status<>'active' or v_staff.id is null or not exists(select 1 from public.school_identity_credentials cr where cr.identity_account_id=v_account.id and cr.person_id=v_code.person_id and cr.credential_status='active') then
    update public.school_sso_authorization_codes set consumed_at=now(),consumed_by='identity_revalidation_denied' where id=v_code.id and consumed_at is null;
    return jsonb_build_object('ok',false,'code',case when v_client.target_app_code='central_registry' then 'REGISTRY_IDENTITY_NOT_ACTIVE' else 'IDENTITY_NOT_ACTIVE' end);
  end if;
  if not wts_internal.school_portal_entry_allowed(v_code.person_id, v_client.target_app_code) then
    update public.school_sso_authorization_codes set consumed_at=now(),consumed_by='portal_operating_mode_restricted' where id=v_code.id and consumed_at is null;
    return jsonb_build_object('ok',false,'code',case when v_client.target_app_code='attendance' then 'ATTENDANCE_PILOT_RESTRICTED' when v_client.target_app_code='notifications' then 'NOTIFICATIONS_DISABLED' else 'PORTAL_OPERATING_MODE_RESTRICTED' end);
  end if;

  begin v_authority := coalesce(wts_internal.institutional_authority(v_code.person_id), '{}'::jsonb); exception when undefined_function then v_authority := '{}'::jsonb; end;
  select g.* into v_grant from public.school_access_grants g where g.person_id=v_code.person_id and g.app_code=v_client.target_app_code and g.grant_status='active' and (g.valid_from is null or g.valid_from<=now()) and (g.valid_until is null or g.valid_until>now()) order by g.created_at desc limit 1;
  if coalesce((v_authority->>'active')::boolean,false) is not true and not found then
    if v_client.target_app_code='central_registry' and not exists (
      select 1 from public.school_access_grants existing
      where existing.person_id=v_code.person_id and existing.app_code='central_registry'
    ) then
      null;
    else
      update public.school_sso_authorization_codes set consumed_at=now(),consumed_by='module_grant_missing' where id=v_code.id and consumed_at is null;
      return jsonb_build_object('ok',false,'code',case when v_client.target_app_code='attendance' then 'ATTENDANCE_ACCESS_NOT_GRANTED' when v_client.target_app_code='notifications' then 'NOTIFICATIONS_ACCESS_NOT_GRANTED' when v_client.target_app_code='central_registry' then 'REGISTRY_ACCESS_NOT_GRANTED' else 'RESULT_ACCESS_NOT_GRANTED' end);
    end if;
  end if;
  if coalesce((v_authority->>'active')::boolean,false) is true then
    v_access_role := coalesce(v_authority->>'classification','staff');
    begin v_permissions := coalesce(wts_internal.institutional_permissions(v_code.person_id,v_client.target_app_code),array[]::text[]); exception when undefined_function then v_permissions := array[]::text[]; end;
  elsif found then
    v_access_role := coalesce(v_grant.access_role,'staff');
    v_permissions := coalesce(v_grant.permissions,array[]::text[]);
  end if;
  if v_client.target_app_code='results' and coalesce((v_authority->>'active')::boolean,false) is not true and coalesce((public.school_result_identity_resolve(v_code.person_id,v_code.identity_account_id)->>'ok')::boolean,false) is not true then
    update public.school_sso_authorization_codes set consumed_at=now(),consumed_by='result_identity_unresolved' where id=v_code.id and consumed_at is null;
    return jsonb_build_object('ok',false,'code','RESULT_IDENTITY_NOT_RESOLVED');
  end if;

  update public.school_sso_authorization_codes set consumed_at=now(),consumed_by=v_client.client_id where id=v_code.id and consumed_at is null;
  if not found then return jsonb_build_object('ok',false,'code','SSO_CODE_REUSED'); end if;
  v_session_secret := encode(gen_random_bytes(32),'base64'); v_expires_at := now()+interval '8 hours';
  insert into public.school_identity_sessions(person_id,identity_account_id,originating_app_code,target_app_code,secret_hash,created_at,expires_at,last_seen_at,metadata)
  values(v_code.person_id,v_code.identity_account_id,v_client.target_app_code,v_client.target_app_code,encode(digest(v_session_secret,'sha256'),'hex'),now(),v_expires_at,now(),jsonb_build_object('source','pkce_sso','authorization_code_id',v_code.id,'source_workspace_session_id',v_code.source_session_id)) returning id into v_session_id;

  if v_client.target_app_code='attendance' then
    perform public.school_sync_person_admin_client(v_code.person_id);
    select c.* into v_attendance_client from public.attendance_admin_clients c where c.central_person_id=v_code.person_id order by c.created_at limit 1 for update;
    if not found then delete from public.school_identity_sessions where id=v_session_id; return jsonb_build_object('ok',false,'code','ATTENDANCE_SESSION_SERVICE_UNAVAILABLE'); end if;
    v_attendance_client_secret := encode(gen_random_bytes(32),'base64');
    update public.attendance_admin_clients set secret_hash=encode(digest(v_attendance_client_secret,'sha256'),'hex'),status='active',session_expires_at=v_expires_at,session_source='central_identity',last_seen_at=now(),updated_at=now(),metadata=metadata||jsonb_build_object('attendance_session_id',v_session_id,'central_session_id',v_session_id,'authorization_code_id',v_code.id,'target_app_code','attendance') where id=v_attendance_client.id;
  end if;
  insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,details)
  values('staff_session',v_code.person_id::text,case when v_client.target_app_code='attendance' then 'identity.attendance_session.issued' when v_client.target_app_code='central_registry' then 'identity.registry_session.issued' when v_client.target_app_code='notifications' then 'identity.notification_session.issued' else 'identity.result_session.issued' end,'school_identity_sessions',v_session_id::text,jsonb_build_object('source','pkce_sso','authorization_code_id',v_code.id,'target_app_code',v_client.target_app_code,'expires_at',v_expires_at,'institutional_classification',v_authority->>'classification'));
  return jsonb_build_object('ok',true,'code','SSO_EXCHANGED','session_id',v_session_id,'session_secret',v_session_secret,'expires_at',v_expires_at,'person_id',v_code.person_id,'identity_account_id',v_code.identity_account_id,'access_role',v_access_role,'permissions',v_permissions,'institutional_authority',v_authority,'attendance_client_code',case when v_client.target_app_code='attendance' then v_attendance_client.client_code else null end,'attendance_client_secret',case when v_client.target_app_code='attendance' then v_attendance_client_secret else null end);
end;
$function$;

revoke all on function public.school_sso_authorization_code_issue(uuid,text,text,text,text,text,text,text,text,text) from public, anon, authenticated;
grant execute on function public.school_sso_authorization_code_issue(uuid,text,text,text,text,text,text,text,text,text) to anon, authenticated;
revoke all on function public.school_sso_authorization_code_exchange(text,text,text,text,text,text) from public, anon, authenticated;
grant execute on function public.school_sso_authorization_code_exchange(text,text,text,text,text,text) to anon, authenticated;
