-- Attendance SSO, effective roster access and protected institutional authority.
-- This migration is additive. It does not create people, pupils, attendance
-- events, devices, class assignments or sample credentials.

create table if not exists public.school_sso_clients (
  client_id text primary key,
  target_app_code text not null,
  approved_origin text not null,
  redirect_uri text not null,
  post_logout_uri text not null,
  scope text not null,
  code_challenge_methods text[] not null default array['S256']::text[],
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint school_sso_clients_method_chk check (code_challenge_methods @> array['S256']::text[])
);

alter table public.school_sso_clients enable row level security;
revoke all on table public.school_sso_clients from public, anon, authenticated;

insert into public.school_sso_clients(
  client_id, target_app_code, approved_origin, redirect_uri, post_logout_uri, scope
)
values
  (
    'result_portal',
    'results',
    'https://wts-result-system.vercel.app',
    'https://wts-result-system.vercel.app/portal_core.html',
    'https://wts-school-platform.vercel.app/workspace',
    'results'
  ),
  (
    'attendance',
    'attendance',
    'https://wts-attendance-system.vercel.app',
    'https://wts-attendance-system.vercel.app/',
    'https://wts-school-platform.vercel.app/workspace',
    'attendance'
  )
on conflict (client_id) do update set
  target_app_code = excluded.target_app_code,
  approved_origin = excluded.approved_origin,
  redirect_uri = excluded.redirect_uri,
  post_logout_uri = excluded.post_logout_uri,
  scope = excluded.scope,
  code_challenge_methods = excluded.code_challenge_methods,
  is_active = true,
  updated_at = now();

do $$
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

  if not exists (
    select 1 from pg_constraint
    where conrelid = 'public.school_sso_authorization_codes'::regclass
      and conname = 'school_sso_authorization_codes_client_chk'
  ) then
    alter table public.school_sso_authorization_codes
      add constraint school_sso_authorization_codes_client_chk
      check (client_id in ('result_portal', 'attendance'));
  end if;
  if not exists (
    select 1 from pg_constraint
    where conrelid = 'public.school_sso_authorization_codes'::regclass
      and conname = 'school_sso_authorization_codes_target_chk'
  ) then
    alter table public.school_sso_authorization_codes
      add constraint school_sso_authorization_codes_target_chk
      check (target_app_code in ('results', 'attendance'));
  end if;
  if not exists (
    select 1 from pg_constraint
    where conrelid = 'public.school_sso_authorization_codes'::regclass
      and conname = 'school_sso_authorization_codes_redirect_chk'
  ) then
    alter table public.school_sso_authorization_codes
      add constraint school_sso_authorization_codes_redirect_chk
      check (redirect_uri in (
        'https://wts-result-system.vercel.app/portal_core.html',
        'https://wts-attendance-system.vercel.app/'
      ));
  end if;
end;
$$;

alter table public.school_people
  add column if not exists institutional_classification text not null default 'ordinary_staff';
alter table public.school_people
  add column if not exists institutional_number text;
alter table public.school_people
  add column if not exists personal_attendance_required boolean not null default true;

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conrelid = 'public.school_people'::regclass
      and conname = 'school_people_institutional_classification_chk'
  ) then
    alter table public.school_people
      add constraint school_people_institutional_classification_chk
      check (institutional_classification in ('system_owner', 'proprietor', 'ordinary_staff'));
  end if;
end;
$$;

create unique index if not exists school_people_institutional_number_uidx
  on public.school_people (institutional_number)
  where institutional_number is not null;

do $$
declare
  v_owner_id uuid;
  v_proprietor_id uuid;
  v_owner_count integer;
  v_proprietor_count integer;
  v_existing_owner_number uuid;
  v_existing_proprietor_number uuid;
begin
  select count(distinct g.person_id), (array_agg(distinct g.person_id order by g.person_id))[1]
    into v_owner_count, v_owner_id
  from public.school_access_grants g
  join public.school_people p on p.id = g.person_id
  join public.staff_attendance_profiles s on s.central_person_id = p.id
  where g.app_code = 'central_registry'
    and g.grant_status = 'active'
    and coalesce((g.metadata ->> 'primary_registry_admin')::boolean, false) = true
    and p.person_status = 'active'
    and s.registration_status = 'active'
    and s.employment_status = 'active';

  if v_owner_count <> 1 or v_owner_id is null then
    raise exception 'Institutional authority migration expected exactly one active primary Registry identity, found %', v_owner_count;
  end if;

  select count(distinct s.central_person_id), (array_agg(distinct s.central_person_id order by s.central_person_id))[1]
    into v_proprietor_count, v_proprietor_id
  from public.staff_attendance_profiles s
  join public.school_people p on p.id = s.central_person_id
  where s.staff_number = 'WTS/STF/000019'
    and p.person_status = 'active'
    and s.registration_status = 'active'
    and s.employment_status = 'active';

  if v_proprietor_count <> 1 or v_proprietor_id is null then
    raise exception 'Institutional authority migration expected the existing proprietor staff identity, found %', v_proprietor_count;
  end if;
  if v_owner_id = v_proprietor_id then
    raise exception 'System Owner and Proprietor must resolve to different existing identities';
  end if;

  select id into v_existing_owner_number
  from public.school_people
  where institutional_number = 'WTS/OWN/000001'
    and id <> v_owner_id;
  if v_existing_owner_number is not null then
    raise exception 'Protected owner institutional number is already assigned to another identity';
  end if;
  select id into v_existing_proprietor_number
  from public.school_people
  where institutional_number = 'WTS/PRO/000001'
    and id <> v_proprietor_id;
  if v_existing_proprietor_number is not null then
    raise exception 'Protected proprietor institutional number is already assigned to another identity';
  end if;

  update public.school_people p
  set institutional_classification = 'system_owner',
      institutional_number = 'WTS/OWN/000001',
      personal_attendance_required = coalesce((
        select s.attendance_required
        from public.staff_attendance_profiles s
        where s.central_person_id = p.id
        order by s.created_at
        limit 1
      ), p.personal_attendance_required),
      updated_at = now()
  where p.id = v_owner_id;

  update public.school_people p
  set institutional_classification = 'proprietor',
      institutional_number = 'WTS/PRO/000001',
      personal_attendance_required = coalesce((
        select s.attendance_required
        from public.staff_attendance_profiles s
        where s.central_person_id = p.id
        order by s.created_at
        limit 1
      ), p.personal_attendance_required),
      updated_at = now()
  where p.id = v_proprietor_id;

  insert into public.school_registry_audit(
    actor_type, actor_id, action, entity_type, entity_id, details
  )
  select
    'system_migration',
    p.id::text,
    'identity.institutional_classification.migrated',
    'school_people',
    p.id::text,
    jsonb_build_object(
      'classification', p.institutional_classification,
      'institutional_number', p.institutional_number,
      'source', '20260806200000_attendance_sso_roster_institutional_authority'
    )
  from public.school_people p
  where p.id in (v_owner_id, v_proprietor_id)
    and not exists (
      select 1 from public.school_registry_audit a
      where a.action = 'identity.institutional_classification.migrated'
        and a.entity_type = 'school_people'
        and a.entity_id = p.id::text
    );
end;
$$;

create or replace function wts_internal.institutional_authority(p_person_id uuid)
returns jsonb
language sql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
  select jsonb_build_object(
    'active',
      p.institutional_classification <> 'ordinary_staff'
      and p.person_status = 'active'
      and coalesce(i.account_status, '') = 'active',
    'classification', p.institutional_classification,
    'institutional_number', p.institutional_number,
    'personal_attendance_required', p.personal_attendance_required
  )
  from public.school_people p
  left join public.school_identity_accounts i on i.person_id = p.id
  where p.id = p_person_id;
$function$;

revoke all on function wts_internal.institutional_authority(uuid) from public, anon, authenticated;

create or replace function wts_internal.institutional_module_allowed(
  p_person_id uuid,
  p_app_code text,
  p_at timestamptz default now()
)
returns boolean
language sql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
  select coalesce((wts_internal.institutional_authority(p_person_id) ->> 'active')::boolean, false)
    and exists (
      select 1 from public.school_portal_catalog c
      where c.app_code = lower(trim(coalesce(p_app_code, '')))
        and c.is_active
        and c.supports_login
    );
$function$;

revoke all on function wts_internal.institutional_module_allowed(uuid, text, timestamptz) from public, anon, authenticated;

create or replace function wts_internal.institutional_permissions(
  p_person_id uuid,
  p_app_code text
)
returns text[]
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_authority jsonb;
  v_permissions text[];
begin
  v_authority := wts_internal.institutional_authority(p_person_id);
  if coalesce((v_authority ->> 'active')::boolean, false) is not true then
    return array[]::text[];
  end if;

  select coalesce(array_agg(distinct c.permission_code order by c.permission_code), array[]::text[])
    into v_permissions
  from public.school_permission_catalog c
  where c.app_code = lower(trim(coalesce(p_app_code, '')));

  if lower(trim(coalesce(p_app_code, ''))) = 'attendance' then
    v_permissions := array_append(v_permissions, '*');
  end if;
  if v_authority ->> 'classification' = 'system_owner' then
    v_permissions := array_append(v_permissions, '*');
  end if;
  return (select coalesce(array_agg(distinct x order by x), array[]::text[]) from unnest(v_permissions) x);
end;
$function$;

revoke all on function wts_internal.institutional_permissions(uuid, text) from public, anon, authenticated;

create or replace function public.school_sync_person_admin_client(p_person_id uuid)
returns uuid
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_permissions text[] := array[]::text[];
  v_attendance_role text;
  v_notification_role text;
  v_registry_role text;
  v_self_service_role text;
  v_client_id uuid;
  v_client_code text;
  v_name text;
  v_authority jsonb;
begin
  v_authority := wts_internal.institutional_authority(p_person_id);
  if coalesce((v_authority ->> 'active')::boolean, false) is true then
    v_permissions := array['*']::text[];
  else
    select access_role into v_attendance_role
    from public.school_access_grants
    where person_id = p_person_id and app_code = 'attendance' and grant_status = 'active'
      and valid_from <= now() and (valid_until is null or valid_until > now());
    if v_attendance_role is not null then
      v_permissions := v_permissions || array['dashboard.read','staff.read','reports.read','credentials.manage','staff.manage']::text[];
      if v_attendance_role = 'attendance_admin' then
        v_permissions := v_permissions || array['devices.manage','staff.rules.manage','settings.manage','corrections.create','corrections.review','manual_entries.create','manual_entries.review']::text[];
      end if;
    end if;

    select access_role into v_notification_role
    from public.school_access_grants
    where person_id = p_person_id and app_code = 'notifications' and grant_status = 'active'
      and valid_from <= now() and (valid_until is null or valid_until > now());
    if v_notification_role is not null then
      v_permissions := v_permissions || array['notifications.manage']::text[];
      if v_notification_role = 'notification_admin' then
        v_permissions := v_permissions || array['settings.manage']::text[];
      end if;
    end if;

    select access_role into v_registry_role
    from public.school_access_grants
    where person_id = p_person_id and app_code = 'central_registry' and grant_status = 'active'
      and valid_from <= now() and (valid_until is null or valid_until > now());
    if v_registry_role is not null then
      v_permissions := v_permissions || array['registry.read','registry.manage']::text[];
      if v_registry_role in ('registry_admin','admissions_officer') then
        v_permissions := v_permissions || array['admissions.manage']::text[];
      end if;
      if v_registry_role = 'registry_admin' then
        v_permissions := v_permissions || array['access.manage']::text[];
      end if;
    end if;

    select access_role into v_self_service_role
    from public.school_access_grants
    where person_id = p_person_id and app_code = 'staff_self_service' and grant_status = 'active'
      and valid_from <= now() and (valid_until is null or valid_until > now());
    if v_self_service_role is not null then
      v_permissions := v_permissions || array['profile.self.read','profile.self.update']::text[];
    end if;
  end if;

  select coalesce(array_agg(distinct permission order by permission), array[]::text[])
    into v_permissions from unnest(v_permissions) permission;

  select id into v_client_id
  from public.attendance_admin_clients
  where central_person_id = p_person_id
  order by created_at
  limit 1;

  if cardinality(v_permissions) = 0 then
    if v_client_id is not null then
      update public.attendance_admin_clients
      set permissions = array[]::text[], status = 'suspended', session_expires_at = null, updated_at = now()
      where id = v_client_id;
    end if;
    return v_client_id;
  end if;

  select full_name into v_name from public.school_people where id = p_person_id;
  v_client_code := 'WTS-ID-' || upper(substr(replace(p_person_id::text, '-', ''), 1, 12));
  if v_client_id is null then
    insert into public.attendance_admin_clients(
      client_code, client_name, secret_hash, status, permissions, central_person_id, session_source, metadata
    ) values(
      v_client_code,
      coalesce(v_name, 'Central staff') || ' — Central Access',
      encode(digest(encode(gen_random_bytes(32), 'hex'), 'sha256'), 'hex'),
      'suspended', v_permissions, p_person_id, 'central_identity', jsonb_build_object('central_identity', true)
    ) returning id into v_client_id;
  else
    update public.attendance_admin_clients
    set client_name = coalesce(v_name, client_name) || ' — Central Access',
        permissions = v_permissions,
        session_source = 'central_identity',
        metadata = metadata || jsonb_build_object('central_identity', true),
        updated_at = now()
    where id = v_client_id;
  end if;
  return v_client_id;
end;
$function$;

revoke all on function public.school_sync_person_admin_client(uuid) from public, anon, authenticated;

create or replace function public.school_identity_session_validate(
  p_session_id uuid,
  p_session_secret text,
  p_target_app_code text default null
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_session public.school_identity_sessions%rowtype;
  v_person public.school_people%rowtype;
  v_staff public.staff_attendance_profiles%rowtype;
  v_account public.school_identity_accounts%rowtype;
  v_credential public.school_identity_credentials%rowtype;
  v_grant public.school_access_grants%rowtype;
  v_target text;
  v_authority jsonb;
  v_permissions text[];
  v_access_role text;
  v_now timestamptz := now();
begin
  if p_session_id is null or coalesce(p_session_secret, '') = '' then
    return jsonb_build_object('ok', false, 'code', 'RESULT_SESSION_REQUIRED');
  end if;

  select s.* into v_session
  from public.school_identity_sessions s
  where s.id = p_session_id and s.revoked_at is null
  for update;
  if not found or v_session.expires_at <= v_now
     or encode(digest(p_session_secret, 'sha256'), 'hex') <> v_session.secret_hash then
    return jsonb_build_object('ok', false, 'code', 'RESULT_SESSION_NOT_ACTIVE');
  end if;

  v_target := lower(trim(coalesce(p_target_app_code, v_session.target_app_code)));
  if v_target <> v_session.target_app_code then
    return jsonb_build_object('ok', false, 'code', 'RESULT_SESSION_AUDIENCE_MISMATCH');
  end if;

  select p.* into v_person from public.school_people p where p.id = v_session.person_id;
  select s.* into v_staff from public.staff_attendance_profiles s where s.central_person_id = v_session.person_id limit 1;
  select i.* into v_account from public.school_identity_accounts i where i.id = v_session.identity_account_id;
  select c.* into v_credential
  from public.school_identity_credentials c
  where c.identity_account_id = v_session.identity_account_id and c.person_id = v_session.person_id
  order by c.created_at limit 1;

  if v_person.id is null or v_person.person_status <> 'active'
     or v_staff.id is null or v_staff.registration_status <> 'active' or v_staff.employment_status <> 'active'
     or v_account.id is null or v_account.account_status <> 'active'
     or v_credential.id is null or v_credential.credential_status <> 'active' then
    update public.school_identity_sessions
    set revoked_at = v_now,
        revocation_reason = case when v_credential.id is null or v_credential.credential_status <> 'active' then 'IDENTITY_CREDENTIAL_NOT_ACTIVE' else 'CENTRAL_IDENTITY_NOT_ACTIVE' end,
        last_seen_at = v_now
    where id = v_session.id and revoked_at is null;
    return jsonb_build_object('ok', false, 'code', case when v_credential.id is null or v_credential.credential_status <> 'active' then 'IDENTITY_CREDENTIAL_NOT_ACTIVE' else 'CENTRAL_IDENTITY_NOT_ACTIVE' end);
  end if;

  v_authority := wts_internal.institutional_authority(v_session.person_id);
  if coalesce((v_authority ->> 'active')::boolean, false) is true then
    v_access_role := v_authority ->> 'classification';
    v_permissions := wts_internal.institutional_permissions(v_session.person_id, v_target);
  else
    select g.* into v_grant
    from public.school_access_grants g
    where g.person_id = v_session.person_id and g.app_code = v_target and g.grant_status = 'active'
      and g.valid_from <= v_now and (g.valid_until is null or g.valid_until > v_now)
    order by g.created_at desc limit 1;
    if not found then
      update public.school_identity_sessions
      set revoked_at = v_now, revocation_reason = 'PORTAL_ACCESS_NOT_GRANTED', last_seen_at = v_now
      where id = v_session.id and revoked_at is null;
      return jsonb_build_object('ok', false, 'code', 'PORTAL_ACCESS_NOT_GRANTED');
    end if;
    v_access_role := v_grant.access_role;
    v_permissions := coalesce(v_grant.permissions, array[]::text[]);
  end if;

  update public.school_identity_sessions set last_seen_at = v_now where id = v_session.id;
  return jsonb_build_object(
    'ok', true,
    'code', 'IDENTITY_SESSION_ACTIVE',
    'session_id', v_session.id,
    'person_id', v_session.person_id,
    'identity_account_id', v_session.identity_account_id,
    'originating_app_code', v_session.originating_app_code,
    'target_app_code', v_session.target_app_code,
    'expires_at', v_session.expires_at,
    'access_role', v_access_role,
    'permissions', v_permissions,
    'institutional_authority', v_authority
  );
end;
$function$;

revoke execute on function public.school_identity_session_validate(uuid, text, text) from public;
grant execute on function public.school_identity_session_validate(uuid, text, text) to anon, authenticated;

create or replace function public.school_identity_session_issue(
  p_client_code text,
  p_client_secret text,
  p_originating_app_code text,
  p_target_app_code text
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_client public.attendance_admin_clients%rowtype;
  v_account public.school_identity_accounts%rowtype;
  v_person public.school_people%rowtype;
  v_staff public.staff_attendance_profiles%rowtype;
  v_grant public.school_access_grants%rowtype;
  v_authority jsonb;
  v_access_role text;
  v_permissions text[];
  v_secret text;
  v_session_id uuid;
  v_origin text := lower(trim(coalesce(p_originating_app_code, '')));
  v_target text := lower(trim(coalesce(p_target_app_code, '')));
  v_now timestamptz := now();
begin
  if v_origin = '' or v_target = '' then return jsonb_build_object('ok', false, 'code', 'SESSION_APPLICATION_REQUIRED'); end if;
  if not exists(select 1 from public.school_portal_catalog c where c.app_code = v_target and c.is_active and c.supports_login) then
    return jsonb_build_object('ok', false, 'code', 'SESSION_TARGET_INVALID');
  end if;

  select c.* into v_client
  from public.attendance_admin_clients c
  where c.client_code = trim(p_client_code) and c.status = 'active'
  for update;
  if not found or coalesce(p_client_secret, '') = ''
     or encode(digest(p_client_secret, 'sha256'), 'hex') <> v_client.secret_hash
     or v_client.central_person_id is null
     or (v_client.session_expires_at is not null and v_client.session_expires_at <= v_now) then
    return jsonb_build_object('ok', false, 'code', 'CENTRAL_SESSION_NOT_ACTIVE');
  end if;

  select p.* into v_person from public.school_people p where p.id = v_client.central_person_id;
  select s.* into v_staff from public.staff_attendance_profiles s where s.central_person_id = v_client.central_person_id limit 1;
  select i.* into v_account from public.school_identity_accounts i where i.person_id = v_client.central_person_id order by i.created_at limit 1;
  if v_person.id is null or v_person.person_status <> 'active' or v_staff.id is null or v_staff.registration_status <> 'active' or v_staff.employment_status <> 'active' or v_account.id is null or v_account.account_status <> 'active' then
    return jsonb_build_object('ok', false, 'code', 'CENTRAL_IDENTITY_NOT_ACTIVE');
  end if;

  v_authority := wts_internal.institutional_authority(v_client.central_person_id);
  if coalesce((v_authority ->> 'active')::boolean, false) is true then
    v_access_role := v_authority ->> 'classification';
    v_permissions := wts_internal.institutional_permissions(v_client.central_person_id, v_target);
  else
    select g.* into v_grant from public.school_access_grants g
    where g.person_id = v_client.central_person_id and g.app_code = v_target and g.grant_status = 'active'
      and g.valid_from <= v_now and (g.valid_until is null or g.valid_until > v_now) limit 1;
    if not found then return jsonb_build_object('ok', false, 'code', 'PORTAL_ACCESS_NOT_GRANTED'); end if;
    v_access_role := v_grant.access_role;
    v_permissions := coalesce(v_grant.permissions, array[]::text[]);
  end if;

  v_secret := encode(gen_random_bytes(32), 'base64');
  insert into public.school_identity_sessions(person_id,identity_account_id,originating_app_code,target_app_code,secret_hash,expires_at,metadata)
  values(v_client.central_person_id,v_account.id,v_origin,v_target,encode(digest(v_secret,'sha256'),'hex'),v_now+interval '8 hours',jsonb_build_object('source_client_id',v_client.id,'source','central_session_exchange'))
  returning id into v_session_id;

  insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,after_data,details)
  values('staff_session',v_client.central_person_id::text,'identity.session.issued','school_identity_sessions',v_session_id::text,jsonb_build_object('originating_app_code',v_origin,'target_app_code',v_target),jsonb_build_object('source','school_identity_session_issue'));

  return jsonb_build_object('ok',true,'code','IDENTITY_SESSION_ISSUED','session_id',v_session_id,'session_secret',v_secret,'expires_at',v_now+interval '8 hours','person_id',v_client.central_person_id,'identity_account_id',v_account.id,'target_app_code',v_target,'access_role',v_access_role,'permissions',v_permissions,'institutional_authority',v_authority);
end;
$function$;

create or replace function public.school_identity_portal_login(
  p_login text,
  p_password text,
  p_app_code text
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_credential public.school_identity_credentials%rowtype;
  v_account public.school_identity_accounts%rowtype;
  v_staff public.staff_attendance_profiles%rowtype;
  v_person public.school_people%rowtype;
  v_grant public.school_access_grants%rowtype;
  v_client public.attendance_admin_clients%rowtype;
  v_authority jsonb;
  v_access_role text;
  v_permissions text[];
  v_raw_secret text;
  v_app text := lower(trim(coalesce(p_app_code, '')));
  v_now timestamptz := now();
begin
  if trim(coalesce(p_login, '')) = '' or coalesce(p_password, '') = '' then return jsonb_build_object('ok', false, 'code', 'LOGIN_AND_PASSWORD_REQUIRED'); end if;
  if v_app not in ('attendance','notifications','central_registry','staff_self_service') then return jsonb_build_object('ok', false, 'code', 'INVALID_PORTAL'); end if;

  select c.* into v_credential
  from public.school_identity_credentials c
  join public.school_identity_accounts i on i.id = c.identity_account_id
  left join public.staff_attendance_profiles s on s.central_person_id = c.person_id
  where lower(c.login_name) = lower(trim(p_login)) or lower(coalesce(i.login_email, '')) = lower(trim(p_login)) or lower(coalesce(s.email, '')) = lower(trim(p_login))
  order by case when lower(c.login_name) = lower(trim(p_login)) then 0 else 1 end
  limit 1 for update of c;
  if not found then return jsonb_build_object('ok', false, 'code', 'INVALID_LOGIN'); end if;
  select * into v_account from public.school_identity_accounts where id = v_credential.identity_account_id;
  select * into v_person from public.school_people where id = v_credential.person_id;
  select * into v_staff from public.staff_attendance_profiles where central_person_id = v_credential.person_id limit 1;
  if v_credential.credential_status <> 'active' or v_account.account_status <> 'active' or v_person.person_status <> 'active' or v_staff.registration_status <> 'active' or v_staff.employment_status <> 'active' then return jsonb_build_object('ok', false, 'code', 'ACCOUNT_NOT_ACTIVE'); end if;
  if v_credential.locked_until is not null and v_credential.locked_until > v_now then return jsonb_build_object('ok', false, 'code', 'ACCOUNT_TEMPORARILY_LOCKED', 'locked_until', v_credential.locked_until); end if;
  if v_credential.password_hash is null or crypt(p_password, v_credential.password_hash) <> v_credential.password_hash then
    update public.school_identity_credentials set failed_attempts = failed_attempts + 1, locked_until = case when failed_attempts + 1 >= 5 then now() + interval '15 minutes' else locked_until end, updated_at = now() where id = v_credential.id;
    return jsonb_build_object('ok', false, 'code', 'INVALID_LOGIN');
  end if;

  v_authority := wts_internal.institutional_authority(v_credential.person_id);
  if coalesce((v_authority ->> 'active')::boolean, false) is true then
    v_access_role := v_authority ->> 'classification';
    v_permissions := wts_internal.institutional_permissions(v_credential.person_id, v_app);
  else
    select * into v_grant from public.school_access_grants where person_id = v_credential.person_id and app_code = v_app and grant_status = 'active' and valid_from <= v_now and (valid_until is null or valid_until > v_now) limit 1;
    if not found then return jsonb_build_object('ok', false, 'code', 'PORTAL_ACCESS_NOT_GRANTED'); end if;
    v_access_role := v_grant.access_role;
    v_permissions := coalesce(v_grant.permissions, array[]::text[]);
  end if;

  perform public.school_sync_person_admin_client(v_credential.person_id);
  select * into v_client from public.attendance_admin_clients where central_person_id = v_credential.person_id order by created_at limit 1;
  if not found or not ((v_app = 'attendance' and ('dashboard.read' = any(v_client.permissions) or '*' = any(v_client.permissions))) or (v_app = 'notifications' and ('notifications.manage' = any(v_client.permissions) or '*' = any(v_client.permissions))) or (v_app = 'central_registry' and ('registry.manage' = any(v_client.permissions) or '*' = any(v_client.permissions))) or (v_app = 'staff_self_service' and ('profile.self.read' = any(v_client.permissions) or '*' = any(v_client.permissions)))) then return jsonb_build_object('ok', false, 'code', 'PORTAL_PERMISSION_SYNC_FAILED'); end if;

  v_raw_secret := encode(gen_random_bytes(32), 'base64');
  update public.attendance_admin_clients set secret_hash = encode(digest(v_raw_secret, 'sha256'), 'hex'), status = 'active', session_expires_at = now() + interval '8 hours', session_source = 'central_identity', last_seen_at = now(), updated_at = now(), metadata = metadata || jsonb_build_object('last_portal_login', v_app, 'last_person_login_at', now()) where id = v_client.id;
  update public.school_identity_credentials set failed_attempts = 0, locked_until = null, last_login_at = now() where id = v_credential.id;
  update public.school_identity_accounts set last_login_at = now(), updated_at = now() where id = v_account.id;

  return jsonb_build_object('ok', true, 'code', 'PORTAL_LOGIN_SUCCESS', 'app_code', v_app, 'client_code', v_client.client_code, 'client_secret', v_raw_secret, 'expires_at', now() + interval '8 hours', 'person', jsonb_build_object('person_id', v_person.id, 'staff_id', v_staff.id, 'full_name', v_staff.full_name, 'staff_number', v_staff.staff_number, 'designation', v_staff.designation, 'photo', v_staff.photo), 'access_role', v_access_role, 'permissions', v_permissions, 'must_change_password', v_credential.must_change_password, 'institutional_authority', v_authority);
end;
$function$;

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
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_context jsonb;
  v_client public.school_sso_clients%rowtype;
  v_person_id uuid;
  v_identity_account_id uuid;
  v_authority jsonb;
  v_code_id uuid;
  v_created_at timestamptz := now();
  v_expires_at timestamptz := v_created_at + interval '5 minutes';
begin
  select c.* into v_client from public.school_sso_clients c where c.client_id = lower(trim(coalesce(p_client_id, ''))) and c.is_active;
  if not found or v_client.target_app_code <> lower(trim(coalesce(p_target_app_code, ''))) or v_client.redirect_uri <> trim(coalesce(p_redirect_uri, '')) then return jsonb_build_object('ok', false, 'code', 'SSO_CLIENT_OR_REDIRECT_INVALID'); end if;
  if coalesce(trim(p_code_hash), '') !~ '^[0-9a-f]{64}$' or coalesce(trim(p_code_challenge), '') !~ '^[A-Za-z0-9_-]{43,128}$' or trim(coalesce(p_code_challenge_method, '')) <> 'S256' or coalesce(trim(p_state_hash), '') !~ '^[0-9a-f]{64}$' or coalesce(trim(p_nonce_hash), '') !~ '^[0-9a-f]{64}$' then return jsonb_build_object('ok', false, 'code', 'SSO_REQUEST_INVALID'); end if;

  v_context := public.school_identity_session_validate(p_session_id, p_session_secret, 'staff_self_service');
  if coalesce((v_context ->> 'ok')::boolean, false) is not true then return jsonb_build_object('ok', false, 'code', 'WTS_SESSION_NOT_ACTIVE'); end if;
  v_person_id := nullif(v_context ->> 'person_id', '')::uuid;
  v_identity_account_id := nullif(v_context ->> 'identity_account_id', '')::uuid;
  if v_person_id is null or v_identity_account_id is null then return jsonb_build_object('ok', false, 'code', 'WTS_SESSION_NOT_ACTIVE'); end if;
  v_authority := wts_internal.institutional_authority(v_person_id);
  if coalesce((v_authority ->> 'active')::boolean, false) is not true
     and not exists (
       select 1 from public.school_access_grants g
       where g.person_id = v_person_id
         and g.app_code = v_client.target_app_code
         and g.grant_status = 'active'
         and g.valid_from <= now()
         and (g.valid_until is null or g.valid_until > now())
     ) then
    return jsonb_build_object('ok', false, 'code', case when v_client.target_app_code = 'attendance' then 'ATTENDANCE_ACCESS_NOT_GRANTED' else 'RESULT_ACCESS_NOT_GRANTED' end);
  end if;
  if v_client.target_app_code = 'results' and coalesce((v_authority ->> 'active')::boolean, false) is not true then
    if coalesce((public.school_result_identity_resolve(v_person_id, v_identity_account_id) ->> 'ok')::boolean, false) is not true then return jsonb_build_object('ok', false, 'code', 'RESULT_IDENTITY_NOT_RESOLVED'); end if;
  end if;

  insert into public.school_sso_authorization_codes(code_hash,client_id,target_app_code,redirect_uri,person_id,identity_account_id,source_session_id,code_challenge,code_challenge_method,state_hash,nonce_hash,created_at,expires_at)
  values(lower(trim(p_code_hash)),v_client.client_id,v_client.target_app_code,v_client.redirect_uri,v_person_id,v_identity_account_id,p_session_id,trim(p_code_challenge),'S256',lower(trim(p_state_hash)),lower(trim(p_nonce_hash)),v_created_at,v_expires_at)
  returning id into v_code_id;
  insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,details)
  values('staff_session',v_person_id::text,'identity.sso.authorization_code.issued','school_sso_authorization_codes',v_code_id::text,jsonb_build_object('client_id',v_client.client_id,'target_app_code',v_client.target_app_code,'redirect_uri',v_client.redirect_uri,'code_challenge_method','S256','expires_at',v_expires_at));
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
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_code public.school_sso_authorization_codes%rowtype;
  v_source_session public.school_identity_sessions%rowtype;
  v_client public.school_sso_clients%rowtype;
  v_person public.school_people%rowtype;
  v_staff public.staff_attendance_profiles%rowtype;
  v_account public.school_identity_accounts%rowtype;
  v_grant public.school_access_grants%rowtype;
  v_authority jsonb;
  v_permissions text[];
  v_access_role text;
  v_session_id uuid;
  v_session_secret text;
  v_attendance_client public.attendance_admin_clients%rowtype;
  v_attendance_client_secret text;
  v_expires_at timestamptz;
  v_verifier_challenge text;
begin
  select c.* into v_client from public.school_sso_clients c where c.client_id = lower(trim(coalesce(p_client_id, ''))) and c.is_active;
  if not found or v_client.redirect_uri <> trim(coalesce(p_redirect_uri, '')) then return jsonb_build_object('ok', false, 'code', 'SSO_CLIENT_OR_REDIRECT_INVALID'); end if;
  if coalesce(trim(p_code), '') = '' or coalesce(trim(p_code_verifier), '') !~ '^[A-Za-z0-9._~-]{43,128}$' or coalesce(trim(p_state), '') !~ '^[A-Za-z0-9._~-]{16,255}$' or coalesce(trim(p_nonce), '') !~ '^[A-Za-z0-9._~-]{16,255}$' then return jsonb_build_object('ok', false, 'code', 'SSO_REQUEST_INVALID'); end if;

  select c.* into v_code from public.school_sso_authorization_codes c where c.code_hash = encode(digest(trim(p_code), 'sha256'), 'hex') for update;
  if not found then return jsonb_build_object('ok', false, 'code', 'SSO_CODE_INVALID'); end if;
  if v_code.client_id <> v_client.client_id or v_code.target_app_code <> v_client.target_app_code then return jsonb_build_object('ok', false, 'code', 'SSO_AUDIENCE_INVALID'); end if;
  if v_code.redirect_uri <> v_client.redirect_uri or trim(p_redirect_uri) <> v_code.redirect_uri then return jsonb_build_object('ok', false, 'code', 'SSO_REDIRECT_URI_MISMATCH'); end if;
  if v_code.consumed_at is not null then return jsonb_build_object('ok', false, 'code', 'SSO_CODE_REUSED'); end if;
  if v_code.expires_at <= now() then return jsonb_build_object('ok', false, 'code', 'SSO_CODE_EXPIRED'); end if;
  if encode(digest(trim(p_state), 'sha256'), 'hex') <> v_code.state_hash or encode(digest(trim(p_nonce), 'sha256'), 'hex') <> v_code.nonce_hash then return jsonb_build_object('ok', false, 'code', 'SSO_STATE_OR_NONCE_INVALID'); end if;

  v_verifier_challenge := rtrim(replace(replace(encode(digest(trim(p_code_verifier), 'sha256'), 'base64'), '+', '-'), '/', '_'), '=');
  if v_code.code_challenge_method <> 'S256' or v_verifier_challenge <> v_code.code_challenge then return jsonb_build_object('ok', false, 'code', 'SSO_PKCE_INVALID'); end if;

  select s.* into v_source_session from public.school_identity_sessions s where s.id = v_code.source_session_id and s.person_id = v_code.person_id and s.identity_account_id = v_code.identity_account_id and s.target_app_code = 'staff_self_service' and s.revoked_at is null and s.expires_at > now() for update;
  if not found then
    update public.school_sso_authorization_codes set consumed_at = now(), consumed_by = 'source_session_inactive' where id = v_code.id and consumed_at is null;
    return jsonb_build_object('ok', false, 'code', 'WTS_SESSION_NOT_ACTIVE');
  end if;

  select p.* into v_person from public.school_people p where p.id = v_code.person_id for update;
  select i.* into v_account from public.school_identity_accounts i where i.id = v_code.identity_account_id and i.person_id = v_code.person_id for update;
  select s.* into v_staff from public.staff_attendance_profiles s where s.central_person_id = v_code.person_id and s.registration_status = 'active' and s.employment_status = 'active' order by s.created_at limit 1;
  if v_person.id is null or v_person.person_status <> 'active' or v_account.id is null or v_account.account_status <> 'active' or v_staff.id is null or not exists(select 1 from public.school_identity_credentials cr where cr.identity_account_id = v_account.id and cr.person_id = v_code.person_id and cr.credential_status = 'active') then
    update public.school_sso_authorization_codes set consumed_at = now(), consumed_by = 'identity_revalidation_denied' where id = v_code.id and consumed_at is null;
    return jsonb_build_object('ok', false, 'code', 'IDENTITY_NOT_ACTIVE');
  end if;

  v_authority := wts_internal.institutional_authority(v_code.person_id);
  select g.* into v_grant from public.school_access_grants g where g.person_id = v_code.person_id and g.app_code = v_client.target_app_code and g.grant_status = 'active' and g.valid_from <= now() and (g.valid_until is null or g.valid_until > now()) order by g.created_at desc limit 1;
  if coalesce((v_authority ->> 'active')::boolean, false) is not true and not found then
    update public.school_sso_authorization_codes set consumed_at = now(), consumed_by = 'module_grant_missing' where id = v_code.id and consumed_at is null;
    return jsonb_build_object('ok', false, 'code', case when v_client.target_app_code = 'attendance' then 'ATTENDANCE_ACCESS_NOT_GRANTED' else 'RESULT_ACCESS_NOT_GRANTED' end);
  end if;
  if coalesce((v_authority ->> 'active')::boolean, false) is true then
    v_access_role := v_authority ->> 'classification';
    v_permissions := wts_internal.institutional_permissions(v_code.person_id, v_client.target_app_code);
  else
    v_access_role := v_grant.access_role;
    v_permissions := coalesce(v_grant.permissions, array[]::text[]);
  end if;
  if v_client.target_app_code = 'results' and coalesce((v_authority ->> 'active')::boolean, false) is not true and coalesce((public.school_result_identity_resolve(v_code.person_id, v_code.identity_account_id) ->> 'ok')::boolean, false) is not true then
    update public.school_sso_authorization_codes set consumed_at = now(), consumed_by = 'result_identity_unresolved' where id = v_code.id and consumed_at is null;
    return jsonb_build_object('ok', false, 'code', 'RESULT_IDENTITY_NOT_RESOLVED');
  end if;

  update public.school_sso_authorization_codes set consumed_at = now(), consumed_by = v_client.client_id where id = v_code.id and consumed_at is null;
  if not found then return jsonb_build_object('ok', false, 'code', 'SSO_CODE_REUSED'); end if;

  v_session_secret := encode(gen_random_bytes(32), 'base64');
  v_expires_at := now() + interval '8 hours';
  insert into public.school_identity_sessions(person_id,identity_account_id,originating_app_code,target_app_code,secret_hash,created_at,expires_at,last_seen_at,metadata)
  values(v_code.person_id,v_code.identity_account_id,v_client.target_app_code,v_client.target_app_code,encode(digest(v_session_secret,'sha256'),'hex'),now(),v_expires_at,now(),jsonb_build_object('source','pkce_sso','authorization_code_id',v_code.id,'source_workspace_session_id',v_code.source_session_id))
  returning id into v_session_id;

  if v_client.target_app_code = 'attendance' then
    perform public.school_sync_person_admin_client(v_code.person_id);
    select c.* into v_attendance_client from public.attendance_admin_clients c where c.central_person_id = v_code.person_id order by c.created_at limit 1 for update;
    if not found then
      delete from public.school_identity_sessions where id = v_session_id;
      return jsonb_build_object('ok', false, 'code', 'ATTENDANCE_SESSION_SERVICE_UNAVAILABLE');
    end if;
    v_attendance_client_secret := encode(gen_random_bytes(32), 'base64');
    update public.attendance_admin_clients
    set secret_hash = encode(digest(v_attendance_client_secret, 'sha256'), 'hex'), status = 'active', session_expires_at = v_expires_at, session_source = 'central_identity', last_seen_at = now(), updated_at = now(), metadata = metadata || jsonb_build_object('attendance_session_id', v_session_id, 'central_session_id', v_session_id, 'authorization_code_id', v_code.id, 'target_app_code', 'attendance')
    where id = v_attendance_client.id;
  end if;

  insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,details)
  values('staff_session',v_code.person_id::text,case when v_client.target_app_code = 'attendance' then 'identity.attendance_session.issued' else 'identity.result_session.issued' end,'school_identity_sessions',v_session_id::text,jsonb_build_object('source','pkce_sso','authorization_code_id',v_code.id,'target_app_code',v_client.target_app_code,'expires_at',v_expires_at,'institutional_classification',v_authority ->> 'classification'));

  return jsonb_build_object('ok',true,'code','SSO_EXCHANGED','session_id',v_session_id,'session_secret',v_session_secret,'expires_at',v_expires_at,'person_id',v_code.person_id,'identity_account_id',v_code.identity_account_id,'access_role',v_access_role,'permissions',v_permissions,'institutional_authority',v_authority,'attendance_client_code',case when v_client.target_app_code = 'attendance' then v_attendance_client.client_code else null end,'attendance_client_secret',case when v_client.target_app_code = 'attendance' then v_attendance_client_secret else null end);
end;
$function$;

revoke all on function public.school_sso_authorization_code_issue(uuid,text,text,text,text,text,text,text,text,text) from public, anon, authenticated;
grant execute on function public.school_sso_authorization_code_issue(uuid,text,text,text,text,text,text,text,text,text) to anon, authenticated;
revoke all on function public.school_sso_authorization_code_exchange(text,text,text,text,text,text) from public, anon, authenticated;
grant execute on function public.school_sso_authorization_code_exchange(text,text,text,text,text,text) to anon, authenticated;

create or replace function public.school_identity_session_revoke(
  p_session_id uuid,
  p_session_secret text,
  p_reason text default 'SESSION_LOGOUT'
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_session public.school_identity_sessions%rowtype;
  v_reason text := left(coalesce(nullif(trim(p_reason), ''), 'SESSION_LOGOUT'), 160);
  v_linked_count integer := 0;
  v_linked public.school_identity_sessions%rowtype;
begin
  select s.* into v_session from public.school_identity_sessions s where s.id = p_session_id and s.revoked_at is null for update;
  if not found or coalesce(p_session_secret, '') = '' or encode(digest(p_session_secret, 'sha256'), 'hex') <> v_session.secret_hash then return jsonb_build_object('ok', false, 'code', 'RESULT_SESSION_NOT_ACTIVE'); end if;
  update public.school_identity_sessions set revoked_at = now(), revocation_reason = v_reason, last_seen_at = now() where id = v_session.id;
  insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,details) values('staff_session',v_session.person_id::text,'identity.session.revoked','school_identity_sessions',v_session.id::text,jsonb_build_object('reason',v_reason,'target_app_code',v_session.target_app_code));

  if v_session.target_app_code in ('staff_self_service','central_registry') then
    for v_linked in select s.* from public.school_identity_sessions s where s.target_app_code in ('results','attendance') and s.revoked_at is null and s.person_id = v_session.person_id and s.identity_account_id = v_session.identity_account_id and (v_session.target_app_code = 'central_registry' or s.metadata ->> 'source_workspace_session_id' = v_session.id::text) for update loop
      update public.school_identity_sessions set revoked_at = now(), revocation_reason = 'LINKED_WTS_SESSION_REVOKED', last_seen_at = now() where id = v_linked.id;
      insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,details) values('staff_session',v_session.person_id::text,case when v_linked.target_app_code = 'attendance' then 'identity.attendance_session.linked_revoked' else 'identity.result_session.linked_revoked' end,'school_identity_sessions',v_linked.id::text,jsonb_build_object('source_session_id',v_session.id,'source_app_code',v_session.target_app_code,'reason',v_reason));
      v_linked_count := v_linked_count + 1;
    end loop;
  end if;

  if v_session.target_app_code in ('staff_self_service','central_registry','attendance') then
    update public.attendance_admin_clients set status = 'suspended', session_expires_at = null, updated_at = now() where central_person_id = v_session.person_id and session_source = 'central_identity';
  end if;
  return jsonb_build_object('ok', true, 'code', 'IDENTITY_SESSION_REVOKED', 'linked_sessions_revoked', v_linked_count);
end;
$function$;

revoke execute on function public.school_identity_session_revoke(uuid,text,text) from public;
grant execute on function public.school_identity_session_revoke(uuid,text,text) to anon, authenticated;

create or replace function wts_internal.revoke_identity_sessions(p_person_id uuid, p_reason text)
returns integer
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare v_count integer;
begin
  update public.school_identity_sessions set revoked_at = coalesce(revoked_at, now()), revocation_reason = coalesce(nullif(trim(p_reason), ''), 'IDENTITY_STATE_CHANGED'), last_seen_at = now() where person_id = p_person_id and revoked_at is null;
  get diagnostics v_count = row_count;
  update public.attendance_admin_clients set status = 'suspended', session_expires_at = null, updated_at = now() where central_person_id = p_person_id and session_source = 'central_identity';
  return v_count;
end;
$function$;

revoke all on function wts_internal.revoke_identity_sessions(uuid,text) from public, anon, authenticated;

create or replace function wts_internal.protect_institutional_person_update()
returns trigger
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
begin
  if (old.institutional_classification <> 'ordinary_staff' or new.institutional_classification <> 'ordinary_staff')
     and current_setting('wts.allow_institutional_recovery', true) <> 'on'
     and (
       old.institutional_classification is distinct from new.institutional_classification
       or old.institutional_number is distinct from new.institutional_number
       or old.person_status is distinct from new.person_status
       or old.archived_at is distinct from new.archived_at
     ) then
    raise exception 'PROTECTED_INSTITUTIONAL_IDENTITY_CHANGE_REQUIRES_RECOVERY';
  end if;
  return new;
end;
$function$;

create or replace function wts_internal.protect_institutional_account_update()
returns trigger
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
begin
  if new.account_status <> 'active'
     and current_setting('wts.allow_institutional_recovery', true) <> 'on'
     and exists(select 1 from public.school_people p where p.id = new.person_id and p.institutional_classification <> 'ordinary_staff') then
    raise exception 'PROTECTED_INSTITUTIONAL_ACCOUNT_CHANGE_REQUIRES_RECOVERY';
  end if;
  return new;
end;
$function$;

create or replace function wts_internal.protect_institutional_staff_update()
returns trigger
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
begin
  if (new.employment_status is distinct from old.employment_status or new.registration_status is distinct from old.registration_status)
     and current_setting('wts.allow_institutional_recovery', true) <> 'on'
     and exists(select 1 from public.school_people p where p.id = new.central_person_id and p.institutional_classification <> 'ordinary_staff') then
    raise exception 'PROTECTED_INSTITUTIONAL_EMPLOYMENT_CHANGE_REQUIRES_RECOVERY';
  end if;
  return new;
end;
$function$;

drop trigger if exists school_people_institutional_protection on public.school_people;
create trigger school_people_institutional_protection
before update on public.school_people
for each row execute function wts_internal.protect_institutional_person_update();

drop trigger if exists school_identity_accounts_institutional_protection on public.school_identity_accounts;
create trigger school_identity_accounts_institutional_protection
before update on public.school_identity_accounts
for each row execute function wts_internal.protect_institutional_account_update();

drop trigger if exists staff_attendance_profiles_institutional_protection on public.staff_attendance_profiles;
create trigger staff_attendance_profiles_institutional_protection
before update on public.staff_attendance_profiles
for each row execute function wts_internal.protect_institutional_staff_update();

create or replace function public.school_institutional_recovery_api(
  p_session_id uuid,
  p_session_secret text,
  p_target_person_id uuid,
  p_action text,
  p_reason text,
  p_recent_reauthentication boolean,
  p_explicit_confirmation boolean
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_session jsonb;
  v_target public.school_people%rowtype;
  v_actor_authority jsonb;
begin
  if not coalesce(p_recent_reauthentication, false) or not coalesce(p_explicit_confirmation, false) or length(trim(coalesce(p_reason, ''))) < 8 then return jsonb_build_object('ok', false, 'code', 'PROTECTED_RECOVERY_CONFIRMATION_REQUIRED'); end if;
  v_session := public.school_identity_session_validate(p_session_id, p_session_secret, 'central_registry');
  if coalesce((v_session ->> 'ok')::boolean, false) is not true then return v_session; end if;
  v_actor_authority := v_session -> 'institutional_authority';
  if v_actor_authority ->> 'classification' <> 'system_owner' then return jsonb_build_object('ok', false, 'code', 'PROTECTED_RECOVERY_OWNER_REQUIRED'); end if;
  select * into v_target from public.school_people where id = p_target_person_id for update;
  if not found or v_target.institutional_classification = 'ordinary_staff' then return jsonb_build_object('ok', false, 'code', 'PROTECTED_IDENTITY_NOT_FOUND'); end if;
  if p_action <> 'restore' then return jsonb_build_object('ok', false, 'code', 'PROTECTED_RECOVERY_ACTION_INVALID'); end if;
  perform set_config('wts.allow_institutional_recovery', 'on', true);
  update public.school_people set person_status = 'active', archived_at = null, archived_reason = null, updated_at = now() where id = p_target.id;
  update public.school_identity_accounts set account_status = 'active', updated_at = now() where person_id = p_target.id;
  update public.staff_attendance_profiles set employment_status = 'active', registration_status = 'active', archived_at = null, updated_at = now() where central_person_id = p_target.id;
  insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,details) values('person',v_session ->> 'person_id','identity.institutional.recovery.restored','school_people',p_target.id::text,jsonb_build_object('reason',left(trim(p_reason),240),'confirmed',true,'recent_reauthentication',true));
  return jsonb_build_object('ok',true,'code','PROTECTED_IDENTITY_RESTORED','person_id',p_target.id);
end;
$function$;

revoke all on function public.school_institutional_recovery_api(uuid,text,uuid,text,text,boolean,boolean) from public, anon, authenticated;
grant execute on function public.school_institutional_recovery_api(uuid,text,uuid,text,text,boolean,boolean) to anon, authenticated;

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
    'staff', coalesce((select jsonb_agg(jsonb_build_object('person_id',s.central_person_id,'staff_id',s.id,'staff_number',s.staff_number,'full_name',s.full_name,'employment_status',s.employment_status,'registration_status',s.registration_status,'valid_from',coalesce(s.activated_at::date,s.created_at::date),'valid_until',s.archived_at::date,'attendance_required',coalesce(p.personal_attendance_required,s.attendance_required)) order by s.full_name) from public.staff_attendance_profiles s join public.school_people p on p.id=s.central_person_id where s.central_person_id is not null and s.registration_status='active' and s.employment_status='active' and coalesce(s.activated_at::date,s.created_at::date)<=v_as_of_date and (s.archived_at is null or s.archived_at::date>v_as_of_date) and p.person_status='active'),'[]'::jsonb),
    'class_teachers', coalesce((select jsonb_agg(jsonb_build_object('person_id',a.person_id,'staff_id',a.staff_id,'class_key',a.class_key,'responsibility',a.responsibility,'effective_from',a.effective_from::date,'effective_until',a.effective_until::date) order by a.class_key,a.responsibility) from public.school_staff_class_allocations a where a.allocation_status='active' and a.responsibility in ('class_teacher','assistant_class_teacher') and a.effective_from::date<=v_as_of_date and (a.effective_until is null or a.effective_until::date>v_as_of_date) and (a.academic_session=v_academic_session or a.academic_session is null) and (a.term_name=v_term or a.term_name is null)),'[]'::jsonb),
    'attendance_grants', coalesce((select jsonb_agg(jsonb_build_object('person_id',g.person_id,'access_role',g.access_role,'permissions',g.permissions,'valid_from',g.valid_from::date,'valid_until',g.valid_until::date) order by g.person_id) from public.school_access_grants g where g.app_code='attendance' and g.grant_status='active' and g.valid_from<=now() and (g.valid_until is null or g.valid_until>now())),'[]'::jsonb),
    'requested_by_person_id', v_person_id
  );
end;
$function$;

revoke all on function public.school_attendance_registry_roster_read_api(uuid,text,text,text,date) from public, anon, authenticated;
grant execute on function public.school_attendance_registry_roster_read_api(uuid,text,text,text,date) to anon, authenticated;

-- Preserve normal staff-management list semantics while excluding institutional
-- identities from ordinary lists. Restricted security/audit views can opt in.
create or replace function public.school_access_management_read_api(
  p_client_code text,
  p_client_secret text,
  p_action text,
  p_payload jsonb default '{}'::jsonb
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_client_id uuid;
  v_actor_person_id uuid;
  v_actor_authority jsonb;
  v_search text := lower(trim(coalesce(p_payload ->> 'search', '')));
  v_staff_id uuid;
  v_person_id uuid;
begin
  v_client_id := public.school_registry_verify_admin(p_client_code, p_client_secret, 'access.manage');
  if v_client_id is null then return jsonb_build_object('ok', false, 'code', 'MANAGEMENT_ACCESS_DENIED'); end if;
  select central_person_id into v_actor_person_id from public.attendance_admin_clients where id = v_client_id;
  v_actor_authority := wts_internal.institutional_authority(v_actor_person_id);

  if p_action = 'staff' then
    return jsonb_build_object('ok', true, 'staff', coalesce((select jsonb_agg(to_jsonb(x) order by x.full_name) from (
      select s.id as staff_id,s.central_person_id as person_id,s.staff_number,s.full_name,s.designation,s.staff_category,s.department,s.employment_status,s.registration_status,i.account_status,
        coalesce((select count(*) from public.school_access_grants g where g.person_id=s.central_person_id and g.grant_status='active' and g.valid_from<=now() and (g.valid_until is null or g.valid_until>now())),0) as active_module_count
      from public.staff_attendance_profiles s join public.school_identity_accounts i on i.person_id=s.central_person_id join public.school_people p on p.id=s.central_person_id
      where s.central_person_id is not null and s.registration_status='active' and s.employment_status='active' and p.institutional_classification='ordinary_staff' and (v_search='' or lower(s.full_name) like '%'||v_search||'%' or lower(coalesce(s.staff_number,'')) like '%'||v_search||'%') order by s.full_name limit 200
    ) x),'[]'::jsonb));
  end if;

  if p_action = 'securityStaff' then
    if v_actor_authority ->> 'classification' not in ('system_owner','proprietor') then return jsonb_build_object('ok', false, 'code', 'SECURITY_VIEW_RESTRICTED'); end if;
    return jsonb_build_object('ok', true, 'staff', coalesce((select jsonb_agg(to_jsonb(x) order by x.full_name) from (
      select s.id as staff_id,s.central_person_id as person_id,s.staff_number,s.full_name,s.employment_status,s.registration_status,i.account_status,p.institutional_classification,p.institutional_number,p.personal_attendance_required
      from public.staff_attendance_profiles s join public.school_identity_accounts i on i.person_id=s.central_person_id join public.school_people p on p.id=s.central_person_id where p.institutional_classification<>'ordinary_staff' order by s.full_name
    ) x),'[]'::jsonb));
  end if;

  if p_action = 'staffAccessProfile' then
    begin v_staff_id := (p_payload ->> 'staffId')::uuid; exception when others then return jsonb_build_object('ok',false,'code','INVALID_STAFF_ID'); end;
    select central_person_id into v_person_id from public.staff_attendance_profiles where id=v_staff_id;
    if v_person_id is null then return jsonb_build_object('ok',false,'code','STAFF_IDENTITY_NOT_LINKED'); end if;
    if exists(select 1 from public.school_people where id=v_person_id and institutional_classification<>'ordinary_staff') and v_actor_authority ->> 'classification' not in ('system_owner','proprietor') then return jsonb_build_object('ok',false,'code','PROTECTED_IDENTITY_RESTRICTED'); end if;
    return jsonb_build_object('ok',true,'staff',(select jsonb_build_object('staff_id',s.id,'person_id',s.central_person_id,'staff_number',s.staff_number,'full_name',s.full_name,'designation',s.designation,'staff_category',s.staff_category,'department',s.department,'employment_status',s.employment_status,'registration_status',s.registration_status,'public_visibility_approved',s.public_visibility_approved,'account_status',i.account_status,'institutional_authority',wts_internal.institutional_authority(s.central_person_id)) from public.staff_attendance_profiles s join public.school_identity_accounts i on i.person_id=s.central_person_id where s.id=v_staff_id),'module_grants',coalesce((select jsonb_agg(jsonb_build_object('id',g.id,'app_code',g.app_code,'access_role',g.access_role,'permissions',g.permissions,'grant_status',g.grant_status,'valid_from',g.valid_from,'valid_until',g.valid_until,'reason',g.reason,'revoked_at',g.revoked_at,'revocation_reason',g.revocation_reason) order by g.app_code) from public.school_access_grants g where g.person_id=v_person_id),'[]'::jsonb));
  end if;
  return jsonb_build_object('ok',false,'code','UNKNOWN_ACTION');
end;
$function$;
