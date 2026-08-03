-- WTS Result authorization boundary and central session foundation.
-- This migration adds security infrastructure only. It does not create
-- identities, grants, scopes, students, scores, or other operational data.

create table if not exists public.school_identity_sessions (
  id uuid primary key default gen_random_uuid(),
  person_id uuid not null references public.school_people(id) on delete restrict,
  identity_account_id uuid not null references public.school_identity_accounts(id) on delete restrict,
  originating_app_code text not null,
  target_app_code text not null,
  secret_hash text not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  last_seen_at timestamptz not null default now(),
  revoked_at timestamptz,
  revocation_reason text,
  metadata jsonb not null default '{}'::jsonb,
  constraint school_identity_sessions_origin_check check (length(trim(originating_app_code)) > 0),
  constraint school_identity_sessions_target_check check (length(trim(target_app_code)) > 0),
  constraint school_identity_sessions_secret_check check (length(secret_hash) >= 32),
  constraint school_identity_sessions_expiry_check check (expires_at > created_at)
);

create index if not exists school_identity_sessions_active_person_idx
  on public.school_identity_sessions (person_id, target_app_code, expires_at desc)
  where revoked_at is null;

create index if not exists school_identity_sessions_active_secret_idx
  on public.school_identity_sessions (id, expires_at)
  where revoked_at is null;

alter table public.school_identity_sessions enable row level security;
revoke all on table public.school_identity_sessions from public, anon, authenticated;

create or replace function public.school_result_permission_allowed(
  p_permissions text[],
  p_required text
)
returns boolean
language sql
immutable
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
  select case trim(coalesce(p_required, ''))
    when 'results.manage' then 'results.manage' = any(coalesce(p_permissions, array[]::text[]))
    when 'results.publish' then coalesce(p_permissions, array[]::text[]) && array['results.publish', 'result_publishing.publish']::text[]
    when 'scores.enter' then coalesce(p_permissions, array[]::text[]) && array['scores.enter', 'result_entry.create', 'result_entry.edit', 'result_entry.submit']::text[]
    when 'remarks.enter' then coalesce(p_permissions, array[]::text[]) && array['remarks.enter', 'result_entry.edit']::text[]
    when 'results.view_assigned' then coalesce(p_permissions, array[]::text[]) && array['results.view_assigned', 'result_entry.view']::text[]
    when 'results.review' then coalesce(p_permissions, array[]::text[]) && array['results.review', 'result_review.review']::text[]
    when 'results.approve' then coalesce(p_permissions, array[]::text[]) && array['results.approve', 'result_approval.approve']::text[]
    when 'report_cards.generate' then coalesce(p_permissions, array[]::text[]) && array['report_cards.generate', 'report_cards.view']::text[]
    when 'results.export' then coalesce(p_permissions, array[]::text[]) && array['results.export', 'report_cards.export']::text[]
    else trim(coalesce(p_required, '')) = any(coalesce(p_permissions, array[]::text[]))
  end;
$function$;

revoke all on function public.school_result_permission_allowed(text[], text) from public, anon, authenticated;

create or replace function public.school_result_identity_resolve(
  p_person_id uuid,
  p_identity_account_id uuid default null
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_match_count integer;
  v_user public.user_profiles%rowtype;
  v_staff public.staff_attendance_profiles%rowtype;
  v_account public.school_identity_accounts%rowtype;
  v_person public.school_people%rowtype;
begin
  if p_person_id is null then
    return jsonb_build_object('ok', false, 'code', 'CENTRAL_PERSON_REQUIRED');
  end if;

  select count(*) into v_match_count
  from (
    select distinct u.id
    from public.user_profiles u
    join public.staff_attendance_profiles s on s.user_profile_id = u.id
    where s.central_person_id = p_person_id
  ) mapped;

  if v_match_count = 0 then
    return jsonb_build_object('ok', false, 'code', 'RESULT_USER_MAPPING_NOT_FOUND');
  end if;
  if v_match_count > 1 then
    return jsonb_build_object('ok', false, 'code', 'RESULT_USER_MAPPING_AMBIGUOUS');
  end if;

  select u.* into v_user
  from public.user_profiles u
  join public.staff_attendance_profiles s on s.user_profile_id = u.id
  where s.central_person_id = p_person_id
  limit 1;

  select s.* into v_staff
  from public.staff_attendance_profiles s
  where s.central_person_id = p_person_id
    and s.user_profile_id = v_user.id
  limit 1;

  select i.* into v_account
  from public.school_identity_accounts i
  where i.person_id = p_person_id
    and (p_identity_account_id is null or i.id = p_identity_account_id)
  order by i.created_at
  limit 1;

  select p.* into v_person
  from public.school_people p
  where p.id = p_person_id;

  if not found or v_person.id is null or v_person.person_status <> 'active'
     or v_staff.id is null
     or v_staff.registration_status <> 'active'
     or v_staff.employment_status <> 'active'
     or v_account.id is null
     or v_account.account_status <> 'active' then
    return jsonb_build_object('ok', false, 'code', 'RESULT_IDENTITY_INACTIVE');
  end if;

  return jsonb_build_object(
    'ok', true,
    'code', 'RESULT_IDENTITY_RESOLVED',
    'person_id', v_person.id,
    'identity_account_id', v_account.id,
    'result_user', jsonb_build_object(
      'id', v_user.id,
      'email', v_user.email,
      'full_name', v_user.full_name,
      'role', v_user.role
    ),
    'staff', jsonb_build_object(
      'id', v_staff.id,
      'staff_number', v_staff.staff_number,
      'full_name', v_staff.full_name,
      'employment_status', v_staff.employment_status,
      'registration_status', v_staff.registration_status
    )
  );
end;
$function$;

revoke all on function public.school_result_identity_resolve(uuid, uuid) from public, anon, authenticated;

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
  v_secret text;
  v_session_id uuid;
  v_origin text := lower(trim(coalesce(p_originating_app_code, '')));
  v_target text := lower(trim(coalesce(p_target_app_code, '')));
  v_now timestamptz := now();
begin
  if v_origin = '' or v_target = '' then
    return jsonb_build_object('ok', false, 'code', 'SESSION_APPLICATION_REQUIRED');
  end if;

  if not exists (
    select 1 from public.school_portal_catalog c
    where c.app_code = v_target and c.is_active = true and c.supports_login = true
  ) then
    return jsonb_build_object('ok', false, 'code', 'SESSION_TARGET_INVALID');
  end if;

  select c.* into v_client
  from public.attendance_admin_clients c
  where c.client_code = trim(p_client_code)
    and c.status = 'active'
  for update;

  if not found or p_client_secret is null
     or encode(digest(p_client_secret, 'sha256'), 'hex') <> v_client.secret_hash
     or v_client.central_person_id is null
     or (v_client.session_expires_at is not null and v_client.session_expires_at <= v_now) then
    return jsonb_build_object('ok', false, 'code', 'CENTRAL_SESSION_NOT_ACTIVE');
  end if;

  select p.* into v_person
  from public.school_people p
  where p.id = v_client.central_person_id;
  select s.* into v_staff
  from public.staff_attendance_profiles s
  where s.central_person_id = v_client.central_person_id;
  select i.* into v_account
  from public.school_identity_accounts i
  where i.person_id = v_client.central_person_id
  order by i.created_at
  limit 1;

  if v_person.id is null or v_person.person_status <> 'active'
     or v_staff.id is null
     or v_staff.registration_status <> 'active'
     or v_staff.employment_status <> 'active'
     or v_account.id is null or v_account.account_status <> 'active' then
    return jsonb_build_object('ok', false, 'code', 'CENTRAL_IDENTITY_NOT_ACTIVE');
  end if;

  select g.* into v_grant
  from public.school_access_grants g
  where g.person_id = v_client.central_person_id
    and g.app_code = v_target
    and g.grant_status = 'active'
    and (g.valid_from is null or g.valid_from <= v_now)
    and (g.valid_until is null or g.valid_until > v_now)
  limit 1;

  if not found then
    return jsonb_build_object('ok', false, 'code', 'RESULT_ACCESS_NOT_GRANTED');
  end if;

  v_secret := encode(gen_random_bytes(32), 'base64');
  insert into public.school_identity_sessions(
    person_id,
    identity_account_id,
    originating_app_code,
    target_app_code,
    secret_hash,
    expires_at,
    metadata
  ) values (
    v_client.central_person_id,
    v_account.id,
    v_origin,
    v_target,
    encode(digest(v_secret, 'sha256'), 'hex'),
    v_now + interval '8 hours',
    jsonb_build_object('source_client_id', v_client.id, 'source', 'central_session_exchange')
  ) returning id into v_session_id;

  insert into public.school_registry_audit(actor_type, actor_id, action, entity_type, entity_id, after_data, details)
  values (
    'staff_session', v_client.central_person_id::text, 'identity.session.issued', 'school_identity_sessions', v_session_id::text,
    jsonb_build_object('originating_app_code', v_origin, 'target_app_code', v_target),
    jsonb_build_object('source', 'school_identity_session_issue')
  );

  return jsonb_build_object(
    'ok', true,
    'code', 'IDENTITY_SESSION_ISSUED',
    'session_id', v_session_id,
    'session_secret', v_secret,
    'expires_at', v_now + interval '8 hours',
    'person_id', v_client.central_person_id,
    'identity_account_id', v_account.id,
    'target_app_code', v_target,
    'access_role', v_grant.access_role,
    'permissions', v_grant.permissions
  );
end;
$function$;

revoke all on function public.school_identity_session_issue(text, text, text, text) from public, anon, authenticated;
grant execute on function public.school_identity_session_issue(text, text, text, text) to service_role;

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
  v_grant public.school_access_grants%rowtype;
  v_target text;
  v_now timestamptz := now();
begin
  if p_session_id is null or coalesce(p_session_secret, '') = '' then
    return jsonb_build_object('ok', false, 'code', 'RESULT_SESSION_REQUIRED');
  end if;

  select s.* into v_session
  from public.school_identity_sessions s
  where s.id = p_session_id
    and s.revoked_at is null
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
  select s.* into v_staff from public.staff_attendance_profiles s where s.central_person_id = v_session.person_id;
  select i.* into v_account from public.school_identity_accounts i where i.id = v_session.identity_account_id;

  if v_person.id is null or v_person.person_status <> 'active'
     or v_staff.id is null
     or v_staff.registration_status <> 'active'
     or v_staff.employment_status <> 'active'
     or v_account.id is null or v_account.account_status <> 'active' then
    update public.school_identity_sessions
    set revoked_at = v_now, revocation_reason = 'CENTRAL_IDENTITY_NOT_ACTIVE', last_seen_at = v_now
    where id = v_session.id and revoked_at is null;
    return jsonb_build_object('ok', false, 'code', 'CENTRAL_IDENTITY_NOT_ACTIVE');
  end if;

  select g.* into v_grant
  from public.school_access_grants g
  where g.person_id = v_session.person_id
    and g.app_code = v_target
    and g.grant_status = 'active'
    and (g.valid_from is null or g.valid_from <= v_now)
    and (g.valid_until is null or g.valid_until > v_now)
  limit 1;

  if not found then
    update public.school_identity_sessions
    set revoked_at = v_now, revocation_reason = 'RESULT_ACCESS_NOT_GRANTED', last_seen_at = v_now
    where id = v_session.id and revoked_at is null;
    return jsonb_build_object('ok', false, 'code', 'RESULT_ACCESS_NOT_GRANTED');
  end if;

  update public.school_identity_sessions
  set last_seen_at = v_now
  where id = v_session.id;

  return jsonb_build_object(
    'ok', true,
    'code', 'IDENTITY_SESSION_ACTIVE',
    'session_id', v_session.id,
    'person_id', v_session.person_id,
    'identity_account_id', v_session.identity_account_id,
    'originating_app_code', v_session.originating_app_code,
    'target_app_code', v_session.target_app_code,
    'expires_at', v_session.expires_at,
    'access_role', v_grant.access_role,
    'permissions', v_grant.permissions
  );
end;
$function$;

revoke all on function public.school_identity_session_validate(uuid, text, text) from public, anon, authenticated;
grant execute on function public.school_identity_session_validate(uuid, text, text) to service_role;

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
begin
  select s.* into v_session
  from public.school_identity_sessions s
  where s.id = p_session_id
    and s.revoked_at is null
  for update;

  if not found or coalesce(p_session_secret, '') = ''
     or encode(digest(p_session_secret, 'sha256'), 'hex') <> v_session.secret_hash then
    return jsonb_build_object('ok', false, 'code', 'RESULT_SESSION_NOT_ACTIVE');
  end if;

  update public.school_identity_sessions
  set revoked_at = now(), revocation_reason = v_reason, last_seen_at = now()
  where id = v_session.id;

  insert into public.school_registry_audit(actor_type, actor_id, action, entity_type, entity_id, details)
  values (
    'staff_session', v_session.person_id::text, 'identity.session.revoked', 'school_identity_sessions', v_session.id::text,
    jsonb_build_object('reason', v_reason)
  );

  return jsonb_build_object('ok', true, 'code', 'IDENTITY_SESSION_REVOKED');
end;
$function$;

revoke all on function public.school_identity_session_revoke(uuid, text, text) from public;
grant execute on function public.school_identity_session_revoke(uuid, text, text) to anon, authenticated, service_role;

create or replace function public.school_identity_result_login(
  p_login text,
  p_password text
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_credential public.school_identity_credentials%rowtype;
  v_account public.school_identity_accounts%rowtype;
  v_grant public.school_access_grants%rowtype;
  v_identity jsonb;
  v_secret text;
  v_session_id uuid;
  v_now timestamptz := now();
begin
  if trim(coalesce(p_login, '')) = '' or coalesce(p_password, '') = '' then
    return jsonb_build_object('ok', false, 'code', 'LOGIN_AND_PASSWORD_REQUIRED');
  end if;

  select c.* into v_credential
  from public.school_identity_credentials c
  join public.school_identity_accounts i on i.id = c.identity_account_id
  left join public.staff_attendance_profiles s on s.central_person_id = c.person_id
  where lower(c.login_name) = lower(trim(p_login))
     or lower(coalesce(i.login_email, '')) = lower(trim(p_login))
     or lower(coalesce(s.email, '')) = lower(trim(p_login))
  order by case when lower(c.login_name) = lower(trim(p_login)) then 0 else 1 end
  limit 1
  for update of c;

  if not found then
    return jsonb_build_object('ok', false, 'code', 'INVALID_LOGIN');
  end if;

  select i.* into v_account from public.school_identity_accounts i where i.id = v_credential.identity_account_id;

  if v_credential.credential_status <> 'active'
     or v_account.account_status <> 'active'
     or not exists (
       select 1 from public.school_people p
       join public.staff_attendance_profiles s on s.central_person_id = p.id
       where p.id = v_credential.person_id
         and p.person_status = 'active'
         and s.registration_status = 'active'
         and s.employment_status = 'active'
     ) then
    return jsonb_build_object('ok', false, 'code', 'ACCOUNT_NOT_ACTIVE');
  end if;

  if v_credential.locked_until is not null and v_credential.locked_until > v_now then
    return jsonb_build_object('ok', false, 'code', 'ACCOUNT_TEMPORARILY_LOCKED', 'locked_until', v_credential.locked_until);
  end if;

  if v_credential.password_hash is null
     or crypt(p_password, v_credential.password_hash) <> v_credential.password_hash then
    update public.school_identity_credentials
    set failed_attempts = failed_attempts + 1,
        locked_until = case when failed_attempts + 1 >= 5 then v_now + interval '15 minutes' else locked_until end,
        updated_at = v_now
    where id = v_credential.id;
    return jsonb_build_object('ok', false, 'code', 'INVALID_LOGIN');
  end if;

  if v_credential.must_change_password then
    return jsonb_build_object('ok', false, 'code', 'PASSWORD_CHANGE_REQUIRED', 'must_change_password', true);
  end if;

  select g.* into v_grant
  from public.school_access_grants g
  where g.person_id = v_credential.person_id
    and g.app_code = 'results'
    and g.grant_status = 'active'
    and (g.valid_from is null or g.valid_from <= v_now)
    and (g.valid_until is null or g.valid_until > v_now)
  limit 1;

  if not found then
    return jsonb_build_object('ok', false, 'code', 'RESULT_ACCESS_NOT_GRANTED');
  end if;

  v_identity := public.school_result_identity_resolve(v_credential.person_id, v_credential.identity_account_id);
  if coalesce((v_identity ->> 'ok')::boolean, false) is not true then
    return v_identity;
  end if;

  v_secret := encode(gen_random_bytes(32), 'base64');
  insert into public.school_identity_sessions(
    person_id,
    identity_account_id,
    originating_app_code,
    target_app_code,
    secret_hash,
    expires_at,
    metadata
  ) values (
    v_credential.person_id,
    v_credential.identity_account_id,
    'results',
    'results',
    encode(digest(v_secret, 'sha256'), 'hex'),
    v_now + interval '8 hours',
    jsonb_build_object('source', 'school_identity_result_login')
  ) returning id into v_session_id;

  update public.school_identity_credentials
  set failed_attempts = 0, locked_until = null, last_login_at = v_now, updated_at = v_now
  where id = v_credential.id;
  update public.school_identity_accounts
  set last_login_at = v_now, updated_at = v_now
  where id = v_account.id;

  insert into public.school_registry_audit(actor_type, actor_id, action, entity_type, entity_id, after_data, detail…1218 tokens truncated…
      end if;
    end if;
  end if;

  if v_action in ('results.publish', 'scores.enter', 'traits.enter', 'remarks.enter') then
    if nullif(trim(coalesce(p_academic_session, '')), '') is null
       or nullif(trim(coalesce(p_term, '')), '') is null then
      return jsonb_build_object('ok', false, 'code', 'RESULT_ACADEMIC_CONTEXT_REQUIRED');
    end if;

    select s.value into v_current_session from public.settings s where s.key = 'session';
    select s.value into v_current_term from public.settings s where s.key = 'term';
    if v_current_session is null or v_current_term is null then
      return jsonb_build_object('ok', false, 'code', 'RESULT_ACADEMIC_CONTEXT_NOT_CONFIGURED');
    end if;
    if trim(p_academic_session) <> v_current_session then
      return jsonb_build_object('ok', false, 'code', 'RESULT_ACADEMIC_SESSION_NOT_ACTIVE');
    end if;
    if trim(p_term) <> v_current_term then
      return jsonb_build_object('ok', false, 'code', 'RESULT_TERM_NOT_ACTIVE');
    end if;
  end if;

  return jsonb_build_object(
    'ok', true,
    'code', 'RESULT_AUTHORIZED',
    'person_id', v_person_id,
    'identity_account_id', v_identity_account_id,
    'access_role', v_access_role,
    'permissions', v_permissions,
    'result_user', v_identity -> 'result_user',
    'class_scope', v_class_scope,
    'subject_scope', v_subject_scope,
    'expires_at', v_session -> 'expires_at'
  );
end;
$function$;

revoke all on function public.school_result_authorize(uuid, text, text, text, integer, text, text) from public, anon, authenticated;
grant execute on function public.school_result_authorize(uuid, text, text, text, integer, text, text) to service_role;

create or replace function public.school_result_api(
  p_session_id uuid,
  p_session_secret text,
  p_action text,
  p_payload jsonb default '{}'::jsonb
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_action text := lower(trim(coalesce(p_action, '')));
  v_auth_action text;
  v_auth jsonb;
  v_payload jsonb := coalesce(p_payload, '{}'::jsonb);
  v_class_key text := nullif(trim(coalesce(v_payload ->> 'class_key', '')), '');
  v_term text := nullif(trim(coalesce(v_payload ->> 'term', '')), '');
  v_academic_session text := nullif(trim(coalesce(v_payload ->> 'academic_session', '')), '');
  v_subject_index integer;
  v_user_id uuid;
  v_student_id uuid;
  v_person_id uuid;
  v_current_class text;
  v_new_role text;
  v_invite_code text;
  v_published boolean;
  v_student jsonb;
  v_before jsonb;
  v_after jsonb;
  v_value numeric;
  v_ca1 numeric;
  v_ca2 numeric;
  v_ca3 numeric;
  v_exam numeric;
begin
  begin
    v_subject_index := nullif(v_payload ->> 'subject_index', '')::integer;
  exception when others then
    return jsonb_build_object('ok', false, 'code', 'RESULT_SUBJECT_INDEX_INVALID');
  end;

  v_auth_action := case v_action
    when 'identity.context' then 'identity.context'
    when 'admin.users.read' then 'users.manage'
    when 'admin.invite.read' then 'users.manage'
    when 'admin.role.update' then 'users.manage'
    when 'admin.user.delete' then 'users.manage'
    when 'admin.invite.rotate' then 'users.manage'
    when 'results.publish' then 'results.publish'
    when 'scores.enter' then 'scores.enter'
    when 'traits.enter' then 'scores.enter'
    when 'remarks.enter' then 'remarks.enter'
    when 'students.upsert' then 'results.manage'
    when 'students.archive' then 'results.manage'
    when 'settings.read' then 'results.manage'
    when 'settings.update' then 'results.manage'
    when 'results.review' then 'results.review'
    when 'results.approve' then 'results.approve'
    when 'report_cards.generate' then 'report_cards.generate'
    when 'results.export' then 'results.export'
    else v_action
  end;

  v_auth := public.school_result_authorize(
    p_session_id,
    p_session_secret,
    v_auth_action,
    v_class_key,
    v_subject_index,
    v_academic_session,
    v_term
  );
  if coalesce((v_auth ->> 'ok')::boolean, false) is not true then
    return v_auth;
  end if;

  v_person_id := (v_auth ->> 'person_id')::uuid;

  if v_action = 'identity.context' then
    return v_auth;
  end if;

  if v_action = 'admin.users.read' then
    return jsonb_build_object(
      'ok', true,
      'code', 'RESULT_USERS_READ',
      'users', coalesce((select jsonb_agg(to_jsonb(x) order by x.created_at)
        from (select id, email, full_name, role, created_at from public.user_profiles) x), '[]'::jsonb)
    );
  end if;

  if v_action = 'admin.invite.read' then
    return jsonb_build_object(
      'ok', true,
      'code', 'RESULT_INVITE_READ',
      'invite', (select to_jsonb(x) from (select code, active, created_at from public.invite_codes where active = true order by created_at desc limit 1) x)
    );
  end if;

  if v_action = 'admin.role.update' then
    begin
      v_user_id := (v_payload ->> 'user_id')::uuid;
    exception when others then
      return jsonb_build_object('ok', false, 'code', 'RESULT_USER_ID_INVALID');
    end;
    v_new_role := lower(trim(coalesce(v_payload ->> 'role', '')));
    if v_user_id is null or v_new_role not in ('admin', 'teacher') then
      return jsonb_build_object('ok', false, 'code', 'RESULT_ROLE_UPDATE_INVALID');
    end if;
    select to_jsonb(u) into v_before from (select id, email, full_name, role from public.user_profiles where id = v_user_id) u;
    if v_before is null then
      return jsonb_build_object('ok', false, 'code', 'RESULT_USER_NOT_FOUND');
    end if;
    update public.user_profiles set role = v_new_role where id = v_user_id;
    select to_jsonb(u) into v_after from (select id, email, full_name, role from public.user_profiles where id = v_user_id) u;
    insert into public.school_registry_audit(actor_type, actor_id, action, entity_type, entity_id, before_data, after_data, details)
    values ('result_session', v_person_id::text, 'result.legacy_role.updated', 'user_profiles', v_user_id::text, v_before, v_after, jsonb_build_object('source', 'school_result_api'));
    return jsonb_build_object('ok', true, 'code', 'RESULT_ROLE_UPDATED', 'user', v_after);
  end if;

  if v_action = 'admin.user.delete' then
    return jsonb_build_object('ok', false, 'code', 'RESULT_USER_DELETION_REQUIRES_CENTRAL_DEPROVISIONING');
  end if;

  if v_action = 'admin.invite.rotate' then
    v_invite_code := upper(substr(encode(gen_random_bytes(6), 'hex'), 1, 8));
    update public.invite_codes set active = false where active = true;
    insert into public.invite_codes(code, active) values (v_invite_code, true);
    insert into public.school_registry_audit(actor_type, actor_id, action, entity_type, entity_id, after_data, details)
    values ('result_session', v_person_id::text, 'result.invite.rotated', 'invite_codes', null, jsonb_build_object('active', true), jsonb_build_object('source', 'school_result_api'));
    return jsonb_build_object('ok', true, 'code', 'RESULT_INVITE_ROTATED', 'invite_code', v_invite_code);
  end if;

  if v_action = 'results.publish' then
    v_published := lower(coalesce(v_payload ->> 'published', 'true')) in ('true', '1', 'yes');
    if v_class_key is null or v_term is null or v_subject_index is null then
      return jsonb_build_object('ok', false, 'code', 'RESULT_PUBLISH_PAYLOAD_INVALID');
    end if;
    if v_published then
      insert into public.published_subjects(class_key, term, subject_index)
      values (v_class_key, v_term, v_subject_index)
      on conflict (class_key, term, subject_index) do nothing;
    else
      delete from public.published_subjects
      where class_key = v_class_key and term = v_term and subject_index = v_subject_index;
    end if;
    insert into public.school_registry_audit(actor_type, actor_id, action, entity_type, entity_id, after_data, details)
    values ('result_session', v_person_id::text, case when v_published then 'result.subject.published' else 'result.subject.unpublished' end, 'published_subjects', v_class_key || ':' || v_term || ':' || v_subject_index::text, jsonb_build_object('published', v_published), jsonb_build_object('source', 'school_result_api'));
    return jsonb_build_object('ok', true, 'code', 'RESULT_PUBLISH_UPDATED', 'published', v_published, 'class_key', v_class_key, 'term', v_term, 'subject_index', v_subject_index);
  end if;

  if v_action = 'scores.enter' then
    begin
      v_student_id := (v_payload ->> 'student_id')::uuid;
    exception when others then
      return jsonb_build_object('ok', false, 'code', 'RESULT_STUDENT_ID_INVALID');
    end;
    if v_student_id is null or v_class_key is null or v_term is null or v_subject_index is null then
      return jsonb_build_object('ok', false, 'code', 'RESULT_SCORE_PAYLOAD_INVALID');
    end if;
    if not exists (select 1 from public.result_subject_catalog r where r.class_key = v_class_key and r.subject_index = v_subject_index) then
      return jsonb_build_object('ok', false, 'code', 'RESULT_SUBJECT_NOT_ASSIGNED');
    end if;
    select s.class_key into v_current_class from public.students s where s.id = v_student_id and coalesce(s.archived, false) = false;
    if v_current_class is null or v_current_class <> v_class_key then
      return jsonb_build_object('ok', false, 'code', 'RESULT_STUDENT_CLASS_MISMATCH');
    end if;
    begin
      v_ca1 := nullif(v_payload ->> 'ca1', '')::numeric;
      v_ca2 := nullif(v_payload ->> 'ca2', '')::numeric;
      v_ca3 := nullif(v_payload ->> 'ca3', '')::numeric;
      v_exam := nullif(v_payload ->> 'exam', '')::numeric;
    exception when others then
      return jsonb_build_object('ok', false, 'code', 'RESULT_SCORE_PAYLOAD_INVALID');
    end;
    if (v_ca1 is not null and (v_ca1 < 0 or v_ca1 > 100))
       or (v_ca2 is not null and (v_ca2 < 0 or v_ca2 > 100))
       or (v_ca3 is not null and (v_ca3 < 0 or v_ca3 > 100))
       or (v_exam is not null and (v_exam < 0 or v_exam > 100)) then
      return jsonb_build_object('ok', false, 'code', 'RESULT_SCORE_RANGE_INVALID');
    end if;
    insert into public.scores(student_id, class_key, subject_index, term, ca1, ca2, ca3, exam)
    values (v_student_id, v_class_key, v_subject_index, v_term, v_ca1, v_ca2, v_ca3, v_exam)
    on conflict (student_id, subject_index, term) do update
    set class_key = excluded.class_key,
        ca1 = excluded.ca1,
        ca2 = excluded.ca2,
        ca3 = excluded.ca3,
        exam = excluded.exam;
    insert into public.school_registry_audit(actor_type, actor_id, action, entity_type, entity_id, details)
    values ('result_session', v_person_id::text, 'result.score.upserted', 'scores', v_student_id::text, jsonb_build_object('class_key', v_class_key, 'term', v_term, 'subject_index', v_subject_index));
    return jsonb_build_object('ok', true, 'code', 'RESULT_SCORE_SAVED', 'student_id', v_student_id, 'class_key', v_class_key, 'term', v_term, 'subject_index', v_subject_index);
  end if;

  if v_action = 'traits.enter' then
    begin
      v_student_id := (v_payload ->> 'student_id')::uuid;
      v_value := nullif(v_payload ->> 'rating', '')::numeric;
    exception when others then
      return jsonb_build_object('ok', false, 'code', 'RESULT_TRAIT_PAYLOAD_INVALID');
    end;
    if v_student_id is null or v_class_key is null or v_term is null
       or nullif(trim(coalesce(v_payload ->> 'trait_type', '')), '') is null
       or nullif(trim(coalesce(v_payload ->> 'trait_name', '')), '') is null
       or v_value is null or v_value <> trunc(v_value) or v_value < 0 or v_value > 5 then
      return jsonb_build_object('ok', false, 'code', 'RESULT_TRAIT_PAYLOAD_INVALID');
    end if;
    if not exists (select 1 from public.students s where s.id = v_student_id and s.class_key = v_class_key and coalesce(s.archived, false) = false) then
      return jsonb_build_object('ok', false, 'code', 'RESULT_STUDENT_CLASS_MISMATCH');
    end if;
    insert into public.traits(student_id, class_key, trait_type, trait_name, rating, term)
    values (v_student_id, v_class_key, trim(v_payload ->> 'trait_type'), trim(v_payload ->> 'trait_name'), v_value::integer, v_term)
    on conflict (student_id, trait_type, trait_name, term) do update
    set class_key = excluded.class_key, rating = excluded.rating;
    insert into public.school_registry_audit(actor_type, actor_id, action, entity_type, entity_id, details)
    values ('result_session', v_person_id::text, 'result.trait.upserted', 'traits', v_student_id::text, jsonb_build_object('class_key', v_class_key, 'term', v_term, 'trait_type', trim(v_payload ->> 'trait_type'), 'trait_name', trim(v_payload ->> 'trait_name')));
    return jsonb_build_object('ok', true, 'code', 'RESULT_TRAIT_SAVED', 'student_id', v_student_id, 'term', v_term);
  end if;

  if v_action = 'remarks.enter' then
    begin
      v_student_id := (v_payload ->> 'student_id')::uuid;
    exception when others then
      return jsonb_build_object('ok', false, 'code', 'RESULT_REMARK_PAYLOAD_INVALID');
    end;
    if v_student_id is null or v_class_key is null or v_term is null then
      return jsonb_build_object('ok', false, 'code', 'RESULT_REMARK_PAYLOAD_INVALID');
    end if;
    if not exists (select 1 from public.students s where s.id = v_student_id and s.class_key = v_class_key and coalesce(s.archived, false) = false) then
      return jsonb_build_object('ok', false, 'code', 'RESULT_STUDENT_CLASS_MISMATCH');
    end if;
    insert into public.remarks(student_id, class_key, academic, form_master, principal, days_opened, days_present, term)
    values (v_student_id, v_class_key, v_payload ->> 'academic', v_payload ->> 'form_master', v_payload ->> 'principal', nullif(v_payload ->> 'days_opened', '')::integer, nullif(v_payload ->> 'days_present', '')::integer, v_term)
    on conflict (student_id, term) do update
    set class_key = excluded.class_key,
        academic = excluded.academic,
        form_master = excluded.form_master,
        principal = excluded.principal,
        days_opened = excluded.days_opened,
        days_present = excluded.days_present;
    insert into public.school_registry_audit(actor_type, actor_id, action, entity_type, entity_id, details)
    values ('result_session', v_person_id::text, 'result.remarks.upserted', 'remarks', v_student_id::text, jsonb_build_object('class_key', v_class_key, 'term', v_term));
    return jsonb_build_object('ok', true, 'code', 'RESULT_REMARKS_SAVED', 'student_id', v_student_id, 'term', v_term);
  end if;

  if v_action = 'students.upsert' then
    begin
      if nullif(v_payload ->> 'id', '') is not null then v_student_id := (v_payload ->> 'id')::uuid; end if;
    exception when others then
      return jsonb_build_object('ok', false, 'code', 'RESULT_STUDENT_ID_INVALID');
    end;
    if v_class_key is null or nullif(trim(coalesce(v_payload ->> 'name', '')), '') is null then
      return jsonb_build_object('ok', false, 'code', 'RESULT_STUDENT_PAYLOAD_INVALID');
    end if;
    if v_student_id is null then
      insert into public.students(class_key, name, gender, admno, house, age, photo, archived, lifecycle_status, admission_source, student_number_status)
      values (v_class_key, trim(v_payload ->> 'name'), v_payload ->> 'gender', v_payload ->> 'admno', v_payload ->> 'house', v_payload ->> 'age', v_payload ->> 'photo', false, coalesce(nullif(v_payload ->> 'lifecycle_status', ''), 'active'), v_payload ->> 'admission_source', coalesce(nullif(v_payload ->> 'student_number_status', ''), 'active'))
      returning to_jsonb(students.*) into v_student;
    else
      if not exists (select 1 from public.students where id = v_student_id) then
        return jsonb_build_object('ok', false, 'code', 'RESULT_STUDENT_NOT_FOUND');
      end if;
      update public.students set
        class_key = v_class_key,
        name = trim(v_payload ->> 'name'),
        gender = v_payload ->> 'gender',
        admno = v_payload ->> 'admno',
        house = v_payload ->> 'house',
        age = v_payload ->> 'age',
        photo = v_payload ->> 'photo',
        lifecycle_status = coalesce(nullif(v_payload ->> 'lifecycle_status', ''), lifecycle_status),
        admission_source = v_payload ->> 'admission_source',
        updated_at = now()
      where id = v_student_id
      returning to_jsonb(students.*) into v_student;
    end if;
    insert into public.school_registry_audit(actor_type, actor_id, action, entity_type, entity_id, after_data, details)
    values ('result_session', v_person_id::text, case when v_payload ->> 'id' is null then 'result.student.created' else 'result.student.updated' end, 'students', (v_student ->> 'id'), v_student - 'photo', jsonb_build_object('source', 'school_result_api'));
    return jsonb_build_object('ok', true, 'code', 'RESULT_STUDENT_SAVED', 'student', v_student);
  end if;

  if v_action = 'students.archive' then
    begin
      v_student_id := (v_payload ->> 'student_id')::uuid;
    exception when others then
      return jsonb_build_object('ok', false, 'code', 'RESULT_STUDENT_ID_INVALID');
    end;
    update public.students
    set archived = true, archived_at = now(), archived_reason = left(coalesce(v_payload ->> 'reason', 'Archived through protected Result administration'), 240), lifecycle_status = 'archived', updated_at = now()
    where id = v_student_id;
    if not found then
      return jsonb_build_object('ok', false, 'code', 'RESULT_STUDENT_NOT_FOUND');
    end if;
    insert into public.school_registry_audit(actor_type, actor_id, action, entity_type, entity_id, details)
    values ('result_session', v_person_id::text, 'result.student.archived', 'students', v_student_id::text, jsonb_build_object('source', 'school_result_api'));
    return jsonb_build_object('ok', true, 'code', 'RESULT_STUDENT_ARCHIVED', 'student_id', v_student_id);
  end if;

  if v_action = 'settings.read' then
    return jsonb_build_object(
      'ok', true,
      'code', 'RESULT_SETTINGS_READ',
      'settings', coalesce((select jsonb_object_agg(key, value) from public.settings where key in ('session', 'term', 'school_name', 'school_addr', 'school_phone', 'school_email', 'card_theme', 'next_term_resumption')), '{}'::jsonb)
    );
  end if;

  if v_action = 'settings.update' then
    if trim(coalesce(v_payload ->> 'key', '')) not in ('session', 'term', 'school_name', 'school_addr', 'school_phone', 'school_email', 'card_theme', 'next_term_resumption') then
      return jsonb_build_object('ok', false, 'code', 'RESULT_SETTING_NOT_ALLOWED');
    end if;
    insert into public.settings(key, value) values (trim(v_payload ->> 'key'), coalesce(v_payload ->> 'value', ''))
    on conflict (key) do update set value = excluded.value;
    insert into public.school_registry_audit(actor_type, actor_id, action, entity_type, entity_id, details)
    values ('result_session', v_person_id::text, 'result.setting.updated', 'settings', trim(v_payload ->> 'key'), jsonb_build_object('source', 'school_result_api'));
    return jsonb_build_object('ok', true, 'code', 'RESULT_SETTING_UPDATED', 'key', trim(v_payload ->> 'key'));
  end if;

  if v_action in ('results.review', 'results.approve', 'report_cards.generate', 'results.export') then
    return v_auth || jsonb_build_object('action', v_action);
  end if;

  return jsonb_build_object('ok', false, 'code', 'RESULT_ACTION_NOT_IMPLEMENTED');
end;
$function$;

revoke all on function public.school_result_api(uuid, text, text, jsonb) from public;
grant execute on function public.school_result_api(uuid, text, text, jsonb) to anon, authenticated, service_role;

-- Remove direct anonymous writes only for operations already represented by
-- the protected API. Reads remain temporarily available for the incremental
-- browser migration and are addressed by the later RLS/data-read phase.
revoke insert, update, delete on table public.user_profiles from anon, authenticated;
revoke insert, update, delete on table public.invite_codes from anon, authenticated;
revoke insert, update, delete on table public.published_subjects from anon, authenticated;
