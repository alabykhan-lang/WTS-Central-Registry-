-- Central Registry staff activation, password recovery and profile completion.
--
-- This migration never creates a person, staff record, assignment or grant.
-- Activation and recovery operate on an existing identity account only. Raw
-- bearer tokens are returned only to the server-side mail adapter; only a
-- SHA-256 token digest is stored in the database.

create table if not exists public.school_identity_recovery_tokens (
  id uuid primary key default gen_random_uuid(),
  identity_account_id uuid not null references public.school_identity_accounts(id),
  person_id uuid not null references public.school_people(id),
  purpose text not null check (purpose in ('activation', 'password_reset')),
  token_hash text not null unique,
  requested_login text,
  destination_email text not null,
  token_status text not null default 'issued'
    check (token_status in ('issued', 'delivered', 'used', 'expired', 'failed', 'revoked')),
  expires_at timestamptz not null,
  delivered_at timestamptz,
  used_at timestamptz,
  invalidated_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  metadata jsonb not null default '{}'::jsonb,
  check (length(destination_email) between 3 and 254),
  check (length(token_hash) = 64)
);

create index if not exists school_identity_recovery_lookup_idx
  on public.school_identity_recovery_tokens (person_id, purpose, token_status, expires_at desc);
create index if not exists school_identity_recovery_created_idx
  on public.school_identity_recovery_tokens (created_at desc);

alter table public.school_identity_recovery_tokens enable row level security;
revoke all on table public.school_identity_recovery_tokens from public, anon, authenticated;

create or replace function public.school_identity_recovery_issue_service(
  p_login text,
  p_purpose text,
  p_reason text default 'self_service_recovery'
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_login text := trim(coalesce(p_login, ''));
  v_purpose text := lower(trim(coalesce(p_purpose, '')));
  v_staff public.staff_attendance_profiles%rowtype;
  v_account public.school_identity_accounts%rowtype;
  v_token_id uuid;
  v_request_id uuid := gen_random_uuid();
  v_raw_token text;
  v_destination text;
  v_recent timestamptz;
begin
  if v_purpose not in ('activation', 'password_reset') then
    return jsonb_build_object('ok', false, 'code', 'RECOVERY_PURPOSE_INVALID');
  end if;

  -- Password recovery accepts a registered email only. Activation accepts
  -- either the immutable staff number or a registered email.
  if v_purpose = 'password_reset'
     and (v_login !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$') then
    return jsonb_build_object('ok', true, 'code', 'RECOVERY_REQUEST_ACCEPTED', 'deliverable', false);
  end if;

  select i.* into v_account
  from public.school_identity_accounts i
  join public.staff_attendance_profiles s on s.central_person_id = i.person_id
  join public.school_people p on p.id = i.person_id
  where i.account_status = 'active'
    and p.person_status = 'active'
    and s.registration_status = 'active'
    and s.employment_status = 'active'
    and (
      lower(i.login_email) = lower(v_login)
      or lower(coalesce(s.email, '')) = lower(v_login)
      or (v_purpose = 'activation' and lower(coalesce(s.staff_number, '')) = lower(v_login))
    )
  order by case when lower(coalesce(s.staff_number, '')) = lower(v_login) then 0 else 1 end
  limit 1;

  if not found then
    return jsonb_build_object('ok', true, 'code', 'RECOVERY_REQUEST_ACCEPTED', 'deliverable', false);
  end if;

  select * into v_staff
  from public.staff_attendance_profiles
  where central_person_id = v_account.person_id
  limit 1;

  v_destination := lower(nullif(trim(coalesce(v_account.login_email, '')), ''));
  if v_destination is null then v_destination := lower(nullif(trim(coalesce(v_staff.email, '')), '')); end if;
  if v_destination is null or v_destination !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$' then
    return jsonb_build_object('ok', true, 'code', 'RECOVERY_REQUEST_ACCEPTED', 'deliverable', false);
  end if;

  select max(created_at) into v_recent
  from public.school_identity_recovery_tokens
  where person_id = v_account.person_id
    and purpose = v_purpose
    and token_status in ('issued', 'delivered')
    and created_at > now() - interval '60 seconds';
  if v_recent is not null then
    return jsonb_build_object('ok', true, 'code', 'RECOVERY_REQUEST_ACCEPTED', 'deliverable', false, 'rate_limited', true);
  end if;

  update public.school_identity_recovery_tokens
  set token_status = 'revoked', invalidated_at = now(), updated_at = now()
  where person_id = v_account.person_id
    and purpose = v_purpose
    and token_status in ('issued', 'delivered')
    and expires_at > now();

  v_raw_token := encode(gen_random_bytes(32), 'hex');
  insert into public.school_identity_recovery_tokens(
    identity_account_id, person_id, purpose, token_hash, requested_login,
    destination_email, token_status, expires_at, metadata
  ) values (
    v_account.id, v_account.person_id, v_purpose,
    encode(digest(v_raw_token, 'sha256'), 'hex'),
    nullif(v_login, ''), v_destination, 'issued', now() + interval '30 minutes',
    jsonb_build_object('request_id', v_request_id, 'reason', left(trim(coalesce(p_reason, '')), 500))
  ) returning id into v_token_id;

  insert into public.school_registry_audit(
    actor_type, actor_id, action, entity_type, entity_id, request_id,
    before_data, after_data, details
  ) values (
    'self_service', 'recovery',
    case when v_purpose = 'activation' then 'identity.activation_requested' else 'identity.password_reset_requested' end,
    'identity_account', v_account.id::text, v_request_id,
    null, jsonb_build_object('purpose', v_purpose, 'expires_at', now() + interval '30 minutes'),
    jsonb_build_object('person_id', v_account.person_id, 'requested_login', v_login, 'destination_email', v_destination)
  );

  return jsonb_build_object(
    'ok', true, 'code', 'RECOVERY_TOKEN_ISSUED', 'deliverable', true,
    'token_id', v_token_id, 'token', v_raw_token, 'purpose', v_purpose,
    'destination_email', v_destination, 'staff_number', v_staff.staff_number,
    'expires_at', now() + interval '30 minutes',
    'request_id', v_request_id
  );
exception
  when others then
    return jsonb_build_object('ok', false, 'code', 'RECOVERY_ISSUE_FAILED');
end;
$function$;

revoke all on function public.school_identity_recovery_issue_service(text, text, text)
  from public, anon, authenticated;
grant execute on function public.school_identity_recovery_issue_service(text, text, text)
  to service_role;

create or replace function public.school_identity_recovery_mark_delivery(
  p_token_id uuid,
  p_delivered boolean,
  p_error text default null
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_token public.school_identity_recovery_tokens%rowtype;
begin
  select * into v_token
  from public.school_identity_recovery_tokens
  where id = p_token_id
  for update;
  if not found then return jsonb_build_object('ok', false, 'code', 'RECOVERY_TOKEN_NOT_FOUND'); end if;
  update public.school_identity_recovery_tokens
  set token_status = case when p_delivered then 'delivered' else 'failed' end,
      delivered_at = case when p_delivered then now() else delivered_at end,
      updated_at = now(),
      metadata = metadata || jsonb_build_object('delivery_error', case when p_delivered then null else left(coalesce(p_error, 'email delivery failed'), 500) end)
  where id = p_token_id and token_status = 'issued';
  return jsonb_build_object('ok', true, 'code', case when p_delivered then 'RECOVERY_EMAIL_MARKED_DELIVERED' else 'RECOVERY_EMAIL_MARKED_FAILED' end);
exception
  when others then return jsonb_build_object('ok', false, 'code', 'RECOVERY_DELIVERY_UPDATE_FAILED');
end;
$function$;

revoke all on function public.school_identity_recovery_mark_delivery(uuid, boolean, text)
  from public, anon, authenticated;
grant execute on function public.school_identity_recovery_mark_delivery(uuid, boolean, text)
  to service_role;

create or replace function public.school_identity_recovery_consume(
  p_token text,
  p_new_password text
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_token public.school_identity_recovery_tokens%rowtype;
  v_account public.school_identity_accounts%rowtype;
  v_staff public.staff_attendance_profiles%rowtype;
  v_credential public.school_identity_credentials%rowtype;
  v_credential_id uuid;
  v_login_name text;
  v_before jsonb;
begin
  if length(coalesce(p_token, '')) < 32 or length(coalesce(p_token, '')) > 256 then
    return jsonb_build_object('ok', false, 'code', 'RECOVERY_TOKEN_INVALID');
  end if;
  if length(coalesce(p_new_password, '')) < 10
     or p_new_password !~ '[A-Z]'
     or p_new_password !~ '[a-z]'
     or p_new_password !~ '[0-9]' then
    return jsonb_build_object('ok', false, 'code', 'PASSWORD_REQUIREMENTS_NOT_MET');
  end if;

  select * into v_token
  from public.school_identity_recovery_tokens
  where token_hash = encode(digest(p_token, 'sha256'), 'hex')
  for update;
  if not found then return jsonb_build_object('ok', false, 'code', 'RECOVERY_TOKEN_INVALID'); end if;
  if v_token.token_status not in ('issued', 'delivered') then
    return jsonb_build_object('ok', false, 'code', 'RECOVERY_TOKEN_ALREADY_USED');
  end if;
  if v_token.expires_at <= now() then
    update public.school_identity_recovery_tokens set token_status = 'expired', updated_at = now() where id = v_token.id;
    return jsonb_build_object('ok', false, 'code', 'RECOVERY_TOKEN_EXPIRED');
  end if;

  select * into v_account from public.school_identity_accounts where id = v_token.identity_account_id for update;
  if not found then return jsonb_build_object('ok', false, 'code', 'IDENTITY_ACCOUNT_NOT_FOUND'); end if;
  select * into v_staff from public.staff_attendance_profiles where central_person_id = v_token.person_id limit 1;
  if not found or v_account.account_status <> 'active' or v_staff.registration_status <> 'active' or v_staff.employment_status <> 'active' then
    return jsonb_build_object('ok', false, 'code', 'ACCOUNT_NOT_ACTIVE');
  end if;

  select * into v_credential
  from public.school_identity_credentials
  where identity_account_id = v_account.id
  for update;
  if found then
    v_before := jsonb_build_object(
      'credential_status', v_credential.credential_status,
      'must_change_password', v_credential.must_change_password,
      'failed_attempts', v_credential.failed_attempts,
      'locked_until', v_credential.locked_until
    );
  else
    v_before := '{}'::jsonb;
  end if;
  v_login_name := coalesce(v_credential.login_name, v_staff.staff_number, v_account.login_email);

  insert into public.school_identity_credentials(
    identity_account_id, person_id, login_name, password_hash, credential_status,
    must_change_password, failed_attempts, locked_until, password_changed_at, updated_at
  ) values (
    v_account.id, v_account.person_id, v_login_name, crypt(p_new_password, gen_salt('bf', 12)), 'active',
    false, 0, null, now(), now()
  )
  on conflict (identity_account_id) do update set
    person_id = excluded.person_id,
    login_name = excluded.login_name,
    password_hash = excluded.password_hash,
    credential_status = 'active',
    must_change_password = false,
    failed_attempts = 0,
    locked_until = null,
    password_changed_at = now(),
    updated_at = now()
  returning id into v_credential_id;

  update public.school_identity_accounts
  set metadata = metadata || jsonb_build_object(
      case when v_token.purpose = 'activation' then 'last_activation_completed_at' else 'last_password_reset_completed_at' end,
      now()
    ), updated_at = now()
  where id = v_account.id;

  if v_token.purpose = 'activation' then
    update public.staff_attendance_profiles
    set activated_at = coalesce(activated_at, now()), updated_at = now()
    where id = v_staff.id;
  end if;

  update public.attendance_admin_clients
  set status = 'suspended', session_expires_at = null,
      secret_hash = encode(digest(encode(gen_random_bytes(32), 'hex'), 'sha256'), 'hex'), updated_at = now()
  where central_person_id = v_account.person_id;

  update public.school_identity_recovery_tokens
  set token_status = 'used', used_at = now(), updated_at = now()
  where id = v_token.id;

  insert into public.school_registry_audit(
    actor_type, actor_id, action, entity_type, entity_id, request_id,
    before_data, after_data, details
  ) values (
    'self_service', 'recovery',
    case when v_token.purpose = 'activation' then 'identity.activation_completed' else 'identity.password_reset_completed' end,
    'identity_credential', v_credential_id::text, gen_random_uuid(),
    v_before,
    jsonb_build_object('credential_status', 'active', 'must_change_password', false, 'sessions_revoked', true),
    jsonb_build_object('person_id', v_account.person_id, 'purpose', v_token.purpose, 'token_id', v_token.id)
  );

  return jsonb_build_object(
    'ok', true, 'code', case when v_token.purpose = 'activation' then 'STAFF_ACCOUNT_ACTIVATED' else 'PASSWORD_RESET_COMPLETED' end,
    'purpose', v_token.purpose, 'staff_number', v_staff.staff_number
  );
exception
  when others then return jsonb_build_object('ok', false, 'code', 'RECOVERY_COMPLETION_FAILED');
end;
$function$;

revoke all on function public.school_identity_recovery_consume(text, text)
  from public, authenticated;
grant execute on function public.school_identity_recovery_consume(text, text) to anon;

-- Return the registration id for safe notification/audit correlation and
-- enqueue a non-secret registration event. No identity or credential is made.
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
  v_fingerprint text;
  v_registration_id uuid;
begin
  if v_name is null or length(v_name) < 2 or length(v_name) > 160 then return jsonb_build_object('ok', false, 'code', 'FULL_NAME_REQUIRED'); end if;
  if v_email is null or length(v_email) > 254 or v_email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$' then return jsonb_build_object('ok', false, 'code', 'VALID_EMAIL_REQUIRED'); end if;
  if v_phone is null or length(v_phone) < 3 or length(v_phone) > 40 then return jsonb_build_object('ok', false, 'code', 'PHONE_REQUIRED'); end if;
  if v_whatsapp is not null and length(v_whatsapp) > 40 then return jsonb_build_object('ok', false, 'code', 'WHATSAPP_NUMBER_INVALID'); end if;
  if v_photo is not null and (length(v_photo) > 260000 or v_photo !~ '^data:image/[a-zA-Z0-9.+-]+;base64,') then return jsonb_build_object('ok', false, 'code', 'PHOTOGRAPH_INVALID'); end if;
  v_fingerprint := md5(lower(v_name) || '|' || coalesce(v_email, '') || '|' || coalesce(v_phone, '') || '|' || coalesce(v_whatsapp, ''));

  if exists (
    select 1 from public.staff_attendance_profiles s
    where s.registration_status in ('active', 'pending', 'suspended')
      and (lower(coalesce(s.email, '')) = v_email or s.phone = v_phone or s.whatsapp_number = v_whatsapp)
  ) or exists (
    select 1 from public.school_staff_registrations r
    where r.registration_status in ('pending', 'under_review', 'approved')
      and (lower(coalesce(r.email, '')) = v_email or r.phone = v_phone or r.whatsapp_number = v_whatsapp)
  ) then
    return jsonb_build_object('ok', true, 'code', 'STAFF_REGISTRATION_ALREADY_ON_FILE');
  end if;

  insert into public.school_staff_registrations(
    full_name, email, phone, whatsapp_number, address, emergency_contact,
    photo_data, registration_status, request_fingerprint
  ) values (
    v_name, v_email, v_phone, v_whatsapp, v_address, v_emergency,
    v_photo, 'pending', v_fingerprint
  ) returning id into v_registration_id;

  insert into public.school_registry_outbox(
    event_type, aggregate_type, aggregate_id, payload, target_apps,
    event_status, idempotency_key
  ) values (
    'staff.registration_received', 'school_staff_registration', v_registration_id,
    jsonb_build_object('registration_id', v_registration_id, 'email', v_email, 'full_name', v_name),
    array['central_registry']::text[], 'pending', 'staff.registration_received:' || v_registration_id::text
  ) on conflict (idempotency_key) do nothing;

  return jsonb_build_object('ok', true, 'code', 'STAFF_REGISTRATION_SUBMITTED', 'registration_id', v_registration_id);
exception
  when others then return jsonb_build_object('ok', false, 'code', 'STAFF_REGISTRATION_FAILED');
end;
$function$;

revoke all on function public.school_staff_public_registration_submit(jsonb) from public, authenticated;
grant execute on function public.school_staff_public_registration_submit(jsonb) to anon;

-- Profile completion is derived from the five personal fields and never
-- treats official employment data as user-editable.
create or replace function public.school_staff_self_service_session_api(
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
  v_session jsonb;
  v_person_id uuid;
  v_staff_id uuid;
  v_permissions text[];
  v_staff public.staff_attendance_profiles%rowtype;
  v_completion integer;
begin
  v_session := public.school_identity_session_validate(p_session_id, p_session_secret, 'staff_self_service');
  if coalesce((v_session ->> 'ok')::boolean, false) is not true then return v_session; end if;
  begin v_person_id := (v_session ->> 'person_id')::uuid; exception when others then return jsonb_build_object('ok', false, 'code', 'CENTRAL_IDENTITY_NOT_ACTIVE'); end;

  select * into v_staff
  from public.staff_attendance_profiles
  where central_person_id = v_person_id and registration_status = 'active' and employment_status = 'active'
  limit 1;
  if not found then return jsonb_build_object('ok', false, 'code', 'STAFF_NOT_ACTIVE'); end if;
  v_staff_id := v_staff.id;
  select coalesce(array(select jsonb_array_elements_text(v_session -> 'permissions')), array[]::text[]) into v_permissions;

  if p_action = 'profile' then
    v_completion :=
      (case when nullif(trim(coalesce(v_staff.photo, '')), '') is not null then 20 else 0 end)
      + (case when nullif(trim(coalesce(v_staff.phone, '')), '') is not null then 20 else 0 end)
      + (case when nullif(trim(coalesce(v_staff.whatsapp_number, '')), '') is not null then 20 else 0 end)
      + (case when nullif(trim(coalesce(v_staff.address, '')), '') is not null then 20 else 0 end)
      + (case when nullif(trim(coalesce(v_staff.metadata ->> 'emergency_contact', '')), '') is not null then 20 else 0 end);
    return jsonb_build_object(
      'ok', true,
      'profile', jsonb_build_object(
        'staff_id', v_staff.id, 'person_id', v_staff.central_person_id, 'staff_number', v_staff.staff_number,
        'full_name', v_staff.full_name, 'email', v_staff.email, 'official_email', v_staff.email,
        'phone', v_staff.phone, 'whatsapp_number', v_staff.whatsapp_number, 'address', v_staff.address,
        'emergency_contact', v_staff.metadata ->> 'emergency_contact', 'staff_category', v_staff.staff_category,
        'department', v_staff.department, 'designation', v_staff.designation, 'school_section', v_staff.school_section,
        'photo', v_staff.photo, 'employment_status', v_staff.employment_status,
        'attendance_required', v_staff.attendance_required, 'profile_completion', v_completion,
        'profile_missing', array_remove(array[
          case when nullif(trim(coalesce(v_staff.photo, '')), '') is null then 'Photograph' end,
          case when nullif(trim(coalesce(v_staff.phone, '')), '') is null then 'Phone' end,
          case when nullif(trim(coalesce(v_staff.whatsapp_number, '')), '') is null then 'WhatsApp number' end,
          case when nullif(trim(coalesce(v_staff.address, '')), '') is null then 'Address' end,
          case when nullif(trim(coalesce(v_staff.metadata ->> 'emergency_contact', '')), '') is null then 'Emergency contact' end
        ], null)
      ),
      'portals', coalesce((select jsonb_agg(jsonb_build_object(
        'app_code', p.app_code, 'app_name', p.app_name, 'description', p.description,
        'grant_status', coalesce(g.grant_status, 'not_granted'), 'access_role', g.access_role
      ) order by p.app_name)
      from public.school_portal_catalog p
      left join public.school_access_grants g on g.person_id = v_person_id and g.app_code = p.app_code
      where p.is_active = true), '[]'::jsonb)
    );
  end if;

  if p_action = 'updateProfile' then
    if not (v_permissions @> array['profile.update']::text[]) then return jsonb_build_object('ok', false, 'code', 'SELF_SERVICE_UPDATE_DENIED'); end if;
    if p_payload ? 'photo' and p_payload ->> 'photo' is not null
       and (length(p_payload ->> 'photo') > 260000 or (p_payload ->> 'photo') !~ '^data:image/[a-zA-Z0-9.+-]+;base64,') then
      return jsonb_build_object('ok', false, 'code', 'PHOTOGRAPH_INVALID');
    end if;
    update public.staff_attendance_profiles
    set phone = case when p_payload ? 'phone' then nullif(trim(p_payload ->> 'phone'), '') else phone end,
        whatsapp_number = case when p_payload ? 'whatsappNumber' then nullif(trim(p_payload ->> 'whatsappNumber'), '') else whatsapp_number end,
        address = case when p_payload ? 'address' then nullif(trim(p_payload ->> 'address'), '') else address end,
        photo = case when p_payload ? 'photo' then nullif(trim(p_payload ->> 'photo'), '') else photo end,
        metadata = case when p_payload ? 'emergencyContact'
          then jsonb_set(coalesce(metadata, '{}'::jsonb), '{emergency_contact}', coalesce(to_jsonb(nullif(trim(p_payload ->> 'emergencyContact'), '')), 'null'::jsonb), true)
          else metadata end,
        updated_at = now()
    where id = v_staff_id;
    update public.school_people
    set primary_phone = case when p_payload ? 'phone' then nullif(trim(p_payload ->> 'phone'), '') else primary_phone end,
        photo_path = case when p_payload ? 'photo' then nullif(trim(p_payload ->> 'photo'), '') else photo_path end,
        updated_at = now()
    where id = v_person_id;
    return jsonb_build_object('ok', true, 'code', 'STAFF_PROFILE_UPDATED', 'staff_id', v_staff_id);
  end if;
  return jsonb_build_object('ok', false, 'code', 'UNKNOWN_ACTION');
exception
  when others then return jsonb_build_object('ok', false, 'code', 'STAFF_SELF_SERVICE_FAILED');
end;
$function$;

revoke all on function public.school_staff_self_service_session_api(uuid, text, text, jsonb) from public, authenticated;
grant execute on function public.school_staff_self_service_session_api(uuid, text, text, jsonb) to anon;
