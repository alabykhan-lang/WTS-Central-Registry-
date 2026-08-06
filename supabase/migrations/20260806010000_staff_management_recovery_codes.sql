-- No-email activation and password recovery for existing WTS staff.
--
-- Management receives the raw code once so it can share it directly with the
-- staff member. Only a SHA-256 digest is stored. This migration does not
-- create identities, credentials, staff, grants, assignments or sample data.

create table if not exists public.school_identity_management_codes (
  id uuid primary key default gen_random_uuid(),
  identity_account_id uuid not null references public.school_identity_accounts(id) on delete restrict,
  person_id uuid not null references public.school_people(id) on delete restrict,
  purpose text not null check (purpose in ('activation', 'password_reset')),
  code_hash text not null,
  attempt_count integer not null default 0 check (attempt_count >= 0 and attempt_count <= 5),
  issued_by_person_id uuid not null references public.school_people(id) on delete restrict,
  issued_at timestamptz not null default now(),
  expires_at timestamptz not null,
  used_at timestamptz,
  revoked_at timestamptz,
  reason text not null,
  request_id uuid not null default gen_random_uuid(),
  metadata jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  constraint school_identity_management_codes_expiry_check check (expires_at > issued_at)
);

create unique index if not exists school_identity_management_codes_hash_uidx
  on public.school_identity_management_codes (code_hash);
create index if not exists school_identity_management_codes_target_idx
  on public.school_identity_management_codes (identity_account_id, purpose, issued_at desc);

alter table public.school_identity_management_codes enable row level security;
revoke all on table public.school_identity_management_codes
  from public, anon, authenticated, service_role;

-- Only an active Central Registry management session may issue a code. The
-- raw code is returned to that authenticated management browser once and is
-- never stored in the database, audit data or server logs.
create or replace function public.school_identity_admin_write_session_api(
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
  v_actor_person_id uuid;
  v_staff public.staff_attendance_profiles%rowtype;
  v_account public.school_identity_accounts%rowtype;
  v_code_id uuid;
  v_raw_code text;
  v_purpose text := lower(trim(coalesce(p_payload ->> 'purpose', '')));
  v_reason text := nullif(trim(coalesce(p_payload ->> 'reason', '')), '');
  v_staff_id uuid;
  v_request_id uuid := gen_random_uuid();
  v_expires_at timestamptz := now() + interval '30 minutes';
begin
  v_session := public.school_identity_session_validate(
    p_session_id,
    p_session_secret,
    'central_registry'
  );
  if coalesce((v_session ->> 'ok')::boolean, false) is not true then
    return v_session;
  end if;

  v_actor_person_id := wts_internal.central_management_actor(v_session);
  if v_actor_person_id is null then
    return jsonb_build_object('ok', false, 'code', 'MANAGEMENT_ACCESS_DENIED');
  end if;

  if lower(trim(coalesce(p_action, ''))) <> 'issuerecoverycode' then
    return jsonb_build_object('ok', false, 'code', 'UNKNOWN_ACTION');
  end if;
  if v_purpose not in ('activation', 'password_reset') then
    return jsonb_build_object('ok', false, 'code', 'RECOVERY_PURPOSE_INVALID');
  end if;
  if v_reason is null or length(v_reason) < 8 then
    return jsonb_build_object('ok', false, 'code', 'RECOVERY_CODE_REASON_REQUIRED');
  end if;
  if length(v_reason) > 500 then
    v_reason := left(v_reason, 500);
  end if;

  begin
    v_staff_id := (p_payload ->> 'staffId')::uuid;
  exception when others then
    return jsonb_build_object('ok', false, 'code', 'INVALID_STAFF_ID');
  end;
  if v_staff_id is null then
    return jsonb_build_object('ok', false, 'code', 'INVALID_STAFF_ID');
  end if;

  select s.* into v_staff
  from public.staff_attendance_profiles s
  join public.school_people p on p.id = s.central_person_id
  where s.id = v_staff_id
    and p.person_status = 'active'
    and s.registration_status = 'active'
    and s.employment_status = 'active';
  if not found or v_staff.central_person_id is null then
    return jsonb_build_object('ok', false, 'code', 'STAFF_IDENTITY_NOT_ACTIVE');
  end if;

  select i.* into v_account
  from public.school_identity_accounts i
  where i.person_id = v_staff.central_person_id
    and i.account_status = 'active'
  for update;
  if not found then
    return jsonb_build_object('ok', false, 'code', 'IDENTITY_ACCOUNT_NOT_ACTIVE');
  end if;

  -- There is only one usable code per person and purpose. Issuing a new code
  -- immediately invalidates any earlier code that may have been shared.
  update public.school_identity_management_codes
  set revoked_at = now(),
      updated_at = now()
  where identity_account_id = v_account.id
    and purpose = v_purpose
    and used_at is null
    and revoked_at is null;

  v_raw_code := 'WTS-' || upper(encode(gen_random_bytes(8), 'hex'));
  insert into public.school_identity_management_codes(
    identity_account_id,
    person_id,
    purpose,
    code_hash,
    issued_by_person_id,
    issued_at,
    expires_at,
    reason,
    request_id,
    metadata
  ) values (
    v_account.id,
    v_account.person_id,
    v_purpose,
    encode(digest(upper(regexp_replace(v_raw_code, '[^A-Za-z0-9]', '', 'g')), 'sha256'), 'hex'),
    v_actor_person_id,
    now(),
    v_expires_at,
    v_reason,
    v_request_id,
    jsonb_build_object('delivery_method', 'management_direct', 'issued_from', 'central_registry_session')
  ) returning id into v_code_id;

  insert into public.school_registry_audit(
    actor_type,
    actor_id,
    action,
    entity_type,
    entity_id,
    request_id,
    before_data,
    after_data,
    details
  ) values (
    'person',
    v_actor_person_id::text,
    case when v_purpose = 'activation'
      then 'identity.activation_code_issued'
      else 'identity.password_recovery_code_issued'
    end,
    'school_identity_management_code',
    v_code_id::text,
    v_request_id,
    null,
    jsonb_build_object('purpose', v_purpose, 'expires_at', v_expires_at, 'attempt_limit', 5),
    jsonb_build_object(
      'staff_id', v_staff.id,
      'person_id', v_account.person_id,
      'reason', v_reason,
      'delivery_method', 'management_direct',
      'raw_code_stored', false
    )
  );

  return jsonb_build_object(
    'ok', true,
    'code', 'MANAGEMENT_RECOVERY_CODE_ISSUED',
    'purpose', v_purpose,
    'staff_id', v_staff.id,
    'staff_number', v_staff.staff_number,
    'recovery_code', v_raw_code,
    'expires_at', v_expires_at,
    'request_id', v_request_id
  );
exception
  when others then
    return jsonb_build_object('ok', false, 'code', 'RECOVERY_CODE_ISSUE_FAILED');
end;
$function$;

revoke all on function public.school_identity_admin_write_session_api(uuid, text, text, jsonb)
  from public, authenticated;
grant execute on function public.school_identity_admin_write_session_api(uuid, text, text, jsonb)
  to anon;

-- The staff member supplies the staff number, the code shared by management,
-- and a new password. The function is deliberately generic on failure so it
-- does not reveal whether a staff number or code is valid.
create or replace function public.school_identity_management_code_consume(
  p_login text,
  p_purpose text,
  p_code text,
  p_new_password text
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_login text := trim(coalesce(p_login, ''));
  v_purpose text := lower(trim(coalesce(p_purpose, '')));
  v_normalized_code text := upper(regexp_replace(trim(coalesce(p_code, '')), '[^A-Za-z0-9]', '', 'g'));
  v_staff public.staff_attendance_profiles%rowtype;
  v_account public.school_identity_accounts%rowtype;
  v_code public.school_identity_management_codes%rowtype;
  v_credential public.school_identity_credentials%rowtype;
  v_credential_id uuid;
  v_login_name text;
  v_before jsonb;
begin
  if length(v_login) = 0 or length(v_login) > 254
     or v_purpose not in ('activation', 'password_reset')
     or v_normalized_code !~ '^WTS[0-9A-F]{16}$'
     or length(coalesce(p_new_password, '')) < 10
     or length(coalesce(p_new_password, '')) > 512
     or p_new_password !~ '[A-Z]'
     or p_new_password !~ '[a-z]'
     or p_new_password !~ '[0-9]' then
    return jsonb_build_object('ok', false, 'code', 'MANAGEMENT_CODE_INVALID');
  end if;

  select s.* into v_staff
  from public.staff_attendance_profiles s
  join public.school_identity_accounts i on i.person_id = s.central_person_id
  join public.school_people p on p.id = s.central_person_id
  where p.person_status = 'active'
    and s.registration_status = 'active'
    and s.employment_status = 'active'
    and i.account_status = 'active'
    and (
      lower(coalesce(s.staff_number, '')) = lower(v_login)
      or lower(coalesce(s.email, '')) = lower(v_login)
      or lower(coalesce(i.login_email, '')) = lower(v_login)
    )
  order by case when lower(coalesce(s.staff_number, '')) = lower(v_login) then 0 else 1 end
  limit 1;
  if not found or v_staff.central_person_id is null then
    return jsonb_build_object('ok', false, 'code', 'MANAGEMENT_CODE_INVALID');
  end if;

  select i.* into v_account
  from public.school_identity_accounts i
  where i.person_id = v_staff.central_person_id
    and i.account_status = 'active'
  for update;
  if not found then
    return jsonb_build_object('ok', false, 'code', 'MANAGEMENT_CODE_INVALID');
  end if;

  select c.* into v_code
  from public.school_identity_management_codes c
  where c.identity_account_id = v_account.id
    and c.person_id = v_account.person_id
    and c.purpose = v_purpose
    and c.used_at is null
    and c.revoked_at is null
  order by c.issued_at desc
  limit 1
  for update;
  if not found then
    return jsonb_build_object('ok', false, 'code', 'MANAGEMENT_CODE_INVALID');
  end if;
  if v_code.expires_at <= now() then
    update public.school_identity_management_codes
    set revoked_at = now(), updated_at = now()
    where id = v_code.id;
    return jsonb_build_object('ok', false, 'code', 'MANAGEMENT_CODE_INVALID');
  end if;

  if v_code.code_hash <> encode(digest(v_normalized_code, 'sha256'), 'hex') then
    update public.school_identity_management_codes
    set attempt_count = least(attempt_count + 1, 5),
        revoked_at = case when attempt_count >= 4 then now() else revoked_at end,
        updated_at = now()
    where id = v_code.id;
    return jsonb_build_object('ok', false, 'code', 'MANAGEMENT_CODE_INVALID');
  end if;

  select c.* into v_credential
  from public.school_identity_credentials c
  where c.identity_account_id = v_account.id
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
    identity_account_id,
    person_id,
    login_name,
    password_hash,
    credential_status,
    must_change_password,
    failed_attempts,
    locked_until,
    password_changed_at,
    updated_at
  ) values (
    v_account.id,
    v_account.person_id,
    v_login_name,
    crypt(p_new_password, gen_salt('bf', 12)),
    'active',
    false,
    0,
    null,
    now(),
    now()
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
      case when v_purpose = 'activation'
        then 'last_management_activation_completed_at'
        else 'last_management_password_reset_completed_at'
      end,
      now()
    ),
    updated_at = now()
  where id = v_account.id;

  if v_purpose = 'activation' then
    update public.staff_attendance_profiles
    set activated_at = coalesce(activated_at, now()), updated_at = now()
    where id = v_staff.id;
  end if;

  perform wts_internal.revoke_identity_sessions(v_account.person_id, 'MANAGEMENT_RECOVERY_CODE_CONSUMED');
  update public.attendance_admin_clients
  set status = 'suspended',
      session_expires_at = null,
      secret_hash = encode(digest(encode(gen_random_bytes(32), 'hex'), 'sha256'), 'hex'),
      updated_at = now()
  where central_person_id = v_account.person_id;

  update public.school_identity_management_codes
  set used_at = now(), updated_at = now()
  where id = v_code.id and used_at is null and revoked_at is null;

  insert into public.school_registry_audit(
    actor_type,
    actor_id,
    action,
    entity_type,
    entity_id,
    request_id,
    before_data,
    after_data,
    details
  ) values (
    'self_service',
    'management_code',
    case when v_purpose = 'activation'
      then 'identity.activation_completed'
      else 'identity.password_reset_completed'
    end,
    'identity_credential',
    v_credential_id::text,
    gen_random_uuid(),
    v_before,
    jsonb_build_object(
      'credential_status', 'active',
      'must_change_password', false,
      'failed_attempts', 0,
      'locked_until', null,
      'sessions_revoked', true
    ),
    jsonb_build_object(
      'person_id', v_account.person_id,
      'purpose', v_purpose,
      'management_code_id', v_code.id,
      'code_issuer_person_id', v_code.issued_by_person_id
    )
  );

  return jsonb_build_object(
    'ok', true,
    'code', case when v_purpose = 'activation'
      then 'STAFF_ACCOUNT_ACTIVATED'
      else 'PASSWORD_RESET_COMPLETED'
    end,
    'purpose', v_purpose,
    'staff_number', v_staff.staff_number
  );
exception
  when others then
    return jsonb_build_object('ok', false, 'code', 'MANAGEMENT_CODE_COMPLETION_FAILED');
end;
$function$;

revoke all on function public.school_identity_management_code_consume(text, text, text, text)
  from public, authenticated;
grant execute on function public.school_identity_management_code_consume(text, text, text, text)
  to anon;
