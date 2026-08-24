-- Shared self-service password activation/recovery for existing teachers.
-- The plaintext school code is never stored here or in application source;
-- only its SHA-256 digest is compared. Staff Number still identifies the
-- single teacher account whose password may be changed.

create or replace function public.school_identity_shared_teacher_code_consume(
  p_login text,
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
  v_normalized_code text := upper(regexp_replace(trim(coalesce(p_code, '')), '[^A-Za-z0-9]', '', 'g'));
  v_shared_code_hash constant text := 'efed2beb3d52be83f4b888b7186dee147b20f3f1ca39938093cf68760d8976cb';
  v_staff public.staff_attendance_profiles%rowtype;
  v_account public.school_identity_accounts%rowtype;
  v_credential public.school_identity_credentials%rowtype;
  v_credential_id uuid;
  v_login_name text;
  v_before jsonb := '{}'::jsonb;
  v_had_credential boolean := false;
  v_request_id uuid := gen_random_uuid();
begin
  if length(v_login) = 0 or length(v_login) > 64
     or v_normalized_code !~ '^WTS[0-9A-F]{16}$'
     or encode(digest(v_normalized_code, 'sha256'), 'hex') <> v_shared_code_hash
     or length(coalesce(p_new_password, '')) < 10
     or length(coalesce(p_new_password, '')) > 512
     or p_new_password !~ '[A-Z]'
     or p_new_password !~ '[a-z]'
     or p_new_password !~ '[0-9]' then
    return jsonb_build_object('ok', false, 'code', 'SHARED_TEACHER_CODE_INVALID');
  end if;

  select s.* into v_staff
  from public.staff_attendance_profiles s
  join public.school_people p on p.id = s.central_person_id
  join public.school_identity_accounts i on i.person_id = s.central_person_id
  where lower(coalesce(s.staff_number, '')) = lower(v_login)
    and p.person_status = 'active'
    and s.registration_status = 'active'
    and s.employment_status = 'active'
    and i.account_status = 'active'
    and (
      lower(coalesce(s.staff_category, '')) in ('teaching', 'teacher')
      or lower(coalesce(s.designation, '')) like '%teacher%'
    )
  limit 1;
  if not found or v_staff.central_person_id is null then
    return jsonb_build_object('ok', false, 'code', 'SHARED_TEACHER_CODE_INVALID');
  end if;

  select i.* into v_account
  from public.school_identity_accounts i
  where i.person_id = v_staff.central_person_id
    and i.account_status = 'active'
  for update;
  if not found then
    return jsonb_build_object('ok', false, 'code', 'SHARED_TEACHER_CODE_INVALID');
  end if;

  select c.* into v_credential
  from public.school_identity_credentials c
  where c.identity_account_id = v_account.id
  for update;
  v_had_credential := found;
  if v_had_credential then
    v_before := jsonb_build_object(
      'credential_status', v_credential.credential_status,
      'must_change_password', v_credential.must_change_password,
      'failed_attempts', v_credential.failed_attempts,
      'locked_until', v_credential.locked_until
    );
  end if;

  v_login_name := coalesce(
    nullif(trim(v_credential.login_name), ''),
    v_staff.staff_number,
    v_account.login_email
  );

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
  set metadata = metadata || jsonb_build_object('last_shared_teacher_recovery_at', now()),
      updated_at = now()
  where id = v_account.id;

  update public.staff_attendance_profiles
  set activated_at = coalesce(activated_at, now()),
      updated_at = now()
  where id = v_staff.id;

  perform wts_internal.revoke_identity_sessions(
    v_account.person_id,
    'SHARED_TEACHER_CODE_PASSWORD_CHANGED'
  );

  update public.attendance_admin_clients
  set status = 'suspended',
      session_expires_at = null,
      secret_hash = encode(digest(encode(gen_random_bytes(32), 'hex'), 'sha256'), 'hex'),
      updated_at = now()
  where central_person_id = v_account.person_id;

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
    'shared_teacher_code',
    case when v_had_credential
      then 'identity.shared_teacher_password_reset_completed'
      else 'identity.shared_teacher_activation_completed'
    end,
    'identity_credential',
    v_credential_id::text,
    v_request_id,
    v_before,
    jsonb_build_object(
      'credential_status', 'active',
      'must_change_password', false,
      'sessions_revoked', true
    ),
    jsonb_build_object(
      'person_id', v_account.person_id,
      'staff_id', v_staff.id,
      'shared_teacher_code', true,
      'raw_code_stored', false
    )
  );

  return jsonb_build_object(
    'ok', true,
    'code', case when v_had_credential
      then 'PASSWORD_RESET_COMPLETED'
      else 'STAFF_ACCOUNT_ACTIVATED'
    end,
    'staff_number', v_staff.staff_number
  );
exception
  when others then
    return jsonb_build_object('ok', false, 'code', 'SHARED_TEACHER_RECOVERY_FAILED');
end;
$function$;

revoke all on function public.school_identity_shared_teacher_code_consume(text, text, text)
  from public, authenticated, service_role;
grant execute on function public.school_identity_shared_teacher_code_consume(text, text, text)
  to anon;
