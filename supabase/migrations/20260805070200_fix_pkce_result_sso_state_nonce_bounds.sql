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
  v_person public.school_people%rowtype;
  v_staff public.staff_attendance_profiles%rowtype;
  v_account public.school_identity_accounts%rowtype;
  v_grant record;
  v_result_identity jsonb;
  v_result_session_id uuid;
  v_result_session_secret text;
  v_expires_at timestamptz;
  v_verifier_challenge text;
begin
  if coalesce(trim(p_client_id), '') <> 'result_portal'
     or coalesce(trim(p_redirect_uri), '') <> 'https://wts-result-system.vercel.app/portal_core.html' then
    return jsonb_build_object('ok', false, 'code', 'SSO_CLIENT_OR_REDIRECT_INVALID');
  end if;
  if coalesce(trim(p_code), '') = ''
     or coalesce(trim(p_code_verifier), '') !~ '^[A-Za-z0-9._~-]{43,128}$'
     or coalesce(trim(p_state), '') !~ '^[A-Za-z0-9._~-]{16,255}$'
     or coalesce(trim(p_nonce), '') !~ '^[A-Za-z0-9._~-]{16,255}$' then
    return jsonb_build_object('ok', false, 'code', 'SSO_REQUEST_INVALID');
  end if;

  select c.* into v_code
  from public.school_sso_authorization_codes c
  where c.code_hash = encode(digest(trim(p_code), 'sha256'), 'hex')
  for update;
  if not found then
    return jsonb_build_object('ok', false, 'code', 'SSO_CODE_INVALID');
  end if;
  if v_code.client_id <> 'result_portal' or v_code.target_app_code <> 'results' then
    return jsonb_build_object('ok', false, 'code', 'SSO_AUDIENCE_INVALID');
  end if;
  if v_code.redirect_uri <> 'https://wts-result-system.vercel.app/portal_core.html'
     or trim(p_redirect_uri) <> v_code.redirect_uri then
    return jsonb_build_object('ok', false, 'code', 'SSO_REDIRECT_URI_MISMATCH');
  end if;
  if v_code.consumed_at is not null then
    return jsonb_build_object('ok', false, 'code', 'SSO_CODE_REUSED');
  end if;
  if v_code.expires_at <= now() then
    return jsonb_build_object('ok', false, 'code', 'SSO_CODE_EXPIRED');
  end if;
  if encode(digest(trim(p_state), 'sha256'), 'hex') <> v_code.state_hash
     or encode(digest(trim(p_nonce), 'sha256'), 'hex') <> v_code.nonce_hash then
    return jsonb_build_object('ok', false, 'code', 'SSO_STATE_OR_NONCE_INVALID');
  end if;

  v_verifier_challenge := rtrim(
    replace(
      replace(encode(digest(trim(p_code_verifier), 'sha256'), 'base64'), '+', '-'),
      '/', '_'
    ),
    '='
  );
  if v_code.code_challenge_method <> 'S256'
     or v_verifier_challenge <> v_code.code_challenge then
    return jsonb_build_object('ok', false, 'code', 'SSO_PKCE_INVALID');
  end if;

  select s.* into v_source_session
  from public.school_identity_sessions s
  where s.id = v_code.source_session_id
    and s.person_id = v_code.person_id
    and s.identity_account_id = v_code.identity_account_id
    and s.target_app_code = 'staff_self_service'
    and s.revoked_at is null
    and s.expires_at > now()
  for update;
  if not found then
    update public.school_sso_authorization_codes
    set consumed_at = now(), consumed_by = 'source_session_inactive'
    where id = v_code.id and consumed_at is null;
    return jsonb_build_object('ok', false, 'code', 'WTS_SESSION_NOT_ACTIVE');
  end if;

  select p.* into v_person from public.school_people p where p.id = v_code.person_id for update;
  select i.* into v_account
  from public.school_identity_accounts i
  where i.id = v_code.identity_account_id and i.person_id = v_code.person_id
  for update;
  select s.* into v_staff
  from public.staff_attendance_profiles s
  where s.central_person_id = v_code.person_id
    and s.registration_status = 'active'
    and s.employment_status = 'active'
  order by s.created_at limit 1;
  select g.* into v_grant
  from public.school_access_grants g
  where g.person_id = v_code.person_id
    and g.app_code = 'results'
    and g.grant_status = 'active'
    and (g.valid_from is null or g.valid_from <= now())
    and (g.valid_until is null or g.valid_until > now())
  order by g.created_at desc limit 1;

  if not found
     or v_person.id is null
     or v_person.person_status <> 'active'
     or v_account.id is null
     or v_account.account_status <> 'active'
     or v_staff.id is null
     or v_grant.id is null then
    update public.school_sso_authorization_codes
    set consumed_at = now(), consumed_by = 'identity_revalidation_denied'
    where id = v_code.id and consumed_at is null;
    return jsonb_build_object('ok', false, 'code', 'RESULT_ACCESS_NOT_GRANTED');
  end if;

  if not exists (
    select 1 from public.school_identity_credentials cr
    where cr.identity_account_id = v_account.id
      and cr.person_id = v_code.person_id
      and cr.credential_status = 'active'
  ) then
    update public.school_sso_authorization_codes
    set consumed_at = now(), consumed_by = 'credential_inactive'
    where id = v_code.id and consumed_at is null;
    return jsonb_build_object('ok', false, 'code', 'IDENTITY_NOT_ACTIVE');
  end if;

  v_result_identity := public.school_result_identity_resolve(v_code.person_id, v_code.identity_account_id);
  if coalesce((v_result_identity ->> 'ok')::boolean, false) is not true then
    update public.school_sso_authorization_codes
    set consumed_at = now(), consumed_by = 'result_identity_unresolved'
    where id = v_code.id and consumed_at is null;
    return jsonb_build_object('ok', false, 'code', coalesce(v_result_identity ->> 'code', 'RESULT_IDENTITY_NOT_RESOLVED'));
  end if;

  update public.school_sso_authorization_codes
  set consumed_at = now(), consumed_by = 'result_portal'
  where id = v_code.id and consumed_at is null;
  if not found then
    return jsonb_build_object('ok', false, 'code', 'SSO_CODE_REUSED');
  end if;

  v_result_session_secret := encode(gen_random_bytes(32), 'base64');
  v_expires_at := now() + interval '8 hours';
  insert into public.school_identity_sessions (
    person_id, identity_account_id, originating_app_code, target_app_code,
    secret_hash, created_at, expires_at, last_seen_at, metadata
  )
  values (
    v_code.person_id, v_code.identity_account_id, 'results', 'results',
    encode(digest(v_result_session_secret, 'sha256'), 'hex'),
    now(), v_expires_at, now(),
    jsonb_build_object(
      'source', 'pkce_sso',
      'authorization_code_id', v_code.id,
      'source_workspace_session_id', v_code.source_session_id
    )
  )
  returning id into v_result_session_id;

  insert into public.school_registry_audit (
    actor_type, actor_id, action, entity_type, entity_id, details
  )
  values (
    'staff_session', v_code.person_id::text, 'identity.result_session.issued',
    'school_identity_sessions', v_result_session_id::text,
    jsonb_build_object(
      'source', 'pkce_sso',
      'authorization_code_id', v_code.id,
      'target_app_code', 'results',
      'expires_at', v_expires_at
    )
  );

  return jsonb_build_object(
    'ok', true,
    'code', 'SSO_EXCHANGED',
    'session_id', v_result_session_id,
    'session_secret', v_result_session_secret,
    'expires_at', v_expires_at,
    'person_id', v_code.person_id,
    'identity_account_id', v_code.identity_account_id,
    'result_user', v_result_identity -> 'result_user',
    'staff', v_result_identity -> 'staff',
    'access_role', v_grant.access_role,
    'permissions', coalesce(v_grant.permissions, array[]::text[])
  );
end;
$function$;
