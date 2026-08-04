-- Contained production recovery additions.
--
-- This migration does not alter RLS, PKCE, scores, students, grants or
-- academic records. It adds an operator-labelled bootstrap wrapper and a
-- grant-checked, audited Result emergency gate. Temporary credentials remain
-- generated and returned only by the existing protected server flow.

create or replace function public.school_identity_bootstrap_reset_with_actor(
  p_staff_number text,
  p_login_email text,
  p_reason text,
  p_actor_id text
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_person_id uuid;
  v_actor_id text := left(coalesce(nullif(trim(p_actor_id), ''), 'bootstrap_operator'), 160);
begin
  if trim(coalesce(p_staff_number, '')) <> 'WTS/STF/000008'
     or lower(trim(coalesce(p_login_email, ''))) <> 'alabykhan@gmail.com' then
    return jsonb_build_object('ok', false, 'code', 'BOOTSTRAP_TARGET_NOT_ALLOWED');
  end if;

  select s.central_person_id into v_person_id
  from public.staff_attendance_profiles s
  join public.school_people p on p.id = s.central_person_id
  where s.staff_number = 'WTS/STF/000008'
    and lower(coalesce(s.email, '')) = 'alabykhan@gmail.com'
    and lower(coalesce(p.primary_email, '')) = 'alabykhan@gmail.com';

  if v_person_id is null then
    return jsonb_build_object('ok', false, 'code', 'BOOTSTRAP_TARGET_NOT_FOUND');
  end if;

  return wts_internal.issue_temporary_credential(
    v_person_id,
    trim(p_reason),
    'bootstrap_recovery',
    v_actor_id,
    true
  );
end;
$function$;

revoke all on function public.school_identity_bootstrap_reset_with_actor(text, text, text, text)
  from public, anon, authenticated;
grant execute on function public.school_identity_bootstrap_reset_with_actor(text, text, text, text)
  to service_role;

-- The emergency route is not a login or registration endpoint. It only grants
-- a short transitional route after the caller proves an active Result session
-- and an active Central Registry management grant. Every successful use is
-- recorded without storing a password, session secret or other raw secret.
create or replace function public.school_identity_result_emergency_access(
  p_session_id uuid,
  p_session_secret text
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_validation jsonb;
  v_person_id uuid;
  v_request_id uuid := gen_random_uuid();
  v_expires_at timestamptz;
begin
  v_validation := public.school_identity_session_validate(
    p_session_id,
    p_session_secret,
    'results'
  );

  if coalesce((v_validation ->> 'ok')::boolean, false) is not true then
    return jsonb_build_object(
      'ok', false,
      'code', coalesce(v_validation ->> 'code', 'RESULT_SESSION_NOT_ACTIVE')
    );
  end if;

  begin
    v_person_id := (v_validation ->> 'person_id')::uuid;
  exception when others then
    return jsonb_build_object('ok', false, 'code', 'RESULT_SESSION_NOT_ACTIVE');
  end;

  if v_person_id is null or not exists (
    select 1
    from public.school_access_grants g
    where g.person_id = v_person_id
      and g.app_code = 'central_registry'
      and g.grant_status = 'active'
      and (g.valid_from is null or g.valid_from <= now())
      and (g.valid_until is null or g.valid_until > now())
      and ('access.manage' = any(g.permissions) or 'registry.manage' = any(g.permissions))
  ) then
    return jsonb_build_object('ok', false, 'code', 'RESULT_EMERGENCY_ADMIN_REQUIRED');
  end if;

  v_expires_at := least(
    (v_validation ->> 'expires_at')::timestamptz,
    now() + interval '10 minutes'
  );

  insert into public.school_registry_audit(
    actor_type,
    actor_id,
    action,
    entity_type,
    entity_id,
    request_id,
    details
  ) values (
    'result_session',
    v_person_id::text,
    'result.emergency_legacy.accessed',
    'result_emergency_route',
    coalesce(p_session_id::text, 'unknown-session'),
    v_request_id,
    jsonb_build_object(
      'source', 'protected_emergency_route',
      'transitional', true,
      'warning_required', true,
      'expires_at', v_expires_at
    )
  );

  return jsonb_build_object(
    'ok', true,
    'code', 'RESULT_EMERGENCY_ACCESS_GRANTED',
    'request_id', v_request_id,
    'expires_at', v_expires_at
  );
end;
$function$;

revoke all on function public.school_identity_result_emergency_access(uuid, text)
  from public;
grant execute on function public.school_identity_result_emergency_access(uuid, text)
  to anon, authenticated;
