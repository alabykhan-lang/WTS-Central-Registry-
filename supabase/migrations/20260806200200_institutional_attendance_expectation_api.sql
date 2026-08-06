-- Personal Attendance expectation is independent from institutional authority.
-- Only a protected authority may change it, and the change is audited.

create or replace function public.school_institutional_attendance_expectation_api(
  p_session_id uuid,
  p_session_secret text,
  p_target_person_id uuid,
  p_personal_attendance_required boolean,
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
  v_actor_authority jsonb;
  v_target public.school_people%rowtype;
  v_before jsonb;
  v_after jsonb;
begin
  if not coalesce(p_recent_reauthentication, false)
     or not coalesce(p_explicit_confirmation, false)
     or length(trim(coalesce(p_reason, ''))) < 8 then
    return jsonb_build_object('ok', false, 'code', 'PROTECTED_RECOVERY_CONFIRMATION_REQUIRED');
  end if;

  v_session := public.school_identity_session_validate(p_session_id, p_session_secret, 'central_registry');
  if coalesce((v_session ->> 'ok')::boolean, false) is not true then
    return v_session;
  end if;
  v_actor_authority := coalesce(v_session -> 'institutional_authority', '{}'::jsonb);
  if v_actor_authority ->> 'classification' not in ('system_owner', 'proprietor') then
    return jsonb_build_object('ok', false, 'code', 'PROTECTED_IDENTITY_AUTHORITY_REQUIRED');
  end if;

  select * into v_target
  from public.school_people
  where id = p_target_person_id
  for update;
  if not found or v_target.institutional_classification = 'ordinary_staff' then
    return jsonb_build_object('ok', false, 'code', 'PROTECTED_IDENTITY_NOT_FOUND');
  end if;

  v_before := jsonb_build_object(
    'institutional_classification', v_target.institutional_classification,
    'personal_attendance_required', v_target.personal_attendance_required
  );
  perform set_config('wts.allow_institutional_recovery', 'on', true);
  update public.school_people
  set personal_attendance_required = coalesce(p_personal_attendance_required, true),
      updated_at = now()
  where id = v_target.id;
  select jsonb_build_object(
    'institutional_classification', p.institutional_classification,
    'personal_attendance_required', p.personal_attendance_required
  ) into v_after
  from public.school_people p
  where p.id = v_target.id;

  insert into public.school_registry_audit(
    actor_type, actor_id, action, entity_type, entity_id, before_data, after_data, details
  ) values (
    'person', v_session ->> 'person_id', 'identity.attendance_expectation.updated',
    'school_people', v_target.id::text, v_before, v_after,
    jsonb_build_object(
      'reason', left(trim(p_reason), 240),
      'recent_reauthentication', true,
      'explicit_confirmation', true,
      'actor_classification', v_actor_authority ->> 'classification'
    )
  );
  return jsonb_build_object(
    'ok', true,
    'code', 'INSTITUTIONAL_ATTENDANCE_EXPECTATION_UPDATED',
    'person_id', v_target.id,
    'personal_attendance_required', p_personal_attendance_required
  );
end;
$function$;

revoke all on function public.school_institutional_attendance_expectation_api(uuid, text, uuid, boolean, text, boolean, boolean)
  from public, anon, authenticated;
grant execute on function public.school_institutional_attendance_expectation_api(uuid, text, uuid, boolean, text, boolean, boolean)
  to anon, authenticated;
