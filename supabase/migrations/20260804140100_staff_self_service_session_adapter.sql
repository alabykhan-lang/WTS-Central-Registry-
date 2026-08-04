-- Replace the browser-supplied staff self-service client secret with the
-- central session foundation. The old function remains available temporarily
-- until the new same-origin route is deployed and verified.

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
begin
  v_session := public.school_identity_session_validate(p_session_id, p_session_secret, 'staff_self_service');
  if coalesce((v_session ->> 'ok')::boolean, false) is not true then return v_session; end if;

  begin
    v_person_id := (v_session ->> 'person_id')::uuid;
  exception when others then
    return jsonb_build_object('ok', false, 'code', 'CENTRAL_IDENTITY_NOT_ACTIVE');
  end;

  select id into v_staff_id
  from public.staff_attendance_profiles
  where central_person_id = v_person_id
    and registration_status = 'active'
    and employment_status = 'active'
  limit 1;
  if v_staff_id is null then return jsonb_build_object('ok', false, 'code', 'STAFF_NOT_ACTIVE'); end if;

  select coalesce(array(select jsonb_array_elements_text(v_session -> 'permissions')), array[]::text[])
    into v_permissions;

  if p_action = 'profile' then
    return jsonb_build_object(
      'ok', true,
      'profile', (select jsonb_build_object(
        'staff_id', s.id, 'person_id', s.central_person_id, 'staff_number', s.staff_number, 'full_name', s.full_name,
        'email', s.email, 'phone', s.phone, 'address', s.address, 'staff_category', s.staff_category,
        'department', s.department, 'designation', s.designation, 'photo', s.photo,
        'employment_status', s.employment_status, 'attendance_required', s.attendance_required
      ) from public.staff_attendance_profiles s where s.id = v_staff_id),
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
    if not (v_permissions @> array['profile.update']::text[]) then
      return jsonb_build_object('ok', false, 'code', 'SELF_SERVICE_UPDATE_DENIED');
    end if;
    update public.staff_attendance_profiles
    set email = case when p_payload ? 'email' then nullif(lower(trim(p_payload ->> 'email')), '') else email end,
        phone = case when p_payload ? 'phone' then nullif(trim(p_payload ->> 'phone'), '') else phone end,
        address = case when p_payload ? 'address' then nullif(trim(p_payload ->> 'address'), '') else address end,
        photo = case when p_payload ? 'photo' then nullif(trim(p_payload ->> 'photo'), '') else photo end,
        updated_at = now()
    where id = v_staff_id;
    update public.school_people
    set primary_email = case when p_payload ? 'email' then nullif(lower(trim(p_payload ->> 'email')), '') else primary_email end,
        primary_phone = case when p_payload ? 'phone' then nullif(trim(p_payload ->> 'phone'), '') else primary_phone end,
        photo_path = case when p_payload ? 'photo' then nullif(trim(p_payload ->> 'photo'), '') else photo_path end,
        updated_at = now()
    where id = v_person_id;
    update public.school_identity_accounts
    set login_email = case when p_payload ? 'email' then nullif(lower(trim(p_payload ->> 'email')), '') else login_email end,
        updated_at = now()
    where person_id = v_person_id;
    return jsonb_build_object('ok', true, 'code', 'STAFF_PROFILE_UPDATED', 'staff_id', v_staff_id);
  end if;

  return jsonb_build_object('ok', false, 'code', 'UNKNOWN_ACTION');
exception
  when others then return jsonb_build_object('ok', false, 'code', 'STAFF_SELF_SERVICE_FAILED');
end;
$function$;

revoke all on function public.school_staff_self_service_session_api(uuid, text, text, jsonb) from public, authenticated;
grant execute on function public.school_staff_self_service_session_api(uuid, text, text, jsonb) to anon;
