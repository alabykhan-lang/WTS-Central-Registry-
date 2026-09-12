-- Fix the Results staff controls against the current Central Registry schema.
-- This is intentionally additive: it does not change Result SSO, PKCE, or
-- any identity-session transaction.

create or replace function public.school_result_staff_write_access_read(
  p_session_id uuid,
  p_session_secret text
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_auth jsonb;
  v_default boolean;
  v_rows jsonb;
begin
  v_auth := public.school_result_authorize(p_session_id, p_session_secret, 'results.manage');
  if coalesce((v_auth ->> 'ok')::boolean, false) is not true then
    v_auth := public.school_result_authorize(p_session_id, p_session_secret, 'result_users.manage');
  end if;
  if coalesce((v_auth ->> 'ok')::boolean, false) is not true then
    v_auth := public.school_result_authorize(p_session_id, p_session_secret, 'result_settings.manage');
  end if;
  if coalesce((v_auth ->> 'ok')::boolean, false) is not true then return v_auth; end if;

  select default_write_enabled into v_default
  from public.school_result_write_policies
  where app_code = 'results';
  v_default := coalesce(v_default, false);

  with registry_staff as (
    select
      p.id as person_id,
      coalesce(nullif(trim(s.full_name), ''), nullif(trim(p.preferred_name), ''), p.full_name, p.id::text) as full_name,
      p.primary_email,
      s.email as staff_email,
      coalesce(s.staff_number, p.institutional_number) as staff_number,
      coalesce(nullif(trim(s.designation), ''),
        case p.institutional_classification
          when 'system_owner' then 'System owner'
          when 'proprietor' then 'Proprietor'
          else 'Staff'
        end) as designation,
      coalesce(nullif(trim(s.staff_category), ''), p.institutional_classification) as staff_category,
      coalesce(s.updated_at, p.updated_at) as staff_updated_at
    from public.school_people p
    left join lateral (
      select s.*
      from public.staff_attendance_profiles s
      where s.central_person_id = p.id
        and s.registration_status = 'active'
        and s.employment_status = 'active'
      order by s.updated_at desc, s.created_at desc, s.id
      limit 1
    ) s on true
    where p.person_status = 'active'
      and p.institutional_classification in ('ordinary_staff', 'proprietor', 'system_owner')
  )
  select coalesce(jsonb_agg(to_jsonb(x) order by lower(x.full_name), x.person_id), '[]'::jsonb)
    into v_rows
  from (
    select
      r.person_id,
      r.staff_number,
      r.full_name,
      coalesce(nullif(trim(r.primary_email), ''), nullif(trim(r.staff_email), '')) as email,
      r.designation,
      r.staff_category,
      coalesce(nullif(trim(g.access_role), ''), 'No Results access') as access_role,
      coalesce(nullif(trim(r.designation), ''), nullif(trim(r.staff_category), ''), 'Staff') as registry_role,
      coalesce(g.permissions, array[]::text[]) as permissions,
      coalesce(g.grant_status, 'none') as grant_status,
      (g.person_id is not null) as results_access,
      (g.person_id is not null and coalesce(g.permissions, array[]::text[]) && array[
        'results.manage',
        'scores.enter',
        'result_entry.create',
        'result_entry.edit',
        'result_entry.submit'
      ]::text[]) as eligible_for_score_entry,
      case
        when g.person_id is null then false
        else public.school_result_write_enabled(g.person_id)
          or public.school_result_permission_allowed(g.permissions, 'results.manage')
      end as write_enabled,
      (a.person_id is not null) as has_override,
      coalesce(a.updated_at, g.updated_at, r.staff_updated_at) as updated_at,
      a.reason as write_reason,
      g.reason as grant_reason
    from registry_staff r
    left join lateral (
      select g.*
      from public.school_access_grants g
      where g.person_id = r.person_id
        and g.app_code = 'results'
        and g.grant_status = 'active'
        and (g.valid_from is null or g.valid_from <= now())
        and (g.valid_until is null or g.valid_until > now())
      order by g.updated_at desc, g.created_at desc, g.id
      limit 1
    ) g on true
    left join public.school_result_staff_write_access a
      on a.app_code = 'results' and a.person_id = r.person_id
  ) x;

  return jsonb_build_object(
    'ok', true,
    'code', 'RESULT_STAFF_WRITE_ACCESS_READ',
    'default_write_enabled', v_default,
    'rows', v_rows,
    'requested_by_person_id', v_auth ->> 'person_id'
  );
end;
$function$;

create or replace function public.school_result_staff_write_access_update(
  p_session_id uuid,
  p_session_secret text,
  p_person_id uuid,
  p_write_enabled boolean,
  p_reason text default null
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_auth jsonb;
  v_before jsonb;
  v_after jsonb;
  v_enabled boolean := coalesce(p_write_enabled, false);
  v_reason text := left(trim(coalesce(p_reason, '')), 500);
begin
  v_auth := public.school_result_authorize(p_session_id, p_session_secret, 'results.manage');
  if coalesce((v_auth ->> 'ok')::boolean, false) is not true then
    v_auth := public.school_result_authorize(p_session_id, p_session_secret, 'result_users.manage');
  end if;
  if coalesce((v_auth ->> 'ok')::boolean, false) is not true then
    v_auth := public.school_result_authorize(p_session_id, p_session_secret, 'result_settings.manage');
  end if;
  if coalesce((v_auth ->> 'ok')::boolean, false) is not true then return v_auth; end if;
  if p_person_id is null then
    return jsonb_build_object('ok', false, 'code', 'RESULT_STAFF_WRITE_TARGET_REQUIRED');
  end if;
  if not exists (
    select 1
    from public.school_access_grants g
    join public.school_people p on p.id = g.person_id
    join public.staff_attendance_profiles s on s.central_person_id = p.id
    where g.person_id = p_person_id
      and g.app_code = 'results'
      and g.grant_status = 'active'
      and (g.valid_from is null or g.valid_from <= now())
      and (g.valid_until is null or g.valid_until > now())
      and p.person_status = 'active'
      and s.registration_status = 'active'
      and s.employment_status = 'active'
  ) then
    return jsonb_build_object('ok', false, 'code', 'RESULT_STAFF_WRITE_TARGET_NOT_FOUND');
  end if;

  select to_jsonb(a) into v_before
  from public.school_result_staff_write_access a
  where a.app_code = 'results' and a.person_id = p_person_id;

  insert into public.school_result_staff_write_access(
    app_code, person_id, write_enabled, reason, updated_by, updated_at
  ) values (
    'results', p_person_id, v_enabled, nullif(v_reason, ''), (v_auth ->> 'person_id')::uuid, now()
  )
  on conflict (app_code, person_id) do update set
    write_enabled = excluded.write_enabled,
    reason = excluded.reason,
    updated_by = excluded.updated_by,
    updated_at = now();

  select to_jsonb(a) into v_after
  from public.school_result_staff_write_access a
  where a.app_code = 'results' and a.person_id = p_person_id;

  insert into public.school_registry_audit(
    actor_type, actor_id, action, entity_type, entity_id, before_data, after_data, details
  ) values (
    'person', (v_auth ->> 'person_id')::uuid, 'results.staff_write_access.updated',
    'school_result_staff_write_access', p_person_id::text, v_before, v_after,
    jsonb_build_object('write_enabled', v_enabled, 'reason', v_reason)
  );

  return jsonb_build_object(
    'ok', true,
    'code', 'RESULT_STAFF_WRITE_ACCESS_UPDATED',
    'person_id', p_person_id,
    'write_enabled', public.school_result_write_enabled(p_person_id)
  );
end;
$function$;

create or replace function public.school_result_staff_write_access_bulk(
  p_session_id uuid,
  p_session_secret text,
  p_write_enabled boolean,
  p_reason text default null
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_auth jsonb;
  v_enabled boolean := coalesce(p_write_enabled, false);
  v_reason text := left(trim(coalesce(p_reason, '')), 500);
  v_removed integer := 0;
begin
  v_auth := public.school_result_authorize(p_session_id, p_session_secret, 'results.manage');
  if coalesce((v_auth ->> 'ok')::boolean, false) is not true then
    v_auth := public.school_result_authorize(p_session_id, p_session_secret, 'result_users.manage');
  end if;
  if coalesce((v_auth ->> 'ok')::boolean, false) is not true then
    v_auth := public.school_result_authorize(p_session_id, p_session_secret, 'result_settings.manage');
  end if;
  if coalesce((v_auth ->> 'ok')::boolean, false) is not true then return v_auth; end if;

  insert into public.school_result_write_policies(
    app_code, default_write_enabled, reason, updated_by, updated_at
  ) values (
    'results', v_enabled,
    nullif(v_reason, ''), (v_auth ->> 'person_id')::uuid, now()
  )
  on conflict (app_code) do update set
    default_write_enabled = excluded.default_write_enabled,
    reason = excluded.reason,
    updated_by = excluded.updated_by,
    updated_at = now();

  delete from public.school_result_staff_write_access a
  where a.app_code = 'results';
  get diagnostics v_removed = row_count;

  insert into public.school_registry_audit(
    actor_type, actor_id, action, entity_type, entity_id, after_data, details
  ) values (
    'person', (v_auth ->> 'person_id')::uuid, 'results.staff_write_access.bulk_updated',
    'school_result_write_policies', 'results',
    (select to_jsonb(p) from public.school_result_write_policies p where p.app_code = 'results'),
    jsonb_build_object('write_enabled', v_enabled, 'overrides_removed', v_removed, 'reason', v_reason)
  );

  return jsonb_build_object(
    'ok', true,
    'code', 'RESULT_STAFF_WRITE_ACCESS_BULK_UPDATED',
    'default_write_enabled', v_enabled,
    'overrides_removed', v_removed
  );
end;
$function$;

revoke all on function public.school_result_staff_write_access_read(uuid, text)
  from public, anon, authenticated;
revoke all on function public.school_result_staff_write_access_update(uuid, text, uuid, boolean, text)
  from public, anon, authenticated;
revoke all on function public.school_result_staff_write_access_bulk(uuid, text, boolean, text)
  from public, anon, authenticated;
grant execute on function public.school_result_staff_write_access_read(uuid, text)
  to anon, authenticated, service_role;
grant execute on function public.school_result_staff_write_access_update(uuid, text, uuid, boolean, text)
  to anon, authenticated, service_role;
grant execute on function public.school_result_staff_write_access_bulk(uuid, text, boolean, text)
  to anon, authenticated, service_role;
