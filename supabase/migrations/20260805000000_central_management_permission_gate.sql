-- Restore the existing primary Central Registry administrator's canonical
-- management permission and expose a server-side Result visibility check.
-- This migration does not create identities, roles, scopes or academic data.

create or replace function public.school_result_central_management_access(
  p_session_id uuid,
  p_session_secret text
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_session jsonb;
  v_person_id uuid;
  v_allowed boolean;
begin
  v_session := public.school_identity_session_validate(p_session_id, p_session_secret, 'results');
  if coalesce((v_session ->> 'ok')::boolean, false) is not true then
    return v_session;
  end if;

  v_person_id := (v_session ->> 'person_id')::uuid;
  select exists (
    select 1
    from public.school_access_grants g
    where g.person_id = v_person_id
      and g.app_code = 'central_registry'
      and g.grant_status = 'active'
      and (g.valid_from is null or g.valid_from <= now())
      and (g.valid_until is null or g.valid_until > now())
      and coalesce(g.permissions, array[]::text[]) && array[
        'central_registry.administer',
        'staff_management.administer',
        'system_administration.administer'
      ]::text[]
  ) into v_allowed;

  return jsonb_build_object(
    'ok', true,
    'code', 'RESULT_CENTRAL_MANAGEMENT_ACCESS_CHECKED',
    'central_registry_management_allowed', v_allowed
  );
end;
$function$;

revoke all on function public.school_result_central_management_access(uuid, text)
  from public, authenticated;
grant execute on function public.school_result_central_management_access(uuid, text)
  to anon;

do $migration$
declare
  v_person_id uuid;
  v_grant_id uuid;
  v_before jsonb;
  v_after jsonb;
  v_request_id uuid := gen_random_uuid();
  v_primary_admin_count integer;
begin
  select count(*) into v_primary_admin_count
  from public.school_access_grants g
  where g.app_code = 'central_registry'
    and g.grant_status = 'active'
    and coalesce((g.metadata ->> 'primary_registry_admin')::boolean, false) = true;

  if v_primary_admin_count <> 1 then
    raise exception 'Expected exactly one active primary Central Registry administrator grant, found %', v_primary_admin_count;
  end if;

  select g.person_id, g.id, to_jsonb(g)
    into v_person_id, v_grant_id, v_before
  from public.school_access_grants g
  where g.app_code = 'central_registry'
    and g.grant_status = 'active'
    and coalesce((g.metadata ->> 'primary_registry_admin')::boolean, false) = true;

  if not (coalesce(v_before -> 'permissions', '[]'::jsonb) ? 'central_registry.administer') then
    update public.school_access_grants as g
    set permissions = (
      select array_agg(permission order by permission)
      from (
        select distinct permission
        from unnest(coalesce(g.permissions, array[]::text[]) || array['central_registry.administer']::text[]) as permissions(permission)
      ) normalized
    ),
        updated_at = now()
    where g.id = v_grant_id;

    select to_jsonb(g) into v_after
    from public.school_access_grants g
    where g.id = v_grant_id;

    insert into public.school_registry_audit(
      actor_type, actor_id, action, entity_type, entity_id, request_id,
      before_data, after_data, details
    ) values (
      'production_security_correction', null,
      'central_registry.management_permission_restored',
      'school_access_grant', v_grant_id::text, v_request_id,
      v_before, v_after,
      jsonb_build_object(
        'person_id', v_person_id,
        'permission_code', 'central_registry.administer',
        'source', '20260805000000_central_management_permission_gate',
        'primary_registry_admin', true
      )
    );
  end if;
end;
$migration$;

