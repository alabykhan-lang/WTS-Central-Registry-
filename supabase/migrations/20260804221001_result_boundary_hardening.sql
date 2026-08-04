-- Result boundary hardening.
-- This migration adds named permission definitions, removes browser-facing
-- legacy Result administration authority, tightens publish/unpublish scope
-- checks, and exposes a session-native workspace read adapter. It does not
-- create grants, scopes, identities, students, scores, or other production data.

insert into public.school_permission_catalog(
  permission_code, app_code, module_code, module_name, action_code, description
) values
  ('traits.enter', 'results', 'result_traits', 'Traits entry', 'create', 'Enter and update Result traits within assigned class scope.'),
  ('results.unpublish', 'results', 'result_unpublishing', 'Result unpublishing', 'publish', 'Unpublish approved Result subjects within authorised scope.'),
  ('result_users.manage', 'results', 'result_users', 'Result user administration', 'administer', 'Manage Result access through the Central Registry grant interface.'),
  ('result_settings.manage', 'results', 'result_settings', 'Result settings', 'administer', 'Manage Result settings through protected server operations.')
on conflict (permission_code) do nothing;

revoke all on table public.school_permission_catalog from public, anon, authenticated;

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
    when 'results.publish' then coalesce(p_permissions, array[]::text[]) && array['results.manage', 'results.publish', 'result_publishing.publish']::text[]
    when 'results.unpublish' then coalesce(p_permissions, array[]::text[]) && array['results.manage', 'results.unpublish']::text[]
    when 'scores.enter' then coalesce(p_permissions, array[]::text[]) && array['results.manage', 'scores.enter', 'result_entry.create', 'result_entry.edit', 'result_entry.submit']::text[]
    when 'traits.enter' then coalesce(p_permissions, array[]::text[]) && array['results.manage', 'traits.enter']::text[]
    when 'remarks.enter' then coalesce(p_permissions, array[]::text[]) && array['results.manage', 'remarks.enter', 'result_entry.edit']::text[]
    when 'results.view_assigned' then coalesce(p_permissions, array[]::text[]) && array['results.manage', 'results.view_assigned', 'result_entry.view']::text[]
    when 'results.review' then coalesce(p_permissions, array[]::text[]) && array['results.manage', 'results.review', 'result_review.review']::text[]
    when 'results.approve' then coalesce(p_permissions, array[]::text[]) && array['results.manage', 'results.approve', 'result_approval.approve']::text[]
    when 'report_cards.generate' then coalesce(p_permissions, array[]::text[]) && array['results.manage', 'report_cards.generate', 'report_cards.view']::text[]
    when 'results.export' then coalesce(p_permissions, array[]::text[]) && array['results.manage', 'results.export', 'report_cards.export']::text[]
    when 'result_users.manage' then coalesce(p_permissions, array[]::text[]) && array['results.manage', 'result_users.manage']::text[]
    when 'result_settings.manage' then coalesce(p_permissions, array[]::text[]) && array['results.manage', 'result_settings.manage']::text[]
    else coalesce(p_permissions, array[]::text[]) && array[trim(coalesce(p_required, ''))]::text[]
  end;
$function$;

revoke all on function public.school_result_permission_allowed(text[], text) from public, anon, authenticated;
grant execute on function public.school_result_permission_allowed(text[], text) to service_role;

-- The existing Result API is retained so calculations and report-card output
-- stay unchanged. Its authorization mapping is amended in place from the
-- deployed definition, with assertions so a drifted production function fails
-- this migration rather than being silently replaced incorrectly.
do $migration$
declare
  v_definition text;
begin
  select pg_get_functiondef(p.oid)
    into v_definition
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public'
    and p.proname = 'school_result_authorize'
    and pg_get_function_identity_arguments(p.oid) = 'p_session_id uuid, p_session_secret text, p_action text, p_class_key text, p_subject_index integer, p_academic_session text, p_term text';
  if v_definition is null then raise exception 'RESULT_AUTHORIZE_DEFINITION_NOT_FOUND'; end if;
  if position('results.unpublish' in v_definition) = 0 then
    v_definition := replace(
      v_definition,
      'v_requires_scope := v_action in (''scores.enter'', ''traits.enter'', ''remarks.enter'', ''results.view_assigned'', ''results.review'', ''results.approve'', ''report_cards.generate'', ''results.export'');',
      'v_requires_scope := v_action in (''scores.enter'', ''traits.enter'', ''remarks.enter'', ''results.view_assigned'', ''results.review'', ''results.approve'', ''results.publish'', ''results.unpublish'', ''report_cards.generate'', ''results.export'');'
    );
    v_definition := replace(
      v_definition,
      'if v_action in (''results.publish'', ''scores.enter'', ''traits.enter'', ''remarks.enter'') then',
      'if v_action in (''results.publish'', ''results.unpublish'', ''scores.enter'', ''traits.enter'', ''remarks.enter'') then'
    );
  end if;
  execute v_definition;
end;
$migration$;

do $migration$
declare
  v_definition text;
begin
  select pg_get_functiondef(p.oid)
    into v_definition
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public'
    and p.proname = 'school_result_api'
    and pg_get_function_identity_arguments(p.oid) = 'p_session_id uuid, p_session_secret text, p_action text, p_payload jsonb';
  if v_definition is null then raise exception 'RESULT_API_DEFINITION_NOT_FOUND'; end if;
  if position('when ''traits.enter'' then ''scores.enter''' in v_definition) > 0 then
    v_definition := replace(v_definition, 'when ''traits.enter'' then ''scores.enter''', 'when ''traits.enter'' then ''traits.enter''');
  end if;
  if position('when ''settings.read'' then ''results.manage''' in v_definition) > 0 then
    v_definition := replace(v_definition, 'when ''settings.read'' then ''results.manage''', 'when ''settings.read'' then ''result_settings.manage''');
    v_definition := replace(v_definition, 'when ''settings.update'' then ''results.manage''', 'when ''settings.update'' then ''result_settings.manage''');
  end if;
  if position('when ''results.unpublish'' then ''results.unpublish''' in v_definition) = 0 then
    v_definition := replace(v_definition, 'when ''results.publish'' then ''results.publish''', 'when ''results.publish'' then ''results.publish''
    when ''results.unpublish'' then ''results.unpublish''');
  end if;
  v_definition := replace(v_definition, 'if v_action = ''results.publish'' then', 'if v_action in (''results.publish'', ''results.unpublish'') then');
  v_definition := replace(v_definition, 'v_published := lower(coalesce(v_payload ->> ''published'', ''true'')) in (''true'', ''1'', ''yes'');', 'v_published := case when v_action = ''results.unpublish'' then false else lower(coalesce(v_payload ->> ''published'', ''true'')) in (''true'', ''1'', ''yes'') end;');
  v_definition := replace(v_definition, '  v_person_id := (v_auth ->> ''person_id'')::uuid;', E'  if v_action in (''admin.users.read'', ''admin.invite.read'', ''admin.role.update'', ''admin.user.delete'', ''admin.invite.rotate'') then\n    return jsonb_build_object(''ok'', false, ''code'', ''RESULT_LEGACY_ADMINISTRATION_RETIRED'');\n  end if;\n\n  v_person_id := (v_auth ->> ''person_id'')::uuid;');
  if position('when ''traits.enter'' then ''traits.enter''' in v_definition) = 0 then raise exception 'RESULT_API_TRAITS_MAPPING_NOT_UPDATED'; end if;
  execute v_definition;
end;
$migration$;

-- Legacy Result profile roles, invite rotation, and self-registration are no
-- longer authority sources. The old API routes are retired in the client and
-- these database guards make the retained compatibility code fail closed.
create or replace function public.result_legacy_mutation_guard()
returns trigger
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
begin
  raise exception using errcode = '42501', message = 'RESULT_LEGACY_ADMINISTRATION_RETIRED';
end;
$function$;

revoke all on function public.result_legacy_mutation_guard() from public, anon, authenticated;
grant execute on function public.result_legacy_mutation_guard() to service_role;

drop trigger if exists result_legacy_role_mutation_guard on public.user_profiles;
create trigger result_legacy_role_mutation_guard
before update of role on public.user_profiles
for each row execute function public.result_legacy_mutation_guard();

drop trigger if exists result_legacy_invite_mutation_guard on public.invite_codes;
create trigger result_legacy_invite_mutation_guard
before insert or update or delete on public.invite_codes
for each row execute function public.result_legacy_mutation_guard();

-- Retire the browser-facing client-code workspace adapter. The server-side
-- session adapter below is the only workspace read contract.
revoke all on function public.school_staff_workspace_read_api(text, text) from public, anon, authenticated;
grant execute on function public.school_staff_workspace_read_api(text, text) to service_role;

do $migration$
declare
  v_definition text;
begin
  select pg_get_functiondef(p.oid)
    into v_definition
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public'
    and p.proname = 'school_staff_workspace_read_api'
    and pg_get_function_identity_arguments(p.oid) = 'p_client_code text, p_client_secret text';
  if v_definition is null then raise exception 'WORKSPACE_READ_DEFINITION_NOT_FOUND'; end if;
  v_definition := replace(v_definition, 'school_staff_workspace_read_api(p_client_code text, p_client_secret text)', 'school_staff_workspace_read_session_api(p_session_id uuid, p_session_secret text)');
  v_definition := replace(v_definition, 'v_person_id uuid;', E'v_session jsonb;\n  v_person_id uuid;');
  v_definition := replace(v_definition, 'v_person_id:=public.school_identity_current_staff_session(p_client_code,p_client_secret);', E'v_session:=public.school_identity_session_validate(p_session_id,p_session_secret,''staff_self_service'');\n  if coalesce((v_session ->> ''ok'')::boolean,false) is not true then return v_session; end if;\n  v_person_id:=(v_session ->> ''person_id'')::uuid;');
  v_definition := replace(v_definition, '''legacy_grant''', '''active_grant''');
  execute v_definition;
end;
$migration$;

revoke all on function public.school_staff_workspace_read_session_api(uuid, text) from public, anon, authenticated;
grant execute on function public.school_staff_workspace_read_session_api(uuid, text) to service_role;
