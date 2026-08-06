-- Central Registry is the single academic-context authority for Result Portal.
-- Result keeps historical contexts available for reading, while all mutations
-- are restricted to the official current open term.

create or replace function public.school_result_settings_read(
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
  v_current jsonb;
  v_config jsonb := '{}'::jsonb;
  v_settings jsonb := '{}'::jsonb;
  v_history jsonb := '[]'::jsonb;
begin
  v_auth := public.school_result_authorize(
    p_session_id,
    p_session_secret,
    'identity.context'
  );
  if coalesce((v_auth ->> 'ok')::boolean, false) is not true then
    return v_auth;
  end if;

  v_current := public.school_academic_current();

  select coalesce(value::jsonb, '{}'::jsonb) - 'geminiKey'
    into v_config
  from public.settings
  where key = 'app_config';

  v_config := jsonb_set(
    jsonb_set(
      coalesce(v_config, '{}'::jsonb),
      '{session}',
      to_jsonb(coalesce(v_current ->> 'academic_session', '')),
      true
    ),
    '{term}',
    to_jsonb(coalesce(v_current ->> 'term', '')),
    true
  );

  select coalesce(jsonb_object_agg(key, value), '{}'::jsonb)
    into v_settings
  from public.settings
  where key in (
    'session', 'term', 'school_name', 'school_addr', 'school_phone',
    'school_email', 'card_theme', 'next_term_resumption'
  );

  v_settings := coalesce(v_settings, '{}'::jsonb) || jsonb_build_object(
    'session', coalesce(v_current ->> 'academic_session', ''),
    'term', coalesce(v_current ->> 'term', ''),
    'term_status', coalesce(v_current ->> 'term_status', 'open')
  );

  select coalesce(jsonb_agg(
    jsonb_build_object(
      'academic_session', x.academic_session,
      'term', x.term,
      'term_status', x.term_status,
      'is_current', x.is_current
    ) order by x.academic_session desc,
      case x.term when '1st Term' then 1 when '2nd Term' then 2 when '3rd Term' then 3 else 9 end
  ), '[]'::jsonb)
    into v_history
  from (
    select t.academic_session, t.term_name as term, t.term_status, t.is_current
    from public.school_academic_terms t
    union
    select h.academic_session, h.term, 'archived'::text, false
    from (
      select distinct s.academic_session, s.term from public.scores s
      union
      select distinct t.academic_session, t.term from public.traits t
      union
      select distinct r.academic_session, r.term from public.remarks r
      union
      select distinct f.academic_session, f.term from public.fees f
      union
      select distinct p.academic_session, p.term from public.published_subjects p
    ) h
    where not exists (
      select 1 from public.school_academic_terms t
      where t.academic_session = h.academic_session and t.term_name = h.term
    )
  ) x;

  return jsonb_build_object(
    'ok', true,
    'code', 'RESULT_SETTINGS_READ',
    'settings', jsonb_build_object(
      'app_config', coalesce(v_config, '{}'::jsonb),
      'safe', v_settings,
      'academic_context', jsonb_build_object(
        'academic_session', v_current ->> 'academic_session',
        'term', v_current ->> 'term',
        'term_status', v_current ->> 'term_status',
        'term_id', v_current -> 'term_id'
      ),
      'academic_history', v_history
    )
  );
end;
$function$;

revoke all on function public.school_result_settings_read(uuid, text) from public;
grant execute on function public.school_result_settings_read(uuid, text) to anon, authenticated, service_role;

create or replace function public.school_result_context_set(
  p_session_id uuid,
  p_session_secret text,
  p_class_key text,
  p_academic_session text,
  p_term text
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_auth jsonb;
  v_class_key text := nullif(trim(coalesce(p_class_key, '')), '');
  v_session text := nullif(trim(coalesce(p_academic_session, '')), '');
  v_term text := nullif(trim(coalesce(p_term, '')), '');
  v_person_id uuid;
begin
  if v_class_key is null or v_session is null or v_term is null
     or v_term not in ('1st Term', '2nd Term', '3rd Term') then
    return jsonb_build_object('ok', false, 'code', 'RESULT_CONTEXT_INVALID');
  end if;

  if not exists (
    select 1 from public.school_academic_terms t
    where t.academic_session = v_session and t.term_name = v_term
  ) and not exists (
    select 1 from public.scores s
    where s.academic_session = v_session and s.term = v_term
  ) and not exists (
    select 1 from public.traits t
    where t.academic_session = v_session and t.term = v_term
  ) and not exists (
    select 1 from public.remarks r
    where r.academic_session = v_session and r.term = v_term
  ) and not exists (
    select 1 from public.fees f
    where f.academic_session = v_session and f.term = v_term
  ) and not exists (
    select 1 from public.published_subjects p
    where p.academic_session = v_session and p.term = v_term
  ) then
    return jsonb_build_object('ok', false, 'code', 'RESULT_ACADEMIC_CONTEXT_NOT_FOUND');
  end if;

  v_auth := public.school_result_authorize(
    p_session_id,
    p_session_secret,
    'results.view_assigned',
    v_class_key,
    null,
    v_session,
    v_term
  );
  if coalesce((v_auth ->> 'ok')::boolean, false) is not true then
    return v_auth;
  end if;

  v_person_id := (v_auth ->> 'person_id')::uuid;
  insert into public.school_result_context(
    session_id, person_id, class_key, academic_session, term
  ) values (
    p_session_id, v_person_id, v_class_key, v_session, v_term
  )
  on conflict (session_id) do update set
    person_id = excluded.person_id,
    class_key = excluded.class_key,
    academic_session = excluded.academic_session,
    term = excluded.term,
    updated_at = now();

  return jsonb_build_object(
    'ok', true,
    'code', 'RESULT_CONTEXT_SET',
    'class_key', v_class_key,
    'academic_session', v_session,
    'term', v_term,
    'read_only', (v_session, v_term) is distinct from (
      (public.school_academic_current() ->> 'academic_session'),
      (public.school_academic_current() ->> 'term')
    )
  );
exception when others then
  return jsonb_build_object('ok', false, 'code', 'RESULT_CONTEXT_INVALID');
end;
$function$;

create or replace function public.school_result_authorize(
  p_session_id uuid,
  p_session_secret text,
  p_action text,
  p_class_key text default null,
  p_subject_index integer default null,
  p_academic_session text default null,
  p_term text default null
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_session jsonb;
  v_identity jsonb;
  v_person_id uuid;
  v_identity_account_id uuid;
  v_permissions text[];
  v_access_role text;
  v_action text := lower(trim(coalesce(p_action, '')));
  v_requires_scope boolean := false;
  v_broad_access boolean := false;
  v_class_scope boolean := false;
  v_subject_scope boolean := false;
  v_context_required boolean := false;
  v_current jsonb;
  v_write_gate jsonb;
begin
  v_session := public.school_identity_session_validate(p_session_id, p_session_secret, 'results');
  if coalesce((v_session ->> 'ok')::boolean, false) is not true then return v_session; end if;

  v_person_id := (v_session ->> 'person_id')::uuid;
  v_identity_account_id := (v_session ->> 'identity_account_id')::uuid;
  v_permissions := coalesce(array(select jsonb_array_elements_text(v_session -> 'permissions')), array[]::text[]);
  v_access_role := v_session ->> 'access_role';
  v_identity := public.school_result_identity_resolve(v_person_id, v_identity_account_id);
  if coalesce((v_identity ->> 'ok')::boolean, false) is not true then return v_identity; end if;

  if v_action = 'identity.context' then
    return jsonb_build_object(
      'ok', true, 'code', 'RESULT_AUTHORIZED',
      'person_id', v_person_id, 'identity_account_id', v_identity_account_id,
      'access_role', v_access_role, 'permissions', v_permissions,
      'result_user', v_identity -> 'result_user', 'staff', v_identity -> 'staff',
      'expires_at', v_session -> 'expires_at'
    );
  end if;

  if not public.school_result_permission_allowed(v_permissions, v_action) then
    return jsonb_build_object('ok', false, 'code', 'RESULT_PERMISSION_DENIED', 'required_permission', v_action);
  end if;

  v_broad_access := public.school_result_permission_allowed(v_permissions, 'results.manage');
  v_requires_scope := v_action in (
    'scores.enter', 'traits.enter', 'remarks.enter', 'results.view_assigned',
    'results.review', 'results.approve', 'results.publish', 'results.unpublish',
    'report_cards.generate', 'results.export'
  );

  if v_action = 'scores.enter' and p_subject_index is null then
    return jsonb_build_object('ok', false, 'code', 'RESULT_SUBJECT_SCOPE_REQUIRED');
  end if;

  if v_requires_scope and not v_broad_access then
    if nullif(trim(coalesce(p_class_key, '')), '') is null then
      return jsonb_build_object('ok', false, 'code', 'RESULT_CLASS_SCOPE_REQUIRED');
    end if;

    select exists(
      select 1 from public.school_staff_access_scopes s
      where s.person_id = v_person_id and s.app_code = 'results'
        and s.scope_type in ('class', 'subject') and s.class_key = trim(p_class_key)
        and s.scope_status = 'active'
        and (s.effective_from is null or s.effective_from <= now())
        and (s.effective_until is null or s.effective_until > now())
        and public.school_result_scope_context_matches(s.metadata, p_academic_session, p_term)
    ) into v_class_scope;
    if not v_class_scope then return jsonb_build_object('ok', false, 'code', 'RESULT_CLASS_SCOPE_DENIED'); end if;

    if p_subject_index is not null then
      select exists(
        select 1 from public.school_staff_access_scopes s
        where s.person_id = v_person_id and s.app_code = 'results'
          and s.scope_type = 'subject' and s.class_key = trim(p_class_key)
          and s.subject_index = p_subject_index and s.scope_status = 'active'
          and (s.effective_from is null or s.effective_from <= now())
          and (s.effective_until is null or s.effective_until > now())
          and public.school_result_scope_context_matches(s.metadata, p_academic_session, p_term)
      ) into v_subject_scope;
      if not v_subject_scope then return jsonb_build_object('ok', false, 'code', 'RESULT_SUBJECT_SCOPE_DENIED'); end if;
    end if;
  end if;

  v_context_required := v_action in (
    'results.publish', 'results.unpublish', 'scores.enter', 'traits.enter',
    'remarks.enter', 'report_cards.generate', 'results.review',
    'results.approve', 'results.export'
  ) or (v_action = 'results.manage' and nullif(trim(coalesce(p_class_key, '')), '') is not null);

  if v_context_required then
    if nullif(trim(coalesce(p_class_key, '')), '') is null
       or nullif(trim(coalesce(p_academic_session, '')), '') is null
       or nullif(trim(coalesce(p_term, '')), '') is null then
      return jsonb_build_object('ok', false, 'code', 'RESULT_ACADEMIC_CONTEXT_REQUIRED');
    end if;
    if trim(p_term) not in ('1st Term', '2nd Term', '3rd Term') then
      return jsonb_build_object('ok', false, 'code', 'RESULT_TERM_INVALID');
    end if;
    if not public.school_result_context_matches(p_session_id, trim(p_class_key), trim(p_academic_session), trim(p_term)) then
      return jsonb_build_object('ok', false, 'code', 'RESULT_CONTEXT_MISMATCH');
    end if;

    -- Historical and closed contexts remain readable, never writable.
    v_current := public.school_academic_current();
    if trim(p_academic_session) <> coalesce(v_current ->> 'academic_session', '')
       or trim(p_term) <> coalesce(v_current ->> 'term', '') then
      return jsonb_build_object(
        'ok', false,
        'code', 'RESULT_ACADEMIC_CONTEXT_READ_ONLY',
        'academic_session', v_current ->> 'academic_session',
        'term', v_current ->> 'term'
      );
    end if;
    v_write_gate := public.school_academic_term_write_gate(trim(p_academic_session), trim(p_term));
    if coalesce((v_write_gate ->> 'ok')::boolean, false) is not true then
      return jsonb_build_object(
        'ok', false,
        'code', 'RESULT_ACADEMIC_TERM_READ_ONLY',
        'term_status', v_write_gate ->> 'term_status'
      );
    end if;
  end if;

  return jsonb_build_object(
    'ok', true, 'code', 'RESULT_AUTHORIZED',
    'person_id', v_person_id, 'identity_account_id', v_identity_account_id,
    'access_role', v_access_role, 'permissions', v_permissions,
    'result_user', v_identity -> 'result_user', 'class_scope', v_class_scope,
    'subject_scope', v_subject_scope, 'expires_at', v_session -> 'expires_at'
  );
end;
$function$;

revoke all on function public.school_result_context_set(uuid, text, text, text, text) from public;
grant execute on function public.school_result_context_set(uuid, text, text, text, text) to anon, authenticated, service_role;
revoke all on function public.school_result_authorize(uuid, text, text, text, integer, text, text) from public;
grant execute on function public.school_result_authorize(uuid, text, text, text, integer, text, text) to anon, authenticated, service_role;
