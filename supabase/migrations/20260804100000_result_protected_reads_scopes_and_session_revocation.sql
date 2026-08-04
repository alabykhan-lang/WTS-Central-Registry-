-- WTS Result protected reads, context-aware scopes and identity-session revocation.
--
-- This migration adds guarded read access and tightens the existing access
-- management structures. It does not create people, staff, credentials,
-- grants, scopes, students, scores or other operational records.

create or replace function public.school_result_scope_context_matches(
  p_metadata jsonb,
  p_academic_session text default null,
  p_term text default null
)
returns boolean
language sql
immutable
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
  select
    (
      nullif(trim(coalesce(p_academic_session, '')), '') is null
      or nullif(trim(coalesce(p_metadata ->> 'academic_session', '')), '') is null
      or trim(p_metadata ->> 'academic_session') = trim(p_academic_session)
    )
    and (
      nullif(trim(coalesce(p_term, '')), '') is null
      or nullif(trim(coalesce(p_metadata ->> 'term', '')), '') is null
      or trim(p_metadata ->> 'term') = trim(p_term)
    );
$function$;

revoke all on function public.school_result_scope_context_matches(jsonb, text, text) from public, anon, authenticated;

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
    when 'results.publish' then coalesce(p_permissions, array[]::text[]) && array['results.publish', 'result_publishing.publish']::text[]
    when 'scores.enter' then coalesce(p_permissions, array[]::text[]) && array['scores.enter', 'result_entry.create', 'result_entry.edit', 'result_entry.submit']::text[]
    when 'traits.enter' then coalesce(p_permissions, array[]::text[]) && array['scores.enter', 'result_entry.create', 'result_entry.edit', 'result_entry.submit']::text[]
    when 'remarks.enter' then coalesce(p_permissions, array[]::text[]) && array['remarks.enter', 'result_entry.edit']::text[]
    when 'results.view_assigned' then coalesce(p_permissions, array[]::text[]) && array['results.view_assigned', 'result_entry.view']::text[]
    when 'results.review' then coalesce(p_permissions, array[]::text[]) && array['results.review', 'result_review.review']::text[]
    when 'results.approve' then coalesce(p_permissions, array[]::text[]) && array['results.approve', 'result_approval.approve']::text[]
    when 'report_cards.generate' then coalesce(p_permissions, array[]::text[]) && array['report_cards.generate', 'report_cards.view']::text[]
    when 'results.export' then coalesce(p_permissions, array[]::text[]) && array['results.export', 'report_cards.export']::text[]
    else trim(coalesce(p_required, '')) = any(coalesce(p_permissions, array[]::text[]))
  end;
$function$;

revoke all on function public.school_result_permission_allowed(text[], text) from public, anon, authenticated;

-- New identity sessions are invalidated as soon as the underlying credential
-- or account is suspended/reset. The validator below also performs the same
-- checks on every request, so expiry and revocation cannot be bypassed by a
-- stale cookie.
create or replace function wts_internal.revoke_identity_sessions(
  p_person_id uuid,
  p_reason text
)
returns integer
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_count integer;
begin
  update public.school_identity_sessions
  set revoked_at = coalesce(revoked_at, now()),
      revocation_reason = coalesce(nullif(trim(p_reason), ''), 'IDENTITY_STATE_CHANGED'),
      last_seen_at = now()
  where person_id = p_person_id
    and revoked_at is null;
  get diagnostics v_count = row_count;
  return v_count;
end;
$function$;

revoke all on function wts_internal.revoke_identity_sessions(uuid, text) from public, anon, authenticated;

create or replace function wts_internal.revoke_sessions_after_credential_change()
returns trigger
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
begin
  if tg_op = 'INSERT'
     or new.credential_status <> 'active'
     or new.must_change_password
     or (tg_op = 'UPDATE' and old.password_hash is distinct from new.password_hash) then
    perform wts_internal.revoke_identity_sessions(new.person_id, 'IDENTITY_CREDENTIAL_CHANGED');
  end if;
  return new;
end;
$function$;

revoke all on function wts_internal.revoke_sessions_after_credential_change() from public, anon, authenticated;
drop trigger if exists school_identity_credentials_revoke_sessions on public.school_identity_credentials;
create trigger school_identity_credentials_revoke_sessions
after insert or update of credential_status, must_change_password, password_hash
on public.school_identity_credentials
for each row execute function wts_internal.revoke_sessions_after_credential_change();

create or replace function wts_internal.revoke_sessions_after_account_change()
returns trigger
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
begin
  if new.account_status <> 'active'
     or (tg_op = 'UPDATE' and old.person_id is distinct from new.person_id) then
    perform wts_internal.revoke_identity_sessions(new.person_id, 'IDENTITY_ACCOUNT_CHANGED');
  end if;
  return new;
end;
$function$;

revoke all on function wts_internal.revoke_sessions_after_account_change() from public, anon, authenticated;
drop trigger if exists school_identity_accounts_revoke_sessions on public.school_identity_accounts;
create trigger school_identity_accounts_revoke_sessions
after insert or update of account_status, person_id
on public.school_identity_accounts
for each row execute function wts_internal.revoke_sessions_after_account_change();

create or replace function wts_internal.revoke_sessions_after_result_grant_change()
returns trigger
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
begin
  if new.app_code = 'results'
     and (
       new.grant_status <> 'active'
       or (new.valid_from is not null and new.valid_from > now())
       or (new.valid_until is not null and new.valid_until <= now())
     ) then
    perform wts_internal.revoke_identity_sessions(new.person_id, 'RESULTS_GRANT_CHANGED');
  end if;
  return new;
end;
$function$;

revoke all on function wts_internal.revoke_sessions_after_result_grant_change() from public, anon, authenticated;
drop trigger if exists school_access_grants_revoke_result_sessions on public.school_access_grants;
create trigger school_access_grants_revoke_result_sessions
after insert or update of app_code, grant_status, valid_from, valid_until, permissions
on public.school_access_grants
for each row execute function wts_internal.revoke_sessions_after_result_grant_change();

create or replace function public.school_identity_session_validate(
  p_session_id uuid,
  p_session_secret text,
  p_target_app_code text default null
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_session public.school_identity_sessions%rowtype;
  v_person public.school_people%rowtype;
  v_staff public.staff_attendance_profiles%rowtype;
  v_account public.school_identity_accounts%rowtype;
  v_credential public.school_identity_credentials%rowtype;
  v_grant public.school_access_grants%rowtype;
  v_target text;
  v_now timestamptz := now();
begin
  if p_session_id is null or coalesce(p_session_secret, '') = '' then
    return jsonb_build_object('ok', false, 'code', 'RESULT_SESSION_REQUIRED');
  end if;

  select s.* into v_session
  from public.school_identity_sessions s
  where s.id = p_session_id
    and s.revoked_at is null
  for update;

  if not found or v_session.expires_at <= v_now
     or encode(digest(p_session_secret, 'sha256'), 'hex') <> v_session.secret_hash then
    return jsonb_build_object('ok', false, 'code', 'RESULT_SESSION_NOT_ACTIVE');
  end if;

  v_target := lower(trim(coalesce(p_target_app_code, v_session.target_app_code)));
  if v_target <> v_session.target_app_code then
    return jsonb_build_object('ok', false, 'code', 'RESULT_SESSION_AUDIENCE_MISMATCH');
  end if;

  select p.* into v_person from public.school_people p where p.id = v_session.person_id;
  select s.* into v_staff from public.staff_attendance_profiles s where s.central_person_id = v_session.person_id;
  select i.* into v_account from public.school_identity_accounts i where i.id = v_session.identity_account_id;
  select c.* into v_credential from public.school_identity_credentials c
  where c.identity_account_id = v_session.identity_account_id
    and c.person_id = v_session.person_id
  order by c.created_at
  limit 1;

  if v_person.id is null or v_person.person_status <> 'active'
     or v_staff.id is null
     or v_staff.registration_status <> 'active'
     or v_staff.employment_status <> 'active'
     or v_account.id is null or v_account.account_status <> 'active'
     or v_credential.id is null or v_credential.credential_status <> 'active' then
    update public.school_identity_sessions
    set revoked_at = v_now,
        revocation_reason = case
          when v_credential.id is null or v_credential.credential_status <> 'active' then 'IDENTITY_CREDENTIAL_NOT_ACTIVE'
          else 'CENTRAL_IDENTITY_NOT_ACTIVE'
        end,
        last_seen_at = v_now
    where id = v_session.id and revoked_at is null;
    return jsonb_build_object('ok', false, 'code', case
      when v_credential.id is null or v_credential.credential_status <> 'active' then 'IDENTITY_CREDENTIAL_NOT_ACTIVE'
      else 'CENTRAL_IDENTITY_NOT_ACTIVE' end);
  end if;

  select g.* into v_grant
  from public.school_access_grants g
  where g.person_id = v_session.person_id
    and g.app_code = v_target
    and g.grant_status = 'active'
    and (g.valid_from is null or g.valid_from <= v_now)
    and (g.valid_until is null or g.valid_until > v_now)
  limit 1;

  if not found then
    update public.school_identity_sessions
    set revoked_at = v_now, revocation_reason = 'PORTAL_ACCESS_NOT_GRANTED', last_seen_at = v_now
    where id = v_session.id and revoked_at is null;
    return jsonb_build_object('ok', false, 'code', 'PORTAL_ACCESS_NOT_GRANTED');
  end if;

  update public.school_identity_sessions set last_seen_at = v_now where id = v_session.id;

  return jsonb_build_object(
    'ok', true,
    'code', 'IDENTITY_SESSION_ACTIVE',
    'session_id', v_session.id,
    'person_id', v_session.person_id,
    'identity_account_id', v_session.identity_account_id,
    'originating_app_code', v_session.originating_app_code,
    'target_app_code', v_session.target_app_code,
    'expires_at', v_session.expires_at,
    'access_role', v_grant.access_role,
    'permissions', v_grant.permissions
  );
end;
$function$;

revoke all on function public.school_identity_session_validate(uuid, text, text) from public, anon, authenticated;
grant execute on function public.school_identity_session_validate(uuid, text, text) to service_role;

-- The Result authorizer keeps class and subject scope decisions server-side.
-- Traits, remarks, fees and student administration are class-scoped; score
-- entry and subject data additionally require an explicit subject scope.
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
  v_current_session text;
  v_current_term text;
  v_requires_scope boolean := false;
  v_broad_access boolean := false;
  v_class_scope boolean := false;
  v_subject_scope boolean := false;
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
    return jsonb_build_object('ok', true, 'code', 'RESULT_AUTHORIZED',
      'person_id', v_person_id, 'identity_account_id', v_identity_account_id,
      'access_role', v_access_role, 'permissions', v_permissions,
      'result_user', v_identity -> 'result_user', 'staff', v_identity -> 'staff',
      'expires_at', v_session -> 'expires_at');
  end if;

  if not public.school_result_permission_allowed(v_permissions, v_action) then
    return jsonb_build_object('ok', false, 'code', 'RESULT_PERMISSION_DENIED', 'required_permission', v_action);
  end if;

  v_broad_access := public.school_result_permission_allowed(v_permissions, 'results.manage');
  v_requires_scope := v_action in ('scores.enter', 'traits.enter', 'remarks.enter', 'results.view_assigned', 'results.review', 'results.approve', 'report_cards.generate', 'results.export');

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

  if v_action in ('results.publish', 'scores.enter', 'traits.enter', 'remarks.enter') then
    if nullif(trim(coalesce(p_academic_session, '')), '') is null or nullif(trim(coalesce(p_term, '')), '') is null then
      return jsonb_build_object('ok', false, 'code', 'RESULT_ACADEMIC_CONTEXT_REQUIRED');
    end if;
    select value into v_current_session from public.settings where key = 'session';
    select value into v_current_term from public.settings where key = 'term';
    if v_current_session is null or v_current_term is null then return jsonb_build_object('ok', false, 'code', 'RESULT_ACADEMIC_CONTEXT_NOT_CONFIGURED'); end if;
    if trim(p_academic_session) <> v_current_session then return jsonb_build_object('ok', false, 'code', 'RESULT_ACADEMIC_SESSION_NOT_ACTIVE'); end if;
    if trim(p_term) <> v_current_term then return jsonb_build_object('ok', false, 'code', 'RESULT_TERM_NOT_ACTIVE'); end if;
  end if;

  return jsonb_build_object('ok', true, 'code', 'RESULT_AUTHORIZED',
    'person_id', v_person_id, 'identity_account_id', v_identity_account_id,
    'access_role', v_access_role, 'permissions', v_permissions,
    'result_user', v_identity -> 'result_user', 'class_scope', v_class_scope,
    'subject_scope', v_subject_scope, 'expires_at', v_session -> 'expires_at');
end;
$function$;

revoke all on function public.school_result_authorize(uuid, text, text, text, integer, text, text) from public, anon, authenticated;
grant execute on function public.school_result_authorize(uuid, text, text, text, integer, text, text) to service_role;

create or replace function public.school_result_read_api(
  p_session_id uuid,
  p_session_secret text,
  p_resource text,
  p_payload jsonb default '{}'::jsonb
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_resource text := lower(trim(coalesce(p_resource, '')));
  v_class_key text := nullif(trim(coalesce(p_payload ->> 'class_key', '')), '');
  v_student_id uuid;
  v_subject_index integer;
  v_term text := nullif(trim(coalesce(p_payload ->> 'term', '')), '');
  v_academic_session text := nullif(trim(coalesce(p_payload ->> 'academic_session', '')), '');
  v_auth jsonb;
  v_permissions text[];
  v_broad boolean;
  v_class_scope boolean;
  v_subject_scope boolean;
  v_rows jsonb;
begin
  begin
    if nullif(p_payload ->> 'student_id', '') is not null then v_student_id := (p_payload ->> 'student_id')::uuid; end if;
    if nullif(p_payload ->> 'subject_index', '') is not null then v_subject_index := (p_payload ->> 'subject_index')::integer; end if;
  exception when others then
    return jsonb_build_object('ok', false, 'code', 'RESULT_READ_FILTER_INVALID');
  end;

  if v_resource not in ('classes', 'subjects', 'students', 'scores', 'traits', 'remarks', 'fees', 'published_subjects', 'result_summary', 'report_card') then
    return jsonb_build_object('ok', false, 'code', 'RESULT_READ_RESOURCE_NOT_ALLOWED');
  end if;

  v_auth := public.school_result_authorize(p_session_id, p_session_secret, 'identity.context');
  if coalesce((v_auth ->> 'ok')::boolean, false) is not true then return v_auth; end if;
  v_permissions := coalesce(array(select jsonb_array_elements_text(v_auth -> 'permissions')), array[]::text[]);
  v_broad := public.school_result_permission_allowed(v_permissions, 'results.manage');
  if not v_broad and not public.school_result_permission_allowed(v_permissions, 'results.view_assigned') then
    return jsonb_build_object('ok', false, 'code', 'RESULT_PERMISSION_DENIED', 'required_permission', 'results.view_assigned');
  end if;

  if v_resource in ('scores', 'traits', 'remarks', 'fees', 'published_subjects', 'result_summary', 'report_card') then
    if v_class_key is null or v_term is null or v_academic_session is null then
      return jsonb_build_object('ok', false, 'code', 'RESULT_ACADEMIC_CONTEXT_REQUIRED');
    end if;
  end if;

  if v_class_key is not null and not v_broad then
    select exists(
      select 1 from public.school_staff_access_scopes s
      where s.person_id = (v_auth ->> 'person_id')::uuid and s.app_code = 'results'
        and s.scope_type in ('class', 'subject') and s.class_key = v_class_key and s.scope_status = 'active'
        and (s.effective_from is null or s.effective_from <= now())
        and (s.effective_until is null or s.effective_until > now())
        and public.school_result_scope_context_matches(s.metadata, v_academic_session, v_term)
    ) into v_class_scope;
    if not v_class_scope and v_resource not in ('classes', 'subjects') then
      return jsonb_build_object('ok', false, 'code', 'RESULT_CLASS_SCOPE_DENIED');
    end if;
  end if;

  if v_resource in ('scores', 'published_subjects', 'result_summary', 'report_card') and not v_broad then
    if v_subject_index is not null then
      select exists(
        select 1 from public.school_staff_access_scopes s
        where s.person_id = (v_auth ->> 'person_id')::uuid and s.app_code = 'results'
          and s.scope_type = 'subject' and s.class_key = v_class_key and s.subject_index = v_subject_index
          and s.scope_status = 'active' and (s.effective_from is null or s.effective_from <= now())
          and (s.effective_until is null or s.effective_until > now())
          and public.school_result_scope_context_matches(s.metadata, v_academic_session, v_term)
      ) into v_subject_scope;
      if not v_subject_scope then return jsonb_build_object('ok', false, 'code', 'RESULT_SUBJECT_SCOPE_DENIED'); end if;
    elsif not exists(
      select 1 from public.school_staff_access_scopes s
      where s.person_id = (v_auth ->> 'person_id')::uuid and s.app_code = 'results'
        and s.scope_type = 'subject' and (v_class_key is null or s.class_key = v_class_key)
        and s.scope_status = 'active' and (s.effective_from is null or s.effective_from <= now())
        and (s.effective_until is null or s.effective_until > now())
        and public.school_result_scope_context_matches(s.metadata, v_academic_session, v_term)
    ) then
      return jsonb_build_object('ok', false, 'code', 'RESULT_SUBJECT_SCOPE_REQUIRED');
    end if;
  end if;

  if v_resource = 'classes' then
    select coalesce(jsonb_agg(to_jsonb(x) order by x.sort_order, x.display_name), '[]'::jsonb) into v_rows
    from (
      select c.id, c.class_key, c.display_name, c.section, c.sort_order, c.is_active
      from public.school_classes c
      where c.is_active and (
        v_broad or exists(select 1 from public.school_staff_access_scopes s where s.person_id=(v_auth->>'person_id')::uuid and s.app_code='results' and s.class_key=c.class_key and s.scope_status='active' and (s.effective_from is null or s.effective_from<=now()) and (s.effective_until is null or s.effective_until>now()) and public.school_result_scope_context_matches(s.metadata,v_academic_session,v_term))
      )
    ) x;
    return jsonb_build_object('ok', true, 'code', 'RESULT_CLASSES_READ', 'rows', v_rows);
  end if;

  if v_resource = 'subjects' then
    select coalesce(jsonb_agg(to_jsonb(x) order by x.class_key, x.subject_index), '[]'::jsonb) into v_rows
    from (
      select r.class_key, r.subject_index, r.subject_name, r.aliases, r.active
      from public.result_subject_catalog r
      where r.active and (v_class_key is null or r.class_key=v_class_key) and (
        v_broad or exists(select 1 from public.school_staff_access_scopes s where s.person_id=(v_auth->>'person_id')::uuid and s.app_code='results' and s.scope_type='subject' and s.class_key=r.class_key and s.subject_index=r.subject_index and s.scope_status='active' and (s.effective_from is null or s.effective_from<=now()) and (s.effective_until is null or s.effective_until>now()) and public.school_result_scope_context_matches(s.metadata,v_academic_session,v_term))
      )
    ) x;
    return jsonb_build_object('ok', true, 'code', 'RESULT_SUBJECTS_READ', 'rows', v_rows);
  end if;

  if v_resource = 'students' then
    select coalesce(jsonb_agg(to_jsonb(x) order by x.name), '[]'::jsonb) into v_rows
    from (
      select s.id, s.class_key, s.name, s.gender, s.admno, s.house, s.age, s.photo, s.created_at, s.archived, s.archived_at, s.archived_reason, s.previous_class_key, s.lifecycle_status, s.admission_date, s.admission_source, s.updated_at, s.student_number_status
      from public.students s
      where coalesce(s.archived,false)=false
        and (v_class_key is null or s.class_key=v_class_key)
        and (v_student_id is null or s.id=v_student_id)
        and (v_broad or exists(select 1 from public.school_staff_access_scopes x where x.person_id=(v_auth->>'person_id')::uuid and x.app_code='results' and x.scope_type in ('class','subject') and x.class_key=s.class_key and x.scope_status='active' and (x.effective_from is null or x.effective_from<=now()) and (x.effective_until is null or x.effective_until>now()) and public.school_result_scope_context_matches(x.metadata,v_academic_session,v_term)))
    ) x;
    return jsonb_build_object('ok', true, 'code', 'RESULT_STUDENTS_READ', 'rows', v_rows);
  end if;

  if v_resource = 'scores' then
    select coalesce(jsonb_agg(to_jsonb(x) order by x.student_id, x.subject_index), '[]'::jsonb) into v_rows
    from (
      select s.id, s.student_id, s.class_key, s.subject_index, s.ca1, s.ca2, s.ca3, s.exam, s.term
      from public.scores s
      where s.class_key=v_class_key and s.term=v_term and (v_student_id is null or s.student_id=v_student_id) and (v_subject_index is null or s.subject_index=v_subject_index)
        and (v_broad or exists(select 1 from public.school_staff_access_scopes x where x.person_id=(v_auth->>'person_id')::uuid and x.app_code='results' and x.scope_type='subject' and x.class_key=s.class_key and x.subject_index=s.subject_index and x.scope_status='active' and (x.effective_from is null or x.effective_from<=now()) and (x.effective_until is null or x.effective_until>now()) and public.school_result_scope_context_matches(x.metadata,v_academic_session,v_term)))
    ) x;
    return jsonb_build_object('ok', true, 'code', 'RESULT_SCORES_READ', 'rows', v_rows);
  end if;

  if v_resource = 'traits' then
    select coalesce(jsonb_agg(to_jsonb(x) order by x.student_id, x.trait_type, x.trait_name), '[]'::jsonb) into v_rows
    from (select t.id,t.student_id,t.class_key,t.trait_type,t.trait_name,t.rating,t.term from public.traits t where t.class_key=v_class_key and t.term=v_term and (v_student_id is null or t.student_id=v_student_id) and (v_broad or exists(select 1 from public.school_staff_access_scopes x where x.person_id=(v_auth->>'person_id')::uuid and x.app_code='results' and x.scope_type in ('class','subject') and x.class_key=t.class_key and x.scope_status='active' and (x.effective_from is null or x.effective_from<=now()) and (x.effective_until is null or x.effective_until>now()) and public.school_result_scope_context_matches(x.metadata,v_academic_session,v_term))) ) x;
    return jsonb_build_object('ok', true, 'code', 'RESULT_TRAITS_READ', 'rows', v_rows);
  end if;

  if v_resource = 'remarks' then
    select coalesce(jsonb_agg(to_jsonb(x) order by x.student_id), '[]'::jsonb) into v_rows
    from (select r.id,r.student_id,r.class_key,r.academic,r.form_master,r.principal,r.days_opened,r.days_present,r.term from public.remarks r where r.class_key=v_class_key and r.term=v_term and (v_student_id is null or r.student_id=v_student_id) and (v_broad or exists(select 1 from public.school_staff_access_scopes x where x.person_id=(v_auth->>'person_id')::uuid and x.app_code='results' and x.scope_type in ('class','subject') and x.class_key=r.class_key and x.scope_status='active' and (x.effective_from is null or x.effective_from<=now()) and (x.effective_until is null or x.effective_until>now()) and public.school_result_scope_context_matches(x.metadata,v_academic_session,v_term))) ) x;
    return jsonb_build_object('ok', true, 'code', 'RESULT_REMARKS_READ', 'rows', v_rows);
  end if;

  if v_resource = 'fees' then
    select coalesce(jsonb_agg(to_jsonb(x) order by x.student_id), '[]'::jsonb) into v_rows
    from (select f.id,f.student_id,f.class_key,f.total,f.paid,f.debt,f.next_term,f.resume_date,f.term from public.fees f where f.class_key=v_class_key and f.term=v_term and (v_student_id is null or f.student_id=v_student_id) and (v_broad or exists(select 1 from public.school_staff_access_scopes x where x.person_id=(v_auth->>'person_id')::uuid and x.app_code='results' and x.scope_type in ('class','subject') and x.class_key=f.class_key and x.scope_status='active' and (x.effective_from is null or x.effective_from<=now()) and (x.effective_until is null or x.effective_until>now()) and public.school_result_scope_context_matches(x.metadata,v_academic_session,v_term))) ) x;
    return jsonb_build_object('ok', true, 'code', 'RESULT_FEES_READ', 'rows', v_rows);
  end if;

  if v_resource = 'published_subjects' then
    select coalesce(jsonb_agg(to_jsonb(x) order by x.subject_index), '[]'::jsonb) into v_rows
    from (select p.id,p.class_key,p.term,p.subject_index,p.published_at from public.published_subjects p where p.class_key=v_class_key and p.term=v_term and (v_subject_index is null or p.subject_index=v_subject_index) and (v_broad or exists(select 1 from public.school_staff_access_scopes x where x.person_id=(v_auth->>'person_id')::uuid and x.app_code='results' and x.scope_type='subject' and x.class_key=p.class_key and x.subject_index=p.subject_index and x.scope_status='active' and (x.effective_from is null or x.effective_from<=now()) and (x.effective_until is null or x.effective_until>now()) and public.school_result_scope_context_matches(x.metadata,v_academic_session,v_term))) ) x;
    return jsonb_build_object('ok', true, 'code', 'RESULT_PUBLISHED_SUBJECTS_READ', 'rows', v_rows);
  end if;

  if v_resource = 'result_summary' then
    select jsonb_build_object('students', coalesce((select jsonb_agg(to_jsonb(s) order by s.name) from public.students s where s.class_key=v_class_key and not coalesce(s.archived,false) and (v_broad or exists(select 1 from public.school_staff_access_scopes x where x.person_id=(v_auth->>'person_id')::uuid and x.app_code='results' and x.scope_type in ('class','subject') and x.class_key=s.class_key and x.scope_status='active' and public.school_result_scope_context_matches(x.metadata,v_academic_session,v_term)))), '[]'::jsonb), 'scores', coalesce((select jsonb_agg(to_jsonb(s)) from public.scores s where s.class_key=v_class_key and s.term=v_term and (v_broad or exists(select 1 from public.school_staff_access_scopes x where x.person_id=(v_auth->>'person_id')::uuid and x.app_code='results' and x.scope_type='subject' and x.class_key=s.class_key and x.subject_index=s.subject_index and x.scope_status='active' and public.school_result_scope_context_matches(x.metadata,v_academic_session,v_term)))), '[]'::jsonb)) into v_rows;
    return jsonb_build_object('ok', true, 'code', 'RESULT_SUMMARY_READ', 'summary', v_rows);
  end if;

  if v_resource = 'report_card' then
    return jsonb_build_object('ok', true, 'code', 'RESULT_REPORT_CARD_READ', 'student_id', v_student_id, 'class_key', v_class_key, 'term', v_term, 'academic_session', v_academic_session);
  end if;

  return jsonb_build_object('ok', false, 'code', 'RESULT_READ_RESOURCE_NOT_ALLOWED');
end;
$function$;

revoke all on function public.school_result_read_api(uuid, text, text, jsonb) from public, anon, authenticated;
grant execute on function public.school_result_read_api(uuid, text, text, jsonb) to service_role;

create or replace function public.school_result_traits_update(
  p_session_id uuid,
  p_session_secret text,
  p_student_id uuid,
  p_class_key text,
  p_term text,
  p_academic_session text,
  p_trait_type text,
  p_trait_name text,
  p_rating integer
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_auth jsonb;
  v_person_id uuid;
begin
  v_auth := public.school_result_authorize(p_session_id,p_session_secret,'traits.enter',p_class_key,null,p_academic_session,p_term);
  if coalesce((v_auth->>'ok')::boolean,false) is not true then return v_auth; end if;
  if p_student_id is null or nullif(trim(coalesce(p_class_key,'')),'') is null or nullif(trim(coalesce(p_term,'')),'') is null
     or lower(trim(coalesce(p_trait_type,''))) not in ('affective','psychomotor')
     or nullif(trim(coalesce(p_trait_name,'')),'') is null or p_rating is null or p_rating<0 or p_rating>5 then
    return jsonb_build_object('ok',false,'code','RESULT_TRAIT_PAYLOAD_INVALID');
  end if;
  if not exists(select 1 from public.students s where s.id=p_student_id and s.class_key=trim(p_class_key) and not coalesce(s.archived,false)) then
    return jsonb_build_object('ok',false,'code','RESULT_STUDENT_CLASS_MISMATCH');
  end if;
  v_person_id := (v_auth->>'person_id')::uuid;
  insert into public.traits(student_id,class_key,trait_type,trait_name,rating,term)
  values(p_student_id,trim(p_class_key),lower(trim(p_trait_type)),trim(p_trait_name),p_rating,trim(p_term))
  on conflict(student_id,trait_type,trait_name,term) do update set class_key=excluded.class_key,rating=excluded.rating;
  insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,details)
  values('result_session',v_person_id::text,'result.trait.upserted','traits',p_student_id::text,jsonb_build_object('class_key',trim(p_class_key),'term',trim(p_term),'trait_type',lower(trim(p_trait_type)),'trait_name',trim(p_trait_name)));
  return jsonb_build_object('ok',true,'code','RESULT_TRAIT_SAVED','student_id',p_student_id,'term',trim(p_term));
end;
$function$;

revoke all on function public.school_result_traits_update(uuid,text,uuid,text,text,text,text,text,integer) from public, anon, authenticated;
grant execute on function public.school_result_traits_update(uuid,text,uuid,text,text,text,text,text,integer) to service_role;

create or replace function public.school_result_remarks_update(
  p_session_id uuid,
  p_session_secret text,
  p_student_id uuid,
  p_class_key text,
  p_term text,
  p_academic_session text,
  p_academic text default null,
  p_form_master text default null,
  p_principal text default null,
  p_days_opened integer default null,
  p_days_present integer default null
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_auth jsonb;
  v_person_id uuid;
begin
  v_auth := public.school_result_authorize(p_session_id,p_session_secret,'remarks.enter',p_class_key,null,p_academic_session,p_term);
  if coalesce((v_auth->>'ok')::boolean,false) is not true then return v_auth; end if;
  if p_student_id is null or nullif(trim(coalesce(p_class_key,'')),'') is null or nullif(trim(coalesce(p_term,'')),'') is null
     or (p_days_opened is not null and p_days_opened<0) or (p_days_present is not null and p_days_present<0)
     or (p_days_opened is not null and p_days_present is not null and p_days_present>p_days_opened) then
    return jsonb_build_object('ok',false,'code','RESULT_REMARK_PAYLOAD_INVALID');
  end if;
  if not exists(select 1 from public.students s where s.id=p_student_id and s.class_key=trim(p_class_key) and not coalesce(s.archived,false)) then
    return jsonb_build_object('ok',false,'code','RESULT_STUDENT_CLASS_MISMATCH');
  end if;
  v_person_id := (v_auth->>'person_id')::uuid;
  insert into public.remarks(student_id,class_key,academic,form_master,principal,days_opened,days_present,term)
  values(p_student_id,trim(p_class_key),p_academic,p_form_master,p_principal,p_days_opened,p_days_present,trim(p_term))
  on conflict(student_id,term) do update set class_key=excluded.class_key,academic=excluded.academic,form_master=excluded.form_master,principal=excluded.principal,days_opened=excluded.days_opened,days_present=excluded.days_present;
  insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,details)
  values('result_session',v_person_id::text,'result.remarks.upserted','remarks',p_student_id::text,jsonb_build_object('class_key',trim(p_class_key),'term',trim(p_term)));
  return jsonb_build_object('ok',true,'code','RESULT_REMARKS_SAVED','student_id',p_student_id,'term',trim(p_term));
end;
$function$;

revoke all on function public.school_result_remarks_update(uuid,text,uuid,text,text,text,text,text,text,integer,integer) from public, anon, authenticated;
grant execute on function public.school_result_remarks_update(uuid,text,uuid,text,text,text,text,text,text,integer,integer) to service_role;

-- Context-aware Result scope write used by the existing Central Registry UI.
-- The legacy access-management RPC remains available during the transition;
-- this guarded variant is the one used for Result class/subject assignments.
create or replace function public.school_access_management_scope_write_api(
  p_client_code text,
  p_client_secret text,
  p_payload jsonb default '{}'::jsonb
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_client_id uuid;
  v_actor_person_id uuid;
  v_staff_id uuid;
  v_person_id uuid;
  v_id uuid;
  v_request_id uuid := gen_random_uuid();
  v_scope_type text := trim(coalesce(p_payload ->> 'scopeType', ''));
  v_class_key text := trim(coalesce(p_payload ->> 'classKey', ''));
  v_app_code text := trim(coalesce(p_payload ->> 'appCode', 'results'));
  v_reason text := nullif(trim(coalesce(p_payload ->> 'reason', '')), '');
  v_academic_session text := nullif(trim(coalesce(p_payload ->> 'academicSession', '')), '');
  v_term text := nullif(trim(coalesce(p_payload ->> 'term', '')), '');
  v_subject_index integer;
  v_enabled boolean := coalesce((p_payload ->> 'enabled')::boolean, false);
  v_from timestamptz := now();
  v_until timestamptz;
  v_before jsonb;
  v_after jsonb;
begin
  v_client_id := public.school_registry_verify_admin(p_client_code, p_client_secret, 'access.manage');
  if v_client_id is null then return jsonb_build_object('ok', false, 'code', 'MANAGEMENT_ACCESS_DENIED'); end if;
  select central_person_id into v_actor_person_id from public.attendance_admin_clients where id=v_client_id;
  begin
    v_staff_id := (p_payload ->> 'staffId')::uuid;
    v_subject_index := nullif(p_payload ->> 'subjectIndex', '')::integer;
    v_from := coalesce(nullif(p_payload ->> 'effectiveFrom', '')::timestamptz, now());
    v_until := nullif(p_payload ->> 'expiresAt', '')::timestamptz;
  exception when others then return jsonb_build_object('ok', false, 'code', 'INVALID_SCOPE_OR_DATE'); end;
  select central_person_id into v_person_id from public.staff_attendance_profiles where id=v_staff_id;
  if v_person_id is null then return jsonb_build_object('ok', false, 'code', 'STAFF_IDENTITY_NOT_LINKED'); end if;
  if v_app_code <> 'results' or v_scope_type not in ('class','subject') then return jsonb_build_object('ok', false, 'code', 'UNSUPPORTED_SCOPE'); end if;
  if not exists(select 1 from public.school_classes where class_key=v_class_key and is_active) then return jsonb_build_object('ok', false, 'code', 'ACTIVE_CLASS_NOT_FOUND'); end if;
  if v_scope_type='class' then v_subject_index:=null; elsif not exists(select 1 from public.result_subject_catalog where class_key=v_class_key and subject_index=v_subject_index and active) then return jsonb_build_object('ok', false, 'code', 'ACTIVE_RESULT_SUBJECT_NOT_FOUND'); end if;
  if v_enabled and (v_academic_session is null or v_term is null) then return jsonb_build_object('ok', false, 'code', 'RESULT_SCOPE_CONTEXT_REQUIRED'); end if;
  if v_until is not null and v_until <= v_from then return jsonb_build_object('ok', false, 'code', 'EXPIRY_MUST_FOLLOW_EFFECTIVE_DATE'); end if;
  select id,to_jsonb(s) into v_id,v_before from public.school_staff_access_scopes s where s.person_id=v_person_id and s.app_code=v_app_code and s.scope_type=v_scope_type and s.class_key=v_class_key and s.subject_index is not distinct from v_subject_index;
  if v_id is null and not v_enabled then return jsonb_build_object('ok', true, 'code', 'SCOPE_ALREADY_NOT_ASSIGNED', 'request_id', v_request_id); end if;
  if v_id is null then
    insert into public.school_staff_access_scopes(person_id,app_code,scope_type,class_key,subject_index,scope_status,effective_from,effective_until,assigned_by_person_id,assigned_at,reason,metadata)
    values(v_person_id,v_app_code,v_scope_type,v_class_key,v_subject_index,'active',v_from,v_until,v_actor_person_id,now(),v_reason,jsonb_build_object('managed_from','central_registry_access_management','staff_id',v_staff_id,'academic_session',v_academic_session,'term',v_term)) returning id into v_id;
  else
    update public.school_staff_access_scopes set scope_status=case when v_enabled then 'active' else 'revoked' end,effective_from=case when v_enabled then v_from else effective_from end,effective_until=case when v_enabled then v_until else now() end,assigned_by_person_id=case when v_enabled then v_actor_person_id else assigned_by_person_id end,assigned_at=case when v_enabled then now() else assigned_at end,revoked_by_person_id=case when v_enabled then null else v_actor_person_id end,revoked_at=case when v_enabled then null else now() end,revocation_reason=case when v_enabled then null else coalesce(v_reason,'Scope revoked through Central Registry access management') end,reason=v_reason,metadata=case when v_enabled then metadata||jsonb_build_object('academic_session',v_academic_session,'term',v_term) else metadata end,updated_at=now() where id=v_id;
  end if;
  select to_jsonb(s) into v_after from public.school_staff_access_scopes s where s.id=v_id;
  insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,request_id,before_data,after_data,details)
  values('person',v_actor_person_id::text,case when v_enabled then 'staff_access.scope_assigned' else 'staff_access.scope_revoked' end,'school_staff_access_scope',v_id::text,v_request_id,v_before,v_after,jsonb_build_object('staff_id',v_staff_id,'person_id',v_person_id,'app_code',v_app_code,'scope_type',v_scope_type,'class_key',v_class_key,'subject_index',v_subject_index,'academic_session',v_academic_session,'term',v_term));
  return jsonb_build_object('ok',true,'code',case when v_enabled then 'SCOPE_ASSIGNED' else 'SCOPE_REVOKED' end,'request_id',v_request_id);
end;
$function$;

revoke all on function public.school_access_management_scope_write_api(text, text, jsonb) from public;
grant execute on function public.school_access_management_scope_write_api(text, text, jsonb) to anon;
