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
    and (g.vali