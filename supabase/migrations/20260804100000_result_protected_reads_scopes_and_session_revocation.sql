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
          and s.scope_type = 'subject' and s.class_key =ãMµ¶‰ËkºwµçA•}ÑåÁ”¥¸€ ±…ÍÌœ°ÍÕ‰©•Ğœ¤…¹à¹±…ÍÍ}­•äõÈ¹±…ÍÍ}­•ä…¹à¹Í½Á•}ÍÑ…ÑÕÌô…Ñ¥Ù”œ…¹€¡à¹•™™•Ñ¥Ù•}™É½´¥Ì¹Õ±°½Èà¹•™™•Ñ¥Ù•}™É½´ğõ¹½Ü ¤¤…¹€¡à¹•™™•Ñ¥Ù•}Õ¹Ñ¥°¥Ì¹Õ±°½Èà¹•™™•Ñ¥Ù•}Õ¹Ñ¥°ù¹½Ü ¤¤…¹ÁÕ‰±¥Œ¹Í¡½½±}É•ÍÕ±Ñ}Í½Á•}½¹Ñ•áÑ}µ…Ñ¡•Ì¡à¹µ•Ñ…‘…Ñ„±Ù}……‘•µ¥}Í•ÍÍ¥½¸±Ù}Ñ•É´¤¤¤€¤àì(€€€É•ÑÕÉ¸©Í½¹‰}‰Õ¥±‘}½‰©•Ğ ½¬œ°ÑÉÕ”°€½‘”œ°€IMU1Q}I5I-M}Iœ°€É½İÌœ°Ù}É½İÌ¤ì(€•¹¥˜ì((€¥˜Ù}É•Í½ÕÉ”€ô€™••ÌœÑ¡•¸(€€€Í•±•Ğ½…±•Í”¡©Í½¹‰}…œ¡Ñ½}©Í½¹ˆ¡à¤½É‘•È‰äà¹ÍÑÕ‘•¹Ñ}¥¤°€mtœèé©Í½¹ˆ¤¥¹Ñ¼Ù}É½İÌ(€€€™É½´€¡Í•±•Ğ˜¹¥±˜¹ÍÑÕ‘•¹Ñ}¥±˜¹±…ÍÍ}­•ä±˜¹Ñ½Ñ…°±˜¹Á…¥±˜¹‘•‰Ğ±˜¹¹•áÑ}Ñ•É´±˜¹É•ÍÕµ•}‘…Ñ”±˜¹Ñ•É´™É½´ÁÕ‰±¥Œ¹™••Ì˜İ¡•É”˜¹±…ÍÍ}­•äõÙ}±…ÍÍ}­•ä…¹˜¹Ñ•É´õÙ}Ñ•É´…¹€¡Ù}ÍÑÕ‘•¹Ñ}¥¥Ì¹Õ±°½È˜¹ÍÑÕ‘•¹Ñ}¥õÙ}ÍÑÕ‘•¹Ñ}¥¤…¹€¡Ù}‰É½…½È•á¥ÍÑÌ¡Í•±•Ğ€Ä™É½´ÁÕ‰±¥Œ¹Í¡½½±}ÍÑ…™™}…•ÍÍ}Í½Á•Ìàİ¡•É”à¹Á•ÉÍ½¹}¥ô¡Ù}…ÕÑ ´øøÁ•ÉÍ½¹}¥œ¤èéÕÕ¥…¹à¹…ÁÁ}½‘”ôÉ•ÍÕ±ÑÌœ…¹à¹Í½Á•}ÑåÁ”¥¸€ ±…ÍÌœ°ÍÕ‰©•Ğœ¤…¹à¹±…ÍÍ}­•äõ˜¹±…ÍÍ}­•ä…¹à¹Í½Á•}ÍÑ…ÑÕÌô…Ñ¥Ù”œ…¹€¡à¹•™™•Ñ¥Ù•}™É½´¥Ì¹Õ±°½Èà¹•™™•Ñ¥Ù•}™É½´ğõ¹½Ü ¤¤…¹€¡à¹•™™•Ñ¥Ù•}Õ¹Ñ¥°¥Ì¹Õ±°½Èà¹•™™•Ñ¥Ù•}Õ¹Ñ¥°ù¹½Ü ¤¤…¹ÁÕ‰±¥Œ¹Í¡½½±}É•ÍÕ±Ñ}Í½Á•}½¹Ñ•áÑ}µ…Ñ¡•Ì¡à¹µ•Ñ…‘…Ñ„±Ù}……‘•µ¥}Í•ÍÍ¥½¸±Ù}Ñ•É´¤¤¤€¤àì(€€€É•ÑÕÉ¸©Í½¹‰}‰Õ¥±‘}½‰©•Ğ ½¬œ°ÑÉÕ”°€½‘”œ°€IMU1Q}M}Iœ°€É½İÌœ°Ù}É½İÌ¤ì(€•¹¥˜ì((€¥˜Ù}É•Í½ÕÉ”€ô€ÁÕ‰±¥Í¡•‘}ÍÕ‰©•ÑÌœÑ¡•¸(€€€Í•±•Ğ½…±•Í”¡©Í½¹‰}…œ¡Ñ½}©Í½¹ˆ¡à¤½É‘•È‰äà¹ÍÕ‰©•Ñ}¥¹‘•à¤°€mtœèé©Í½¹ˆ¤¥¹Ñ¼Ù}É½İÌ(€€€™É½´€¡Í•±•ĞÀ¹¥±À¹±…ÍÍ}­•ä±À¹Ñ•É´±À¹ÍÕ‰©•Ñ}¥¹‘•à±À¹ÁÕ‰±¥Í¡•‘}…Ğ™É½´ÁÕ‰±¥Œ¹ÁÕ‰±¥Í¡•‘}ÍÕ‰©•ÑÌÀİ¡•É”À¹±…ÍÍ}­•äõÙ}±…ÍÍ}­•ä…¹À¹Ñ•É´õÙ}Ñ•É´…¹€¡Ù}ÍÕ‰©•Ñ}¥¹‘•à¥Ì¹Õ±°½ÈÀ¹ÍÕ‰©•Ñ}¥¹‘•àõÙ}ÍÕ‰©•Ñ}¥¹‘•à¤…¹€¡Ù}‰É½…½È•á¥ÍÑÌ¡Í•±•Ğ€Ä™É½´ÁÕ‰±¥Œ¹Í¡½½±}ÍÑ…™™}…•ÍÍ}Í½Á•Ìàİ¡•É”à¹Á•ÉÍ½¹}¥ô¡Ù}…ÕÑ ´øøÁ•ÉÍ½¹}¥œ¤èéÕÕ¥…¹à¹…ÁÁ}½‘”ôÉ•ÍÕ±ÑÌœ…¹à¹Í½Á•}ÑåÁ”ôÍÕ‰©•Ğœ…¹à¹±…ÍÍ}­•äõÀ¹±…ÍÍ}­•ä…¹à¹ÍÕ‰©•Ñ}¥¹‘•àõÀ¹ÍÕ‰©•Ñ}¥¹‘•à…¹à¹Í½Á•}ÍÑ…ÑÕÌô…Ñ¥Ù”œ…¹€¡à¹•™™•Ñ¥Ù•}™É½´¥Ì¹Õ±°½Èà¹•™™•Ñ¥Ù•}™É½´ğõ¹½Ü ¤¤…¹€¡à¹•™™•Ñ¥Ù•}Õ¹Ñ¥°¥Ì¹Õ±°½Èà¹•™™•Ñ¥Ù•}Õ¹Ñ¥°ù¹½Ü ¤¤…¹ÁÕ‰±¥Œ¹Í¡½½±}É•ÍÕ±Ñ}Í½Á•}½¹Ñ•áÑ}µ…Ñ¡•Ì¡à¹µ•Ñ…‘…Ñ„±Ù}……‘•µ¥}Í•ÍÍ¥½¸±Ù}Ñ•É´¤¤¤€¤àì(€€€É•ÑÕÉ¸©Í½¹‰}‰Õ¥±‘}½‰©•Ğ ½¬œ°ÑÉÕ”°€½‘”œ°€IMU1Q}AU	1%M!}MU	)QM}Iœ°€É½İÌœ°Ù}É½İÌ¤ì(€•¹¥˜ì((€¥˜Ù}É•Í½ÕÉ”€ô€É•ÍÕ±Ñ}ÍÕµµ…ÉäœÑ¡•¸(€€€Í•±•Ğ©Í½¹‰}‰Õ¥±‘}½‰©•Ğ ÍÑÕ‘•¹ÑÌœ°½…±•Í” ¡Í•±•Ğ©Í½¹‰}…œ¡Ñ½}©Í½¹ˆ¡Ì¤½É‘•È‰äÌ¹¹…µ”¤™É½´ÁÕ‰±¥Œ¹ÍÑÕ‘•¹ÑÌÌİ¡•É”Ì¹±…ÍÍ}­•äõÙ}±…ÍÍ}­•ä…¹¹½Ğ½…±•Í”¡Ì¹…É¡¥Ù•±™…±Í”¤…¹€¡Ù}‰É½…½È•á¥ÍÑÌ¡Í•±•Ğ€Ä™É½´ÁÕ‰±¥Œ¹Í¡½½±}ÍÑ…™™}…•ÍÍ}Í½Á•Ìàİ¡•É”à¹Á•ÉÍ½¹}¥ô¡Ù}…ÕÑ ´øøÁ•ÉÍ½¹}¥œ¤èéÕÕ¥…¹à¹…ÁÁ}½‘”ôÉ•ÍÕ±ÑÌœ…¹à¹Í½Á•}ÑåÁ”¥¸€ ±…ÍÌœ°ÍÕ‰©•Ğœ¤…¹à¹±…ÍÍ}­•äõÌ¹±…ÍÍ}­•ä…¹à¹Í½Á•}ÍÑ…ÑÕÌô…Ñ¥Ù”œ…¹ÁÕ‰±¥Œ¹Í¡½½±}É•ÍÕ±Ñ}Í½Á•}½¹Ñ•áÑ}µ…Ñ¡•Ì¡à¹µ•Ñ…‘…Ñ„±Ù}……‘•µ¥}Í•ÍÍ¥½¸±Ù}Ñ•É´¤¤¤¤°€mtœèé©Í½¹ˆ¤°€Í½É•Ìœ°½…±•Í” ¡Í•±•Ğ©Í½¹‰}…œ¡Ñ½}©Í½¹ˆ¡Ì¤¤™É½´ÁÕ‰±¥Œ¹Í½É•ÌÌİ¡•É”Ì¹±…ÍÍ}­•äõÙ}±…ÍÍ}­•ä…¹Ì¹Ñ•É´õÙ}Ñ•É´…¹€¡Ù}‰É½…½È•á¥ÍÑÌ¡Í•±•Ğ€Ä™É½´ÁÕ‰±¥Œ¹Í¡½½±}ÍÑ…™™}…•ÍÍ}Í½Á•Ìàİ¡•É”à¹Á•ÉÍ½¹}¥ô¡Ù}…ÕÑ ´øøÁ•ÉÍ½¹}¥œ¤èéÕÕ¥…¹à¹…ÁÁ}½‘”ôÉ•ÍÕ±ÑÌœ…¹à¹Í½Á•}ÑåÁ”ôÍÕ‰©•Ğœ…¹à¹±…ÍÍ}­•äõÌ¹±…ÍÍ}­•ä…¹à¹ÍÕ‰©•Ñ}¥¹‘•àõÌ¹ÍÕ‰©•Ñ}¥¹‘•à…¹à¹Í½Á•}ÍÑ…ÑÕÌô…Ñ¥Ù”œ…¹ÁÕ‰±¥Œ¹Í¡½½±}É•ÍÕ±Ñ}Í½Á•}½¹Ñ•áÑ}µ…Ñ¡•Ì¡à¹µ•Ñ…‘…Ñ„±Ù}……‘•µ¥}Í•ÍÍ¥½¸±Ù}Ñ•É´¤¤¤¤°€mtœèé©Í½¹ˆ¤¤¥¹Ñ¼Ù}É½İÌì(€€€É•ÑÕÉ¸©Í½¹‰}‰Õ¥±‘}½‰©•Ğ ½¬œ°ÑÉÕ”°€½‘”œ°€IMU1Q}MU55Ie}Iœ°€ÍÕµµ…Éäœ°Ù}É½İÌ¤ì(€•¹¥˜ì((€¥˜Ù}É•Í½ÕÉ”€ô€É•Á½ÉÑ}…ÉœÑ¡•¸(€€€É•ÑÕÉ¸©Í½¹‰}‰Õ¥±‘}½‰©•Ğ ½¬œ°ÑÉÕ”°€½‘”œ°€IMU1Q}IA=IQ}I}Iœ°€ÍÑÕ‘•¹Ñ}¥œ°Ù}ÍÑÕ‘•¹Ñ}¥°€±…ÍÍ}­•äœ°Ù}±…ÍÍ}­•ä°€Ñ•É´œ°Ù}Ñ•É´°€……‘•µ¥}Í•ÍÍ¥½¸œ°Ù}……‘•µ¥}Í•ÍÍ¥½¸¤ì(€•¹¥˜ì((€É•ÑÕÉ¸©Í½¹‰}‰Õ¥±‘}½‰©•Ğ ½¬œ°™…±Í”°€½‘”œ°€IMU1Q}I}IM=UI}9=Q}11=]œ¤ì)•¹ì(‘™Õ¹Ñ¥½¸ì()É•Ù½­”…±°½¸™Õ¹Ñ¥½¸ÁÕ‰±¥Œ¹Í¡½½±}É•ÍÕ±Ñ}É•…‘}…Á¤¡ÕÕ¥°Ñ•áĞ°Ñ•áĞ°©Í½¹ˆ¤™É½´ÁÕ‰±¥Œ°…¹½¸°…ÕÑ¡•¹Ñ¥…Ñ•ì)É…¹Ğ•á•ÕÑ”½¸™Õ¹Ñ¥½¸ÁÕ‰±¥Œ¹Í¡½½±}É•ÍÕ±Ñ}É•…‘}…Á¤¡ÕÕ¥°Ñ•áĞ°Ñ•áĞ°©Í½¹ˆ¤Ñ¼Í•ÉÙ¥•}É½±”ì()É•…Ñ”½ÈÉ•Á±…”™Õ¹Ñ¥½¸ÁÕ‰±¥Œ¹Í¡½½±}É•ÍÕ±Ñ}ÑÉ…¥ÑÍ}ÕÁ‘…Ñ” (€Á}Í•ÍÍ¥½¹}¥ÕÕ¥°(€Á}Í•ÍÍ¥½¹}Í•É•ĞÑ•áĞ°(€Á}ÍÑÕ‘•¹Ñ}¥ÕÕ¥°(€Á}±…ÍÍ}­•äÑ•áĞ°(€Á}Ñ•É´Ñ•áĞ°(€Á}……‘•µ¥}Í•ÍÍ¥½¸Ñ•áĞ°(€Á}ÑÉ…¥Ñ}ÑåÁ”Ñ•áĞ°(€Á}ÑÉ…¥Ñ}¹…µ”Ñ•áĞ°(€Á}É…Ñ¥¹œ¥¹Ñ••È(¤)É•ÑÕÉ¹Ì©Í½¹ˆ)±…¹Õ…”Á±ÁÍÅ°)Í•ÕÉ¥Ñä‘•™¥¹•È)Í•ĞÍ•…É¡}Á…Ñ Ñ¼€Á}…Ñ…±½œœ°€•áÑ•¹Í¥½¹Ìœ°€ÁÕ‰±¥Œœ)…Ì€‘™Õ¹Ñ¥½¸)‘•±…É”(€Ù}…ÕÑ ©Í½¹ˆì(€Ù}Á•ÉÍ½¹}¥ÕÕ¥ì)‰•¥¸(€Ù}…ÕÑ €èôÁÕ‰±¥Œ¹Í¡½½±}É•ÍÕ±Ñ}…ÕÑ¡½É¥é”¡Á}Í•ÍÍ¥½¹}¥±Á}Í•ÍÍ¥½¹}Í•É•Ğ°ÑÉ…¥ÑÌ¹•¹Ñ•Èœ±Á}±…ÍÍ}­•ä±¹Õ±°±Á}……‘•µ¥}Í•ÍÍ¥½¸±Á}Ñ•É´¤ì(€¥˜½…±•Í” ¡Ù}…ÕÑ ´øø½¬œ¤èé‰½½±•…¸±™…±Í”¤¥Ì¹½ĞÑÉÕ”Ñ¡•¸É•ÑÕÉ¸Ù}…ÕÑ ì•¹¥˜ì(€¥˜Á}ÍÑÕ‘•¹Ñ}¥¥Ì¹Õ±°½È¹Õ±±¥˜¡ÑÉ¥´¡½…±•Í”¡Á}±…ÍÍ}­•ä°œœ¤¤°œœ¤¥Ì¹Õ±°½È¹Õ±±¥˜¡ÑÉ¥´¡½…±•Í”¡Á}Ñ•É´°œœ¤¤°œœ¤¥Ì¹Õ±°(€€€€½È±½İ•È¡ÑÉ¥´¡½…±•Í”¡Á}ÑÉ…¥Ñ}ÑåÁ”°œœ¤¤¤¹½Ğ¥¸€ …™™•Ñ¥Ù”œ°ÁÍå¡½µ½Ñ½Èœ¤(€€€€½È¹Õ±±¥˜¡ÑÉ¥´¡½…±•Í”¡Á}ÑÉ…¥Ñ}¹…µ”°œœ¤¤°œœ¤¥Ì¹Õ±°½ÈÁ}É…Ñ¥¹œ¥Ì¹Õ±°½ÈÁ}É…Ñ¥¹œğÀ½ÈÁ}É…Ñ¥¹œøÔÑ¡•¸(€€€É•ÑÕÉ¸©Í½¹‰}‰Õ¥±‘}½‰©•Ğ ½¬œ±™…±Í”°½‘”œ°IMU1Q}QI%Q}Ae1=}%9Y1%œ¤ì(€•¹¥˜ì(€¥˜¹½Ğ•á¥ÍÑÌ¡Í•±•Ğ€Ä™É½´ÁÕ‰±¥Œ¹ÍÑÕ‘•¹ÑÌÌİ¡•É”Ì¹¥õÁ}ÍÑÕ‘•¹Ñ}¥…¹Ì¹±…ÍÍ}­•äõÑÉ¥´¡Á}±…ÍÍ}­•ä¤…¹¹½Ğ½…±•Í”¡Ì¹…É¡¥Ù•±™…±Í”¤¤Ñ¡•¸(€€€É•ÑÕÉ¸©Í½¹‰}‰Õ¥±‘}½‰©•Ğ ½¬œ±™…±Í”°½‘”œ°IMU1Q}MQU9Q}1MM}5%M5Q œ¤ì(€•¹¥˜ì(€Ù}Á•ÉÍ½¹}¥€èô€¡Ù}…ÕÑ ´øøÁ•ÉÍ½¹}¥œ¤èéÕÕ¥ì(€¥¹Í•ÉĞ¥¹Ñ¼ÁÕ‰±¥Œ¹ÑÉ…¥ÑÌ¡ÍÑÕ‘•¹Ñ}¥±±…ÍÍ}­•ä±ÑÉ…¥Ñ}ÑåÁ”±ÑÉ…¥Ñ}¹…µ”±É…Ñ¥¹œ±Ñ•É´¤(€Ù…±Õ•Ì¡Á}ÍÑÕ‘•¹Ñ}¥±ÑÉ¥´¡Á}±…ÍÍ}­•ä¤±±½İ•È¡ÑÉ¥´¡Á}ÑÉ…¥Ñ}ÑåÁ”¤¤±ÑÉ¥´¡Á}ÑÉ…¥Ñ}¹…µ”¤±Á}É…Ñ¥¹œ±ÑÉ¥´¡Á}Ñ•É´¤¤(€½¸½¹™±¥Ğ¡ÍÑÕ‘•¹Ñ}¥±ÑÉ…¥Ñ}ÑåÁ”±ÑÉ…¥Ñ}¹…µ”±Ñ•É´¤‘¼ÕÁ‘…Ñ”Í•Ğ±…ÍÍ}­•äõ•á±Õ‘•¹±…ÍÍ}­•ä±É…Ñ¥¹œõ•á±Õ‘•¹É…Ñ¥¹œì(€¥¹Í•ÉĞ¥¹Ñ¼ÁÕ‰±¥Œ¹Í¡½½±}É•¥ÍÑÉå}…Õ‘¥Ğ¡…Ñ½É}ÑåÁ”±…Ñ½É}¥±…Ñ¥½¸±•¹Ñ¥Ñå}ÑåÁ”±•¹Ñ¥Ñå}¥±‘•Ñ…¥±Ì¤(€Ù…±Õ•Ì É•ÍÕ±Ñ}Í•ÍÍ¥½¸œ±Ù}Á•ÉÍ½¹}¥èéÑ•áĞ°É•ÍÕ±Ğ¹ÑÉ…¥Ğ¹ÕÁÍ•ÉÑ•œ°ÑÉ…¥ÑÌœ±Á}ÍÑÕ‘•¹Ñ}¥èéÑ•áĞ±©Í½¹‰}‰Õ¥±‘}½‰©•Ğ ±…ÍÍ}­•äœ±ÑÉ¥´¡Á}±…ÍÍ}­•ä¤°Ñ•É´œ±ÑÉ¥´¡Á}Ñ•É´¤°ÑÉ…¥Ñ}ÑåÁ”œ±±½İ•È¡ÑÉ¥´¡Á}ÑÉ…¥Ñ}ÑåÁ”¤¤°ÑÉ…¥Ñ}¹…µ”œ±ÑÉ¥´¡Á}ÑÉ…¥Ñ}¹…µ”¤¤¤ì(€É•ÑÕÉ¸©Í½¹‰}‰Õ¥±‘}½‰©•Ğ ½¬œ±ÑÉÕ”°½‘”œ°IMU1Q}QI%Q}MYœ°ÍÑÕ‘•¹Ñ}¥œ±Á}ÍÑÕ‘•¹Ñ}¥°Ñ•É´œ±ÑÉ¥´¡Á}Ñ•É´¤¤ì)•¹ì(‘™Õ¹Ñ¥½¸ì()É•Ù½­”…±°½¸™Õ¹Ñ¥½¸ÁÕ‰±¥Œ¹Í¡½½±}É•ÍÕ±Ñ}ÑÉ…¥ÑÍ}ÕÁ‘…Ñ”¡ÕÕ¥±Ñ•áĞ±ÕÕ¥±Ñ•áĞ±Ñ•áĞ±Ñ•áĞ±Ñ•áĞ±Ñ•áĞ±¥¹Ñ••È¤™É½´ÁÕ‰±¥Œ°…¹½¸°…ÕÑ¡•¹Ñ¥…Ñ•ì)É…¹Ğ•á•ÕÑ”½¸™Õ¹Ñ¥½¸ÁÕ‰±¥Œ¹Í¡½½±}É•ÍÕ±Ñ}ÑÉ…¥ÑÍ}ÕÁ‘…Ñ”¡ÕÕ¥±Ñ•áĞ±ÕÕ¥±Ñ•áĞ±Ñ•áĞ±Ñ•áĞ±Ñ•áĞ±Ñ•áĞ±¥¹Ñ••È¤Ñ¼Í•ÉÙ¥•}É½±”ì()É•…Ñ”½ÈÉ•Á±…”™Õ¹Ñ¥½¸ÁÕ‰±¥Œ¹Í¡½½±}É•ÍÕ±Ñ}É•µ…É­Í}ÕÁ‘…Ñ” (€Á}Í•ÍÍ¥½¹}¥ÕÕ¥°(€Á}Í•ÍÍ¥½¹}Í•É•ĞÑ•áĞ°(€Á}ÍÑÕ‘•¹Ñ}¥ÕÕ¥°(€Á}±…ÍÍ}­•äÑ•áĞ°(€Á}Ñ•É´Ñ•áĞ°(€Á}……‘•µ¥}Í•ÍÍ¥½¸Ñ•áĞ°(€Á}……‘•µ¥ŒÑ•áĞ‘•™…Õ±Ğ¹Õ±°°(€Á}™½Éµ}µ…ÍÑ•ÈÑ•áĞ‘•™…Õ±Ğ¹Õ±°°(€Á}ÁÉ¥¹¥Á…°Ñ•áĞ‘•™…Õ±Ğ¹Õ±°°(€Á}‘…åÍ}½Á•¹•¥¹Ñ••È‘•™…Õ±Ğ¹Õ±°°(€Á}‘…åÍ}ÁÉ•Í•¹Ğ¥¹Ñ••È‘•™…Õ±Ğ¹Õ±°(¤)É•ÑÕÉ¹Ì©Í½¹ˆ)±…¹Õ…”Á±ÁÍÅ°)Í•ÕÉ¥Ñä‘•™¥¹•È)Í•ĞÍ•…É¡}Á…Ñ Ñ¼€Á}…Ñ…±½œœ°€•áÑ•¹Í¥½¹Ìœ°€ÁÕ‰±¥Œœ)…Ì€‘™Õ¹Ñ¥½¸)‘•±…É”(€Ù}…ÕÑ ©Í½¹ˆì(€Ù}Á•ÉÍ½¹}¥ÕÕ¥ì)‰•¥¸(€Ù}…ÕÑ €èôÁÕ‰±¥Œ¹Í¡½½±}É•ÍÕ±Ñ}…ÕÑ¡½É¥é”¡Á}Í•ÍÍ¥½¹}¥±Á}Í•ÍÍ¥½¹}Í•É•Ğ°É•µ…É­Ì¹•¹Ñ•Èœ±Á}±…ÍÍ}­•ä±¹Õ±°±Á}……‘•µ¥}Í•ÍÍ¥½¸±Á}Ñ•É´¤ì(€¥˜½…±•Í” ¡Ù}…ÕÑ ´øø½¬œ¤èé‰½½±•…¸±™…±Í”¤¥Ì¹½ĞÑÉÕ”Ñ¡•¸É•ÑÕÉ¸Ù}…ÕÑ ì•¹¥˜ì(€¥˜Á}ÍÑÕ‘•¹Ñ}¥¥Ì¹Õ±°½È¹Õ±±¥˜¡ÑÉ¥´¡½…±•Í”¡Á}±…ÍÍ}­•ä°œœ¤¤°œœ¤¥Ì¹Õ±°½È¹Õ±±¥˜¡ÑÉ¥´¡½…±•Í”¡Á}Ñ•É´°œœ¤¤°œœ¤¥Ì¹Õ±°(€€€€½È€¡Á}‘…åÍ}½Á•¹•¥Ì¹½Ğ¹Õ±°…¹Á}‘…åÍ}½Á•¹•ğÀ¤½È€¡Á}‘…åÍ}ÁÉ•Í•¹Ğ¥Ì¹½Ğ¹Õ±°…¹Á}‘…åÍ}ÁÉ•Í•¹ĞğÀ¤(€€€€½È€¡Á}‘…åÍ}½Á•¹•¥Ì¹½Ğ¹Õ±°…¹Á}‘…åÍ}ÁÉ•Í•¹Ğ¥Ì¹½Ğ¹Õ±°…¹Á}‘…åÍ}ÁÉ•Í•¹ĞùÁ}‘…åÍ}½Á•¹•¤Ñ¡•¸(€€€É•ÑÕÉ¸©Í½¹‰}‰Õ¥±‘}½‰©•Ğ ½¬œ±™…±Í”°½‘”œ°IMU1Q}I5I-}Ae1=}%9Y1%œ¤ì(€•¹¥˜ì(€¥˜¹½Ğ•á¥ÍÑÌ¡Í•±•Ğ€Ä™É½´ÁÕ‰±¥Œ¹ÍÑÕ‘•¹ÑÌÌİ¡•É”Ì¹¥õÁ}ÍÑÕ‘•¹Ñ}¥…¹Ì¹±…ÍÍ}­•äõÑÉ¥´¡Á}±…ÍÍ}­•ä¤…¹¹½Ğ½…±•Í”¡Ì¹…É¡¥Ù•±™…±Í”¤¤Ñ¡•¸(€€€É•ÑÕÉ¸©Í½¹‰}‰Õ¥±‘}½‰©•Ğ ½¬œ±™…±Í”°½‘”œ°IMU1Q}MQU9Q}1MM}5%M5Q œ¤ì(€•¹¥˜ì(€Ù}Á•ÉÍ½¹}¥€èô€¡Ù}…ÕÑ ´øøÁ•ÉÍ½¹}¥œ¤èéÕÕ¥ì(€¥¹Í•ÉĞ¥¹Ñ¼ÁÕ‰±¥Œ¹É•µ…É­Ì¡ÍÑÕ‘•¹Ñ}¥±±…ÍÍ}­•ä±……‘•µ¥Œ±™½Éµ}µ…ÍÑ•È±ÁÉ¥¹¥Á…°±‘…åÍ}½Á•¹•±‘…åÍ}ÁÉ•Í•¹Ğ±Ñ•É´¤(€Ù…±Õ•Ì¡Á}ÍÑÕ‘•¹Ñ}¥±ÑÉ¥´¡Á}±…ÍÍ}­•ä¤±Á}……‘•µ¥Œ±Á}™½Éµ}µ…ÍÑ•È±Á}ÁÉ¥¹¥Á…°±Á}‘…åÍ}½Á•¹•±Á}‘…åÍ}ÁÉ•Í•¹Ğ±ÑÉ¥´¡Á}Ñ•É´¤¤(€½¸½¹™±¥Ğ¡ÍÑÕ‘•¹Ñ}¥±Ñ•É´¤‘¼ÕÁ‘…Ñ”Í•Ğ±…ÍÍ}­•äõ•á±Õ‘•¹±…ÍÍ}­•ä±……‘•µ¥Œõ•á±Õ‘•¹……‘•µ¥Œ±™½Éµ}µ…ÍÑ•Èõ•á±Õ‘•¹™½Éµ}µ…ÍÑ•È±ÁÉ¥¹¥Á…°õ•á±Õ‘•¹ÁÉ¥¹¥Á…°±‘…åÍ}½Á•¹•õ•á±Õ‘•¹‘…åÍ}½Á•¹•±‘…åÍ}ÁÉ•Í•¹Ğõ•á±Õ‘•¹‘…åÍ}ÁÉ•Í•¹Ğì(€¥¹Í•ÉĞ¥¹Ñ¼ÁÕ‰±¥Œ¹Í¡½½±}É•¥ÍÑÉå}…Õ‘¥Ğ¡…Ñ½É}ÑåÁ”±…Ñ½É}¥±…Ñ¥½¸±•¹Ñ¥Ñå}ÑåÁ”±•¹Ñ¥Ñå}¥±‘•Ñ…¥±Ì¤(€Ù…±Õ•Ì É•ÍÕ±Ñ}Í•ÍÍ¥½¸œ±Ù}Á•ÉÍ½¹}¥èéÑ•áĞ°É•ÍÕ±Ğ¹É•µ…É­Ì¹ÕÁÍ•ÉÑ•œ°É•µ…É­Ìœ±Á}ÍÑÕ‘•¹Ñ}¥èéÑ•áĞ±©Í½¹‰}‰Õ¥±‘}½‰©•Ğ ±…ÍÍ}­•äœ±ÑÉ¥´¡Á}±…ÍÍ}­•ä¤°Ñ•É´œ±ÑÉ¥´¡Á}Ñ•É´¤¤¤ì(€É•ÑÕÉ¸©Í½¹‰}‰Õ¥±‘}½‰©•Ğ ½¬œ±ÑÉÕ”°½‘”œ°IMU1Q}I5I-M}MYœ°ÍÑÕ‘•¹Ñ}¥œ±Á}ÍÑÕ‘•¹Ñ}¥°Ñ•É´œ±ÑÉ¥´¡Á}Ñ•É´¤¤ì)•¹ì(‘™Õ¹Ñ¥½¸ì()É•Ù½­”…±°½¸™Õ¹Ñ¥½¸ÁÕ‰±¥Œ¹Í¡½½±}É•ÍÕ±Ñ}É•µ…É­Í}ÕÁ‘…Ñ”¡ÕÕ¥±Ñ•áĞ±ÕÕ¥±Ñ•áĞ±Ñ•áĞ±Ñ•áĞ±Ñ•áĞ±Ñ•áĞ±Ñ•áĞ±¥¹Ñ••È±¥¹Ñ••È¤™É½´ÁÕ‰±¥Œ°…¹½¸°…ÕÑ¡•¹Ñ¥…Ñ•ì)É…¹Ğ•á•ÕÑ”½¸™Õ¹Ñ¥½¸ÁÕ‰±¥Œ¹Í¡½½±}É•ÍÕ±Ñ}É•µ…É­Í}ÕÁ‘…Ñ”¡ÕÕ¥±Ñ•áĞ±ÕÕ¥±Ñ•áĞ±Ñ•áĞ±Ñ•áĞ±Ñ•áĞ±Ñ•áĞ±Ñ•áĞ±¥¹Ñ••È±¥¹Ñ••È¤Ñ¼Í•ÉÙ¥•}É½±”ì((´´½¹Ñ•áĞµ…İ…É”I•ÍÕ±ĞÍ½Á”İÉ¥Ñ”ÕÍ•‰äÑ¡”•á¥ÍÑ¥¹œ•¹ÑÉ…°I•¥ÍÑÉäU$¸(´´Q¡”±•…ä…•ÍÌµµ…¹…•µ•¹ĞIAÉ•µ…¥¹Ì…Ù…¥±…‰±”‘ÕÉ¥¹œÑ¡”ÑÉ…¹Í¥Ñ¥½¸ì(´´Ñ¡¥ÌÕ…É‘•Ù…É¥…¹Ğ¥ÌÑ¡”½¹”ÕÍ•™½ÈI•ÍÕ±Ğ±…ÍÌ½ÍÕ‰©•Ğ…ÍÍ¥¹µ•¹ÑÌ¸)É•…Ñ”½ÈÉ•Á±…”™Õ¹Ñ¥½¸ÁÕ‰±¥Œ¹Í¡½½±}…•ÍÍ}µ…¹…•µ•¹Ñ}Í½Á•}İÉ¥Ñ•}…Á¤ (€Á}±¥•¹Ñ}½‘”Ñ•áĞ°(€Á}±¥•¹Ñ}Í•É•ĞÑ•áĞ°(€Á}Á…å±½…©Í½¹ˆ‘•™…Õ±Ğ€íôœèé©Í½¹ˆ(¤)É•ÑÕÉ¹Ì©Í½¹ˆ)±…¹Õ…”Á±ÁÍÅ°)Í•ÕÉ¥Ñä‘•™¥¹•È)Í•ĞÍ•…É¡}Á…Ñ Ñ¼€Á}…Ñ…±½œœ°€•áÑ•¹Í¥½¹Ìœ°€ÁÕ‰±¥Œœ)…Ì€‘™Õ¹Ñ¥½¸)‘•±…É”(€Ù}±¥•¹Ñ}¥ÕÕ¥ì(€Ù}…Ñ½É}Á•ÉÍ½¹}¥ÕÕ¥ì(€Ù}ÍÑ…™™}¥ÕÕ¥ì(€Ù}Á•ÉÍ½¹}¥ÕÕ¥ì(€Ù}¥ÕÕ¥ì(€Ù}É•ÅÕ•ÍÑ}¥ÕÕ¥€èô•¹}É…¹‘½µ}ÕÕ¥ ¤ì(€Ù}Í½Á•}ÑåÁ”Ñ•áĞ€èôÑÉ¥´¡½…±•Í”¡Á}Á…å±½…€´øø€Í½Á•QåÁ”œ°€œœ¤¤ì(€Ù}±…ÍÍ}­•äÑ•áĞ€èôÑÉ¥´¡½…±•Í”¡Á}Á…å±½…€´øø€±…ÍÍ-•äœ°€œœ¤¤ì(€Ù}…ÁÁ}½‘”Ñ•áĞ€èôÑÉ¥´¡½…±•Í”¡Á}Á…å±½…€´øø€…ÁÁ½‘”œ°€É•ÍÕ±ÑÌœ¤¤ì(€Ù}É•…Í½¸Ñ•áĞ€èô¹Õ±±¥˜¡ÑÉ¥´¡½…±•Í”¡Á}Á…å±½…€´øø€É•…Í½¸œ°€œœ¤¤°€œœ¤ì(€Ù}……‘•µ¥}Í•ÍÍ¥½¸Ñ•áĞ€èô¹Õ±±¥˜¡ÑÉ¥´¡½…±•Í”¡Á}Á…å±½…€´øø€……‘•µ¥M•ÍÍ¥½¸œ°€œœ¤¤°€œœ¤ì(€Ù}Ñ•É´Ñ•áĞ€èô¹Õ±±¥˜¡ÑÉ¥´¡½…±•Í”¡Á}Á…å±½…€´øø€Ñ•É´œ°€œœ¤¤°€œœ¤ì(€Ù}ÍÕ‰©•Ñ}¥¹‘•à¥¹Ñ••Èì(€Ù}•¹…‰±•‰½½±•…¸€èô½…±•Í” ¡Á}Á…å±½…€´øø€•¹…‰±•œ¤èé‰½½±•…¸°™…±Í”¤ì(€Ù}™É½´Ñ¥µ•ÍÑ…µÁÑè€èô¹½Ü ¤ì(€Ù}Õ¹Ñ¥°Ñ¥µ•ÍÑ…µÁÑèì(€Ù}‰•™½É”©Í½¹ˆì(€Ù}…™Ñ•È©Í½¹ˆì)‰•¥¸(€Ù}±¥•¹Ñ}¥€èôÁÕ‰±¥Œ¹Í¡½½±}É•¥ÍÑÉå}Ù•É¥™å}…‘µ¥¸¡Á}±¥•¹Ñ}½‘”°Á}±¥•¹Ñ}Í•É•Ğ°€…•ÍÌ¹µ…¹…”œ¤ì(€¥˜Ù}±¥•¹Ñ}¥¥Ì¹Õ±°Ñ¡•¸É•ÑÕÉ¸©Í½¹‰}‰Õ¥±‘}½‰©•Ğ ½¬œ°™…±Í”°€½‘”œ°€5959Q}MM}9%œ¤ì•¹¥˜ì(€Í•±•Ğ•¹ÑÉ…±}Á•ÉÍ½¹}¥¥¹Ñ¼Ù}…Ñ½É}Á•ÉÍ½¹}¥™É½´ÁÕ‰±¥Œ¹…ÑÑ•¹‘…¹•}…‘µ¥¹}±¥•¹ÑÌİ¡•É”¥õÙ}±¥•¹Ñ}¥ì(€‰•¥¸(€€€Ù}ÍÑ…™™}¥€èô€¡Á}Á…å±½…€´øø€ÍÑ…™™%œ¤èéÕÕ¥ì(€€€Ù}ÍÕ‰©•Ñ}¥¹‘•à€èô¹Õ±±¥˜¡Á}Á…å±½…€´øø€ÍÕ‰©•Ñ%¹‘•àœ°€œœ¤èé¥¹Ñ••Èì(€€€Ù}™É½´€èô½…±•Í”¡¹Õ±±¥˜¡Á}Á…å±½…€´øø€•™™•Ñ¥Ù•É½´œ°€œœ¤èéÑ¥µ•ÍÑ…µÁÑè°¹½Ü ¤¤ì(€€€Ù}Õ¹Ñ¥°€èô¹Õ±±¥˜¡Á}Á…å±½…€´øø€•áÁ¥É•ÍĞœ°€œœ¤èéÑ¥µ•ÍÑ…µÁÑèì(€•á•ÁÑ¥½¸İ¡•¸½Ñ¡•ÉÌÑ¡•¸É•ÑÕÉ¸©Í½¹‰}‰Õ¥±‘}½‰©•Ğ ½¬œ°™…±Í”°€½‘”œ°€%9Y1%}M=A}=I}Qœ¤ì•¹ì(€Í•±•Ğ•¹ÑÉ…±}Á•ÉÍ½¹}¥¥¹Ñ¼Ù}Á•ÉÍ½¹}¥™É½´ÁÕ‰±¥Œ¹ÍÑ…™™}…ÑÑ•¹‘…¹•}ÁÉ½™¥±•Ìİ¡•É”¥õÙ}ÍÑ…™™}¥ì(€¥˜Ù}Á•ÉÍ½¹}¥¥Ì¹Õ±°Ñ¡•¸É•ÑÕÉ¸©Í½¹‰}‰Õ¥±‘}½‰©•Ğ ½¬œ°™…±Í”°€½‘”œ°€MQ}%9Q%Qe}9=Q}1%9-œ¤ì•¹¥˜ì(€¥˜Ù}…ÁÁ}½‘”€ğø€É•ÍÕ±ÑÌœ½ÈÙ}Í½Á•}ÑåÁ”¹½Ğ¥¸€ ±…ÍÌœ°ÍÕ‰©•Ğœ¤Ñ¡•¸É•ÑÕÉ¸©Í½¹‰}‰Õ¥±‘}½‰©•Ğ ½¬œ°™…±Í”°€½‘”œ°€U9MUAA=IQ}M=Aœ¤ì•¹¥˜ì(€¥˜¹½Ğ•á¥ÍÑÌ¡Í•±•Ğ€Ä™É½´ÁÕ‰±¥Œ¹Í¡½½±}±…ÍÍ•Ìİ¡•É”±…ÍÍ}­•äõÙ}±…ÍÍ}­•ä…¹¥Í}…Ñ¥Ù”¤Ñ¡•¸É•ÑÕÉ¸©Í½¹‰}‰Õ¥±‘}½‰©•Ğ ½¬œ°™…±Í”°€½‘”œ°€Q%Y}1MM}9=Q}=U9œ¤ì•¹¥˜ì(€¥˜Ù}Í½Á•}ÑåÁ”ô±…ÍÌœÑ¡•¸Ù}ÍÕ‰©•Ñ}¥¹‘•àèõ¹Õ±°ì•±Í¥˜¹½Ğ•á¥ÍÑÌ¡Í•±•Ğ€Ä™É½´ÁÕ‰±¥Œ¹É•ÍÕ±Ñ}ÍÕ‰©•Ñ}…Ñ…±½œİ¡•É”±…ÍÍ}­•äõÙ}±…ÍÍ}­•ä…¹ÍÕ‰©•Ñ}¥¹‘•àõÙ}ÍÕ‰©•Ñ}¥¹‘•à…¹…Ñ¥Ù”¤Ñ¡•¸É•ÑÕÉ¸©Í½¹‰}‰Õ¥±‘}½‰©•Ğ ½¬œ°™…±Í”°€½‘”œ°€Q%Y}IMU1Q}MU	)Q}9=Q}=U9œ¤ì•¹¥˜ì(€¥˜Ù}•¹…‰±•…¹€¡Ù}……‘•µ¥}Í•ÍÍ¥½¸¥Ì¹Õ±°½ÈÙ}Ñ•É´¥Ì¹Õ±°¤Ñ¡•¸É•ÑÕÉ¸©Í½¹‰}‰Õ¥±‘}½‰©•Ğ ½¬œ°™…±Í”°€½‘”œ°€IMU1Q}M=A}=9QaQ}IEU%Iœ¤ì•¹¥˜ì(€¥˜Ù}Õ¹Ñ¥°¥Ì¹½Ğ¹Õ±°…¹Ù}Õ¹Ñ¥°€ğôÙ}™É½´Ñ¡•¸É•ÑÕÉ¸©Í½¹‰}‰Õ¥±‘}½‰©•Ğ ½¬œ°™…±Í”°€½‘”œ°€aA%Ie}5UMQ}=11=]}Q%Y}Qœ¤ì•¹¥˜ì(€Í•±•Ğ¥±Ñ½}©Í½¹ˆ¡Ì¤¥¹Ñ¼Ù}¥±Ù}‰•™½É”™É½´ÁÕ‰±¥Œ¹Í¡½½±}ÍÑ…™™}…•ÍÍ}Í½Á•ÌÌİ¡•É”Ì¹Á•ÉÍ½¹}¥õÙ}Á•ÉÍ½¹}¥…¹Ì¹…ÁÁ}½‘”õÙ}…ÁÁ}½‘”…¹Ì¹Í½Á•}ÑåÁ”õÙ}Í½Á•}ÑåÁ”…¹Ì¹±…ÍÍ}­•äõÙ}±…ÍÍ}­•ä…¹Ì¹ÍÕ‰©•Ñ}¥¹‘•à¥Ì¹½Ğ‘¥ÍÑ¥¹Ğ™É½´Ù}ÍÕ‰©•Ñ}¥¹‘•àì(€¥˜Ù}¥¥Ì¹Õ±°…¹¹½ĞÙ}•¹…‰±•Ñ¡•¸É•ÑÕÉ¸©Í½¹‰}‰Õ¥±‘}½‰©•Ğ ½¬œ°ÑÉÕ”°€½‘”œ°€M=A}1Ie}9=Q}MM%9œ°€É•ÅÕ•ÍÑ}¥œ°Ù}É•ÅÕ•ÍÑ}¥¤ì•¹¥˜ì(€¥˜Ù}¥¥Ì¹Õ±°Ñ¡•¸(€€€¥¹Í•ÉĞ¥¹Ñ¼ÁÕ‰±¥Œ¹Í¡½½±}ÍÑ…™™}…•ÍÍ}Í½Á•Ì¡Á•ÉÍ½¹}¥±…ÁÁ}½‘”±Í½Á•}ÑåÁ”±±…ÍÍ}­•ä±ÍÕ‰©•Ñ}¥¹‘•à±Í½Á•}ÍÑ…ÑÕÌ±•™™•Ñ¥Ù•}™É½´±•™™•Ñ¥Ù•}Õ¹Ñ¥°±…ÍÍ¥¹•‘}‰å}Á•ÉÍ½¹}¥±…ÍÍ¥¹•‘}…Ğ±É•…Í½¸±µ•Ñ…‘…Ñ„¤(€€€Ù…±Õ•Ì¡Ù}Á•ÉÍ½¹}¥±Ù}…ÁÁ}½‘”±Ù}Í½Á•}ÑåÁ”±Ù}±…ÍÍ}­•ä±Ù}ÍÕ‰©•Ñ}¥¹‘•à°…Ñ¥Ù”œ±Ù}™É½´±Ù}Õ¹Ñ¥°±Ù}…Ñ½É}Á•ÉÍ½¹}¥±¹½Ü ¤±Ù}É•…Í½¸±©Í½¹‰}‰Õ¥±‘}½‰©•Ğ µ…¹…•‘}™É½´œ°•¹ÑÉ…±}É•¥ÍÑÉå}…•ÍÍ}µ…¹…•µ•¹Ğœ°ÍÑ…™™}¥œ±Ù}ÍÑ…™™}¥°……‘•µ¥}Í•ÍÍ¥½¸œ±Ù}……‘•µ¥}Í•ÍÍ¥½¸°Ñ•É´œ±Ù}Ñ•É´¤¤É•ÑÕÉ¹¥¹œ¥¥¹Ñ¼Ù}¥ì(€•±Í”(€€€ÕÁ‘…Ñ”ÁÕ‰±¥Œ¹Í¡½½±}ÍÑ…™™}…•ÍÍ}Í½Á•ÌÍ•ĞÍ½Á•}ÍÑ…ÑÕÌõ…Í”İ¡•¸Ù}•¹…‰±•Ñ¡•¸€…Ñ¥Ù”œ•±Í”€É•Ù½­•œ•¹±•™™•Ñ¥Ù•}™É½´õ…Í”İ¡•¸Ù}•¹…‰±•Ñ¡•¸Ù}™É½´•±Í”•™™•Ñ¥Ù•}™É½´•¹±•™™•Ñ¥Ù•}Õ¹Ñ¥°õ…Í”İ¡•¸Ù}•¹…‰±•Ñ¡•¸Ù}Õ¹Ñ¥°•±Í”¹½Ü ¤•¹±…ÍÍ¥¹•‘}‰å}Á•ÉÍ½¹}¥õ…Í”İ¡•¸Ù}•¹…‰±•Ñ¡•¸Ù}…Ñ½É}Á•ÉÍ½¹}¥•±Í”…ÍÍ¥¹•‘}‰å}Á•ÉÍ½¹}¥•¹±…ÍÍ¥¹•‘}…Ğõ…Í”İ¡•¸Ù}•¹…‰±•Ñ¡•¸¹½Ü ¤•±Í”…ÍÍ¥¹•‘}…Ğ•¹±É•Ù½­•‘}‰å}Á•ÉÍ½¹}¥õ…Í”İ¡•¸Ù}•¹…‰±•Ñ¡•¸¹Õ±°•±Í”Ù}…Ñ½É}Á•ÉÍ½¹}¥•¹±É•Ù½­•‘}…Ğõ…Í”İ¡•¸Ù}•¹…‰±•Ñ¡•¸¹Õ±°•±Í”¹½Ü ¤•¹±É•Ù½…Ñ¥½¹}É•…Í½¸õ…Í”İ¡•¸Ù}•¹…‰±•Ñ¡•¸¹Õ±°•±Í”½…±•Í”¡Ù}É•…Í½¸°M½Á”É•Ù½­•Ñ¡É½Õ •¹ÑÉ…°I•¥ÍÑÉä…•ÍÌµ…¹…•µ•¹Ğœ¤•¹±É•…Í½¸õÙ}É•…Í½¸±µ•Ñ…‘…Ñ„õ…Í”İ¡•¸Ù}•¹…‰±•Ñ¡•¸µ•Ñ…‘…Ñ…ññ©Í½¹‰}‰Õ¥±‘}½‰©•Ğ ……‘•µ¥}Í•ÍÍ¥½¸œ±Ù}……‘•µ¥}Í•ÍÍ¥½¸°Ñ•É´œ±Ù}Ñ•É´¤•±Í”µ•Ñ…‘…Ñ„•¹±ÕÁ‘…Ñ•‘}…Ğõ¹½Ü ¤İ¡•É”¥õÙ}¥ì(€•¹¥˜ì(€Í•±•ĞÑ½}©Í½¹ˆ¡Ì¤¥¹Ñ¼Ù}…™Ñ•È™É½´ÁÕ‰±¥Œ¹Í¡½½±}ÍÑ…™™}…•ÍÍ}Í½Á•ÌÌİ¡•É”Ì¹¥õÙ}¥ì(€¥¹Í•ÉĞ¥¹Ñ¼ÁÕ‰±¥Œ¹Í¡½½±}É•¥ÍÑÉå}…Õ‘¥Ğ¡…Ñ½É}ÑåÁ”±…Ñ½É}¥±…Ñ¥½¸±•¹Ñ¥Ñå}ÑåÁ”±•¹Ñ¥Ñå}¥±É•ÅÕ•ÍÑ}¥±‰•™½É•}‘…Ñ„±…™Ñ•É}‘…Ñ„±‘•Ñ…¥±Ì¤(€Ù…±Õ•Ì Á•ÉÍ½¸œ±Ù}…Ñ½É}Á•ÉÍ½¹}¥èéÑ•áĞ±…Í”İ¡•¸Ù}•¹…‰±•Ñ¡•¸€ÍÑ…™™}…•ÍÌ¹Í½Á•}…ÍÍ¥¹•œ•±Í”€ÍÑ…™™}…•ÍÌ¹Í½Á•}É•Ù½­•œ•¹°Í¡½½±}ÍÑ…™™}…•ÍÍ}Í½Á”œ±Ù}¥èéÑ•áĞ±Ù}É•ÅÕ•ÍÑ}¥±Ù}‰•™½É”±Ù}…™Ñ•È±©Í½¹‰}‰Õ¥±‘}½‰©•Ğ ÍÑ…™™}¥œ±Ù}ÍÑ…™™}¥°Á•ÉÍ½¹}¥œ±Ù}Á•ÉÍ½¹}¥°…ÁÁ}½‘”œ±Ù}…ÁÁ}½‘”°Í½Á•}ÑåÁ”œ±Ù}Í½Á•}ÑåÁ”°±…ÍÍ}­•äœ±Ù}±…ÍÍ}­•ä°ÍÕ‰©•Ñ}¥¹‘•àœ±Ù}ÍÕ‰©•Ñ}¥¹‘•à°……‘•µ¥}Í•ÍÍ¥½¸œ±Ù}……‘•µ¥}Í•ÍÍ¥½¸°Ñ•É´œ±Ù}Ñ•É´¤¤ì(€É•ÑÕÉ¸©Í½¹‰}‰Õ¥±‘}½‰©•Ğ ½¬œ±ÑÉÕ”°½‘”œ±…Í”İ¡•¸Ù}•¹…‰±•Ñ¡•¸€M=A}MM%9œ•±Í”€M=A}IY=-œ•¹°É•ÅÕ•ÍÑ}¥œ±Ù}É•ÅÕ•ÍÑ}¥¤ì)•¹ì(‘™Õ¹Ñ¥½¸ì()É•Ù½­”…±°½¸™Õ¹Ñ¥½¸ÁÕ‰±¥Œ¹Í¡½½±}…•ÍÍ}µ…¹…•µ•¹Ñ}Í½Á•}İÉ¥Ñ•}…Á¤¡Ñ•áĞ°Ñ•áĞ°©Í½¹ˆ¤™É½´ÁÕ‰±¥Œì)É…¹Ğ•á•ÕÑ”½¸™Õ¹Ñ¥½¸ÁÕ‰±¥Œ¹Í¡½½±}…•ÍÍ}µ…¹…•µ•¹Ñ}Í½Á•}İÉ¥Ñ•}…Á¤¡Ñ•áĞ°Ñ•áĞ°©Í½¹ˆ¤Ñ¼…¹½¸ì