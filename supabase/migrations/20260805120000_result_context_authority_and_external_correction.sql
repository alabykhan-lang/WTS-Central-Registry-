-- Authoritative Result context and protected score correction contract.
-- settings.term is a default only; an explicitly selected session/term is authoritative.
-- This migration is data-preserving: it adds context columns/backfills the configured
-- session and replaces ambiguous active-record keys without changing score values.

alter table public.scores add column if not exists academic_session text;
alter table public.traits add column if not exists academic_session text;
alter table public.remarks add column if not exists academic_session text;
alter table public.fees add column if not exists academic_session text;
alter table public.published_subjects add column if not exists academic_session text;

do $$
declare v_session text; v_table text;
begin
  select nullif(trim(value),'') into v_session from public.settings where key='session' limit 1;
  if v_session is null then raise exception 'RESULT_SESSION_CONFIGURATION_MISSING'; end if;
  foreach v_table in array array['scores','traits','remarks','fees','published_subjects'] loop
    execute format('update public.%I set academic_session=$1 where academic_session is null',v_table) using v_session;
    execute format('alter table public.%I alter column academic_session set default %L',v_table,v_session);
    execute format('alter table public.%I alter column academic_session set not null',v_table);
  end loop;
end $$;

alter table public.school_result_score_audit add column if not exists correction_reason text;
alter table public.school_result_score_audit add column if not exists audit_metadata jsonb;

alter table public.scores drop constraint if exists scores_student_subject_term_key;
alter table public.traits drop constraint if exists traits_student_type_name_term_key;
alter table public.traits drop constraint if exists traits_upsert_key;
alter table public.remarks drop constraint if exists remarks_student_term_key;
alter table public.remarks drop constraint if exists remarks_upsert_key;
alter table public.fees drop constraint if exists fees_student_term_key;
alter table public.fees drop constraint if exists fees_upsert_key;
alter table public.published_subjects drop constraint if exists published_subjects_class_key_term_subject_index_key;

create unique index if not exists scores_context_unique_idx on public.scores(student_id,class_key,subject_index,academic_session,term);
create unique index if not exists traits_context_unique_idx on public.traits(student_id,class_key,trait_type,trait_name,academic_session,term);
create unique index if not exists remarks_context_unique_idx on public.remarks(student_id,class_key,academic_session,term);
create unique index if not exists fees_context_unique_idx on public.fees(student_id,class_key,academic_session,term);
create unique index if not exists published_subjects_context_unique_idx on public.published_subjects(class_key,academic_session,term,subject_index);

alter table public.scores drop constraint if exists result_scores_component_range;
alter table public.scores add constraint result_scores_component_range check (
  (ca1 is null or ca1 between 0 and 100) and
  (ca2 is null or ca2 between 0 and 100) and
  (ca3 is null or ca3 between 0 and 100) and
  (exam is null or exam between 0 and 100)
);

create table if not exists public.school_result_context(
  session_id uuid primary key references public.school_identity_sessions(id) on delete cascade,
  person_id uuid not null,
  class_key text not null,
  academic_session text not null,
  term text not null check(term in ('1st Term','2nd Term','3rd Term')),
  updated_at timestamptz not null default now()
);
create index if not exists school_result_context_person_idx on public.school_result_context(person_id);
alter table public.school_result_context enable row level security;
revoke all on table public.school_result_context from public,anon,authenticated;

CREATE OR REPLACE FUNCTION public.school_result_context_matches(p_session_id uuid, p_class_key text, p_academic_session text, p_term text)
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'extensions', 'public'
AS $function$
select exists(select 1 from public.school_result_context c where c.session_id=p_session_id and c.class_key=trim(coalesce(p_class_key,'')) and c.academic_session=trim(coalesce(p_academic_session,'')) and c.term=trim(coalesce(p_term,'')));
$function$;

CREATE OR REPLACE FUNCTION public.school_result_context_set(p_session_id uuid, p_session_secret text, p_class_key text, p_academic_session text, p_term text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'extensions', 'public'
AS $function$
declare v_auth jsonb; v_class_key text:=nullif(trim(coalesce(p_class_key,'')),''); v_session text:=nullif(trim(coalesce(p_academic_session,'')),''); v_term text:=nullif(trim(coalesce(p_term,'')),''); v_person_id uuid;
begin
 if v_class_key is null or v_session is null or v_term is null or v_term not in ('1st Term','2nd Term','3rd Term') then return jsonb_build_object('ok',false,'code','RESULT_CONTEXT_INVALID'); end if;
 v_auth:=public.school_result_authorize(p_session_id,p_session_secret,'results.view_assigned',v_class_key,null,v_session,v_term);
 if coalesce((v_auth->>'ok')::boolean,false) is not true then return v_auth; end if;
 v_person_id:=(v_auth->>'person_id')::uuid;
 insert into public.school_result_context(session_id,person_id,class_key,academic_session,term) values(p_session_id,v_person_id,v_class_key,v_session,v_term)
 on conflict(session_id) do update set person_id=excluded.person_id,class_key=excluded.class_key,academic_session=excluded.academic_session,term=excluded.term,updated_at=now();
 return jsonb_build_object('ok',true,'code','RESULT_CONTEXT_SET','class_key',v_class_key,'academic_session',v_session,'term',v_term);
exception when others then return jsonb_build_object('ok',false,'code','RESULT_CONTEXT_INVALID');
end;
$function$;

CREATE OR REPLACE FUNCTION public.school_result_context_read(p_session_id uuid, p_session_secret text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'extensions', 'public'
AS $function$
declare v_session jsonb; v_context public.school_result_context%rowtype;
begin
 v_session:=public.school_identity_session_validate(p_session_id,p_session_secret,'results');
 if coalesce((v_session->>'ok')::boolean,false) is not true then return v_session; end if;
 select * into v_context from public.school_result_context where session_id=p_session_id;
 if not found then return jsonb_build_object('ok',true,'code','RESULT_CONTEXT_NOT_SET','context',null); end if;
 if v_context.person_id<>(v_session->>'person_id')::uuid then return jsonb_build_object('ok',false,'code','RESULT_CONTEXT_MISMATCH'); end if;
 return jsonb_build_object('ok',true,'code','RESULT_CONTEXT_READ','context',jsonb_build_object('class_key',v_context.class_key,'academic_session',v_context.academic_session,'term',v_context.term,'updated_at',v_context.updated_at));
end;
$function$;

CREATE OR REPLACE FUNCTION public.school_result_authorize(p_session_id uuid, p_session_secret text, p_action text, p_class_key text DEFAULT NULL::text, p_subject_index integer DEFAULT NULL::integer, p_academic_session text DEFAULT NULL::text, p_term text DEFAULT NULL::text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'extensions', 'public'
AS $function$
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
  v_requires_scope := v_action in ('scores.enter', 'traits.enter', 'remarks.enter', 'results.view_assigned', 'results.review', 'results.approve', 'results.publish', 'results.unpublish', 'report_cards.generate', 'results.export');

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

  v_context_required := v_action in ('results.publish', 'results.unpublish', 'scores.enter', 'traits.enter', 'remarks.enter', 'report_cards.generate', 'results.review', 'results.approve', 'results.export')
    or (v_action = 'results.manage' and nullif(trim(coalesce(p_class_key, '')), '') is not null);

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
  end if;

  return jsonb_build_object('ok', true, 'code', 'RESULT_AUTHORIZED',
    'person_id', v_person_id, 'identity_account_id', v_identity_account_id,
    'access_role', v_access_role, 'permissions', v_permissions,
    'result_user', v_identity -> 'result_user', 'class_scope', v_class_scope,
    'subject_scope', v_subject_scope, 'expires_at', v_session -> 'expires_at');
end;
$function$;

CREATE OR REPLACE FUNCTION public.school_result_read_api(p_session_id uuid, p_session_secret text, p_resource text, p_payload jsonb DEFAULT '{}'::jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'extensions', 'public'
AS $function$
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
    if not public.school_result_context_matches(p_session_id, v_class_key, v_academic_session, v_term) then
      return jsonb_build_object('ok', false, 'code', 'RESULT_CONTEXT_MISMATCH');
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
      where s.class_key=v_class_key and s.academic_session=v_academic_session and s.term=v_term and (v_student_id is null or s.student_id=v_student_id) and (v_subject_index is null or s.subject_index=v_subject_index)
        and (v_broad or exists(select 1 from public.school_staff_access_scopes x where x.person_id=(v_auth->>'person_id')::uuid and x.app_code='results' and x.scope_type='subject' and x.class_key=s.class_key and x.subject_index=s.subject_index and x.scope_status='active' and (x.effective_from is null or x.effective_from<=now()) and (x.effective_until is null or x.effective_until>now()) and public.school_result_scope_context_matches(x.metadata,v_academic_session,v_term)))
    ) x;
    return jsonb_build_object('ok', true, 'code', 'RESULT_SCORES_READ', 'rows', v_rows);
  end if;

  if v_resource = 'traits' then
    select coalesce(jsonb_agg(to_jsonb(x) order by x.student_id, x.trait_type, x.trait_name), '[]'::jsonb) into v_rows
    from (select t.id,t.student_id,t.class_key,t.trait_type,t.trait_name,t.rating,t.academic_session,t.term from public.traits t where t.class_key=v_class_key and t.academic_session=v_academic_session and t.term=v_term and (v_student_id is null or t.student_id=v_student_id) and (v_broad or exists(select 1 from public.school_staff_access_scopes x where x.person_id=(v_auth->>'person_id')::uuid and x.app_code='results' and x.scope_type in ('class','subject') and x.class_key=t.class_key and x.scope_status='active' and (x.effective_from is null or x.effective_from<=now()) and (x.effective_until is null or x.effective_until>now()) and public.school_result_scope_context_matches(x.metadata,v_academic_session,v_term))) ) x;
    return jsonb_build_object('ok', true, 'code', 'RESULT_TRAITS_READ', 'rows', v_rows);
  end if;

  if v_resource = 'remarks' then
    select coalesce(jsonb_agg(to_jsonb(x) order by x.student_id), '[]'::jsonb) into v_rows
    from (select r.id,r.student_id,r.class_key,r.academic,r.form_master,r.principal,r.days_opened,r.days_present,r.academic_session,r.term from public.remarks r where r.class_key=v_class_key and r.academic_session=v_academic_session and r.term=v_term and (v_student_id is null or r.student_id=v_student_id) and (v_broad or exists(select 1 from public.school_staff_access_scopes x where x.person_id=(v_auth->>'person_id')::uuid and x.app_code='results' and x.scope_type in ('class','subject') and x.class_key=r.class_key and x.scope_status='active' and (x.effective_from is null or x.effective_from<=now()) and (x.effective_until is null or x.effective_until>now()) and public.school_result_scope_context_matches(x.metadata,v_academic_session,v_term))) ) x;
    return jsonb_build_object('ok', true, 'code', 'RESULT_REMARKS_READ', 'rows', v_rows);
  end if;

  if v_resource = 'fees' then
    select coalesce(jsonb_agg(to_jsonb(x) order by x.student_id), '[]'::jsonb) into v_rows
    from (select f.id,f.student_id,f.class_key,f.total,f.paid,f.debt,f.next_term,f.resume_date,f.academic_session,f.term from public.fees f where f.class_key=v_class_key and f.academic_session=v_academic_session and f.term=v_term and (v_student_id is null or f.student_id=v_student_id) and (v_broad or exists(select 1 from public.school_staff_access_scopes x where x.person_id=(v_auth->>'person_id')::uuid and x.app_code='results' and x.scope_type in ('class','subject') and x.class_key=f.class_key and x.scope_status='active' and (x.effective_from is null or x.effective_from<=now()) and (x.effective_until is null or x.effective_until>now()) and public.school_result_scope_context_matches(x.metadata,v_academic_session,v_term))) ) x;
    return jsonb_build_object('ok', true, 'code', 'RESULT_FEES_READ', 'rows', v_rows);
  end if;

  if v_resource = 'published_subjects' then
    select coalesce(jsonb_agg(to_jsonb(x) order by x.subject_index), '[]'::jsonb) into v_rows
    from (select p.id,p.class_key,p.academic_session,p.term,p.subject_index,p.published_at from public.published_subjects p where p.class_key=v_class_key and p.academic_session=v_academic_session and p.term=v_term and (v_subject_index is null or p.subject_index=v_subject_index) and (v_broad or exists(select 1 from public.school_staff_access_scopes x where x.person_id=(v_auth->>'person_id')::uuid and x.app_code='results' and x.scope_type='subject' and x.class_key=p.class_key and x.subject_index=p.subject_index and x.scope_status='active' and (x.effective_from is null or x.effective_from<=now()) and (x.effective_until is null or x.effective_until>now()) and public.school_result_scope_context_matches(x.metadata,v_academic_session,v_term))) ) x;
    return jsonb_build_object('ok', true, 'code', 'RESULT_PUBLISHED_SUBJECTS_READ', 'rows', v_rows);
  end if;

  if v_resource = 'result_summary' then
    select jsonb_build_object('students', coalesce((select jsonb_agg(to_jsonb(s) order by s.name) from public.students s where s.class_key=v_class_key and not coalesce(s.archived,false) and (v_broad or exists(select 1 from public.school_staff_access_scopes x where x.person_id=(v_auth->>'person_id')::uuid and x.app_code='results' and x.scope_type in ('class','subject') and x.class_key=s.class_key and x.scope_status='active' and public.school_result_scope_context_matches(x.metadata,v_academic_session,v_term)))), '[]'::jsonb), 'scores', coalesce((select jsonb_agg(to_jsonb(s)) from public.scores s where s.class_key=v_class_key and s.academic_session=v_academic_session and s.term=v_term and (v_broad or exists(select 1 from public.school_staff_access_scopes x where x.person_id=(v_auth->>'person_id')::uuid and x.app_code='results' and x.scope_type='subject' and x.class_key=s.class_key and x.subject_index=s.subject_index and x.scope_status='active' and public.school_result_scope_context_matches(x.metadata,v_academic_session,v_term)))), '[]'::jsonb)) into v_rows;
    return jsonb_build_object('ok', true, 'code', 'RESULT_SUMMARY_READ', 'summary', v_rows);
  end if;

  if v_resource = 'report_card' then
    return jsonb_build_object('ok', true, 'code', 'RESULT_REPORT_CARD_READ', 'student_id', v_student_id, 'class_key', v_class_key, 'term', v_term, 'academic_session', v_academic_session);
  end if;

  return jsonb_build_object('ok', false, 'code', 'RESULT_READ_RESOURCE_NOT_ALLOWED');
end;
$function$;

CREATE OR REPLACE FUNCTION public.school_result_score_update(p_session_id uuid, p_session_secret text, p_student_id uuid, p_class_key text, p_subject_index integer, p_term text, p_academic_session text, p_ca1 numeric, p_ca2 numeric, p_ca3 numeric, p_exam numeric)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'extensions', 'public'
AS $function$
declare
  v_session jsonb;
  v_auth jsonb;
  v_person_id uuid;
  v_staff_id uuid;
  v_request_id uuid := gen_random_uuid();
  v_before jsonb;
  v_after jsonb;
  v_score_id uuid;
  v_failure_code text;
  v_action_type text;
  v_current_class text;
begin
  v_session := public.school_identity_session_validate(
    p_session_id,
    p_session_secret,
    'results'
  );
  if coalesce((v_session ->> 'ok')::boolean, false) is not true then
    return v_session;
  end if;

  v_person_id := (v_session ->> 'person_id')::uuid;
  select s.id
    into v_staff_id
  from public.staff_attendance_profiles s
  where s.central_person_id = v_person_id
  order by s.id
  limit 1;

  v_auth := public.school_result_authorize(
    p_session_id,
    p_session_secret,
    'scores.enter',
    p_class_key,
    p_subject_index,
    p_academic_session,
    p_term
  );

  if coalesce((v_auth ->> 'ok')::boolean, false) is not true then
    insert into public.school_result_score_audit(
      request_id, actor_person_id, staff_id, student_id, class_key,
      subject_index, academic_session, term, component, action_type,
      source_application, success, failure_code
    ) values (
      v_request_id, v_person_id, v_staff_id, p_student_id, p_class_key,
      p_subject_index, p_academic_session, p_term, 'score_record',
      'score_write_rejected', 'result_portal', false,
      coalesce(v_auth ->> 'code', 'RESULT_SCORE_WRITE_REJECTED')
    );

    insert into public.school_registry_audit(
      actor_type, actor_id, action, entity_type, entity_id, request_id,
      details
    ) values (
      'result_session', v_person_id::text, 'result.score.write_failed',
      'scores', p_student_id::text, v_request_id,
      jsonb_build_object(
        'staff_id', v_staff_id,
        'person_id', v_person_id,
        'class_key', p_class_key,
        'subject_index', p_subject_index,
        'academic_session', p_academic_session,
        'term', p_term,
        'source_application', 'result_portal',
        'success', false,
        'failure_code', coalesce(v_auth ->> 'code', 'RESULT_SCORE_WRITE_REJECTED')
      )
    );

    return v_auth || jsonb_build_object('request_id', v_request_id);
  end if;

  if p_student_id is null
     or nullif(trim(coalesce(p_class_key, '')), '') is null
     or p_subject_index is null
     or p_subject_index < 0
     or nullif(trim(coalesce(p_term, '')), '') is null
     or nullif(trim(coalesce(p_academic_session, '')), '') is null then
    v_failure_code := 'RESULT_SCORE_PAYLOAD_INVALID';
  elsif not exists (
    select 1
    from public.result_subject_catalog r
    where r.class_key = trim(p_class_key)
      and r.subject_index = p_subject_index
  ) then
    v_failure_code := 'RESULT_SUBJECT_NOT_ASSIGNED';
  else
    select s.class_key
      into v_current_class
    from public.students s
    where s.id = p_student_id
      and coalesce(s.archived, false) = false;

    if v_current_class is null or v_current_class <> trim(p_class_key) then
      v_failure_code := 'RESULT_STUDENT_CLASS_MISMATCH';
    elsif (p_ca1 is not null and (p_ca1 < 0 or p_ca1 > 100))
       or (p_ca2 is not null and (p_ca2 < 0 or p_ca2 > 100))
       or (p_ca3 is not null and (p_ca3 < 0 or p_ca3 > 100))
       or (p_exam is not null and (p_exam < 0 or p_exam > 100)) then
      v_failure_code := 'RESULT_SCORE_RANGE_INVALID';
    end if;
  end if;

  if v_failure_code is not null then
    insert into public.school_result_score_audit(
      request_id, actor_person_id, staff_id, student_id, class_key,
      subject_index, academic_session, term, component, action_type,
      source_application, success, failure_code
    ) values (
      v_request_id, v_person_id, v_staff_id, p_student_id, p_class_key,
      p_subject_index, p_academic_session, p_term, 'score_record',
      'score_write_rejected', 'result_portal', false, v_failure_code
    );

    insert into public.school_registry_audit(
      actor_type, actor_id, action, entity_type, entity_id, request_id,
      details
    ) values (
      'result_session', v_person_id::text, 'result.score.write_failed',
      'scores', p_student_id::text, v_request_id,
      jsonb_build_object(
        'staff_id', v_staff_id,
        'person_id', v_person_id,
        'class_key', p_class_key,
        'subject_index', p_subject_index,
        'academic_session', p_academic_session,
        'term', p_term,
        'source_application', 'result_portal',
        'success', false,
        'failure_code', v_failure_code
      )
    );

    return jsonb_build_object(
      'ok', false,
      'code', v_failure_code,
      'request_id', v_request_id
    );
  end if;

  select to_jsonb(s), s.id
    into v_before, v_score_id
  from public.scores s
  where s.student_id = p_student_id
    and s.class_key = trim(p_class_key)
    and s.subject_index = p_subject_index
    and s.academic_session = trim(p_academic_session)
    and s.term = trim(p_term)
  for update;

  begin
    insert into public.scores(
      student_id, class_key, subject_index, academic_session, term, ca1, ca2, ca3, exam
    ) values (
      p_student_id, trim(p_class_key), p_subject_index, trim(p_academic_session), trim(p_term),
      p_ca1, p_ca2, p_ca3, p_exam
    )
    on conflict (student_id, class_key, subject_index, academic_session, term) do update
    set class_key = excluded.class_key,
        ca1 = excluded.ca1,
        ca2 = excluded.ca2,
        ca3 = excluded.ca3,
        exam = excluded.exam
    returning id into v_score_id;

    select to_jsonb(s)
      into v_after
    from public.scores s
    where s.id = v_score_id;
  exception when others then
    insert into public.school_result_score_audit(
      request_id, actor_person_id, staff_id, student_id, class_key,
      subject_index, academic_session, term, component, action_type,
      old_record, source_application, success, failure_code
    ) values (
      v_request_id, v_person_id, v_staff_id, p_student_id, p_class_key,
      p_subject_index, p_academic_session, p_term, 'score_record',
      'score_write_failed', v_before, 'result_portal', false,
      'RESULT_SCORE_SAVE_FAILED'
    );

    insert into public.school_registry_audit(
      actor_type, actor_id, action, entity_type, entity_id, request_id,
      before_data, details
    ) values (
      'result_session', v_person_id::text, 'result.score.write_failed',
      'scores', coalesce(v_score_id, p_student_id)::text, v_request_id,
      v_before,
      jsonb_build_object(
        'staff_id', v_staff_id,
        'person_id', v_person_id,
        'class_key', p_class_key,
        'subject_index', p_subject_index,
        'academic_session', p_academic_session,
        'term', p_term,
        'source_application', 'result_portal',
        'success', false,
        'failure_code', 'RESULT_SCORE_SAVE_FAILED'
      )
    );

    return jsonb_build_object(
      'ok', false,
      'code', 'RESULT_SCORE_SAVE_FAILED',
      'request_id', v_request_id
    );
  end;

  v_action_type := case
    when v_before is null then 'score_entry'
    when (v_before ->> 'ca1') is distinct from (v_after ->> 'ca1')
      or (v_before ->> 'ca2') is distinct from (v_after ->> 'ca2')
      or (v_before ->> 'ca3') is distinct from (v_after ->> 'ca3')
      or (v_before ->> 'exam') is distinct from (v_after ->> 'exam')
      then 'score_correction'
    else 'score_save_confirmed'
  end;

  insert into public.school_result_score_audit(
    request_id, actor_person_id, staff_id, student_id, class_key,
    subject_index, academic_session, term, component, old_value,
    new_value, old_record, new_record, action_type, source_application,
    success, failure_code
  )
  select
    v_request_id, v_person_id, v_staff_id, p_student_id, trim(p_class_key),
    p_subject_index, trim(p_academic_session), trim(p_term), x.component,
    x.old_value, x.new_value, v_before, v_after, v_action_type,
    'result_portal', true, null
  from (
    values
      ('ca1'::text, nullif(v_before ->> 'ca1', '')::numeric, nullif(v_after ->> 'ca1', '')::numeric),
      ('ca2'::text, nullif(v_before ->> 'ca2', '')::numeric, nullif(v_after ->> 'ca2', '')::numeric),
      ('ca3'::text, nullif(v_before ->> 'ca3', '')::numeric, nullif(v_after ->> 'ca3', '')::numeric),
      ('exam'::text, nullif(v_before ->> 'exam', '')::numeric, nullif(v_after ->> 'exam', '')::numeric)
  ) as x(component, old_value, new_value);

  insert into public.school_registry_audit(
    actor_type, actor_id, action, entity_type, entity_id, request_id,
    before_data, after_data, details
  ) values (
    'result_session', v_person_id::text,
    case when v_action_type = 'score_entry'
      then 'result.score.entered'
      else 'result.score.corrected'
    end,
    'scores', v_score_id::text, v_request_id, v_before, v_after,
    jsonb_build_object(
      'staff_id', v_staff_id,
      'person_id', v_person_id,
      'student_id', p_student_id,
      'class_key', trim(p_class_key),
      'subject_index', p_subject_index,
      'academic_session', trim(p_academic_session),
      'term', trim(p_term),
      'source_application', 'result_portal',
      'success', true
    )
  );

  return jsonb_build_object(
    'ok', true,
    'code', 'RESULT_SCORE_SAVED',
    'request_id', v_request_id,
    'persisted', true,
    'student_id', p_student_id,
    'class_key', trim(p_class_key),
    'subject_index', p_subject_index,
    'term', trim(p_term),
    'academic_session', trim(p_academic_session),
    'score', jsonb_build_object(
      'id', v_after -> 'id',
      'student_id', v_after -> 'student_id',
      'class_key', v_after -> 'class_key',
      'subject_index', v_after -> 'subject_index',
      'academic_session', v_after -> 'academic_session',
      'term', v_after -> 'term',
      'ca1', v_after -> 'ca1',
      'ca2', v_after -> 'ca2',
      'ca3', v_after -> 'ca3',
      'exam', v_after -> 'exam'
    )
  );
exception when others then
  return jsonb_build_object(
    'ok', false,
    'code', 'RESULT_SCORE_SAVE_FAILED',
    'request_id', v_request_id
  );
end;
$function$;

CREATE OR REPLACE FUNCTION public.school_result_traits_update(p_session_id uuid, p_session_secret text, p_student_id uuid, p_class_key text, p_term text, p_academic_session text, p_trait_type text, p_trait_name text, p_rating integer)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'extensions', 'public'
AS $function$
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
  insert into public.traits(student_id,class_key,trait_type,trait_name,rating,academic_session,term)
  values(p_student_id,trim(p_class_key),lower(trim(p_trait_type)),trim(p_trait_name),p_rating,trim(p_academic_session),trim(p_term))
  on conflict(student_id,class_key,trait_type,trait_name,academic_session,term) do update set class_key=excluded.class_key,rating=excluded.rating;
  insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,details)
  values('result_session',v_person_id::text,'result.trait.upserted','traits',p_student_id::text,jsonb_build_object('class_key',trim(p_class_key),'term',trim(p_term),'trait_type',lower(trim(p_trait_type)),'trait_name',trim(p_trait_name)));
  return jsonb_build_object('ok',true,'code','RESULT_TRAIT_SAVED','student_id',p_student_id,'academic_session',trim(p_academic_session),'term',trim(p_term));
end;
$function$;

CREATE OR REPLACE FUNCTION public.school_result_remarks_update(p_session_id uuid, p_session_secret text, p_student_id uuid, p_class_key text, p_term text, p_academic_session text, p_academic text DEFAULT NULL::text, p_form_master text DEFAULT NULL::text, p_principal text DEFAULT NULL::text, p_days_opened integer DEFAULT NULL::integer, p_days_present integer DEFAULT NULL::integer)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'extensions', 'public'
AS $function$
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
  insert into public.remarks(student_id,class_key,academic,form_master,principal,days_opened,days_present,academic_session,term)
  values(p_student_id,trim(p_class_key),p_academic,p_form_master,p_principal,p_days_opened,p_days_present,trim(p_academic_session),trim(p_term))
  on conflict(student_id,class_key,academic_session,term) do update set class_key=excluded.class_key,academic=excluded.academic,form_master=excluded.form_master,principal=excluded.principal,days_opened=excluded.days_opened,days_present=excluded.days_present;
  insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,details)
  values('result_session',v_person_id::text,'result.remarks.upserted','remarks',p_student_id::text,jsonb_build_object('class_key',trim(p_class_key),'academic_session',trim(p_academic_session),'term',trim(p_term)));
  return jsonb_build_object('ok',true,'code','RESULT_REMARKS_SAVED','student_id',p_student_id,'academic_session',trim(p_academic_session),'term',trim(p_term));
end;
$function$;

CREATE OR REPLACE FUNCTION public.school_result_fees_update(p_session_id uuid, p_session_secret text, p_student_id uuid, p_class_key text, p_term text, p_academic_session text, p_total numeric DEFAULT NULL::numeric, p_paid numeric DEFAULT NULL::numeric, p_debt numeric DEFAULT NULL::numeric)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'extensions', 'public'
AS $function$
declare
  v_auth jsonb;
begin
  if nullif(trim(coalesce(p_class_key, '')), '') is null
     or nullif(trim(coalesce(p_term, '')), '') is null
     or nullif(trim(coalesce(p_academic_session, '')), '') is null then
    return jsonb_build_object('ok', false, 'code', 'RESULT_FEE_PAYLOAD_INVALID');
  end if;

  v_auth := public.school_result_authorize(
    p_session_id,
    p_session_secret,
    'results.manage',
    trim(p_class_key),
    null,
    trim(p_academic_session),
    trim(p_term)
  );
  if coalesce((v_auth ->> 'ok')::boolean, false) is not true then
    return v_auth;
  end if;

  if p_total is not null and p_total < 0
     or p_paid is not null and p_paid < 0
     or p_debt is not null and p_debt < 0 then
    return jsonb_build_object('ok', false, 'code', 'RESULT_FEE_VALUE_INVALID');
  end if;

  if not exists (
    select 1 from public.students s
    where s.id = p_student_id
      and s.class_key = trim(p_class_key)
      and coalesce(s.archived, false) = false
  ) then
    return jsonb_build_object('ok', false, 'code', 'RESULT_STUDENT_CLASS_MISMATCH');
  end if;

  insert into public.fees(student_id, class_key, academic_session, term, total, paid, debt)
  values (p_student_id, trim(p_class_key), trim(p_academic_session), trim(p_term), p_total, p_paid, p_debt)
  on conflict (student_id, class_key, academic_session, term) do update
  set class_key = excluded.class_key,
      total = excluded.total,
      paid = excluded.paid,
      debt = excluded.debt;

  insert into public.school_registry_audit(
    actor_type, actor_id, action, entity_type, entity_id, details
  )
  values (
    'result_session',
    v_auth ->> 'person_id',
    'result.fees.upserted',
    'fees',
    p_student_id::text,
    jsonb_build_object('class_key', trim(p_class_key), 'academic_session', trim(p_academic_session), 'term', trim(p_term))
  );

  return jsonb_build_object(
    'ok', true,
    'code', 'RESULT_FEES_SAVED',
    'student_id', p_student_id,
    'class_key', trim(p_class_key),
    'academic_session', trim(p_academic_session),
    'term', trim(p_term)
  );
end;
$function$;

CREATE OR REPLACE FUNCTION public.school_result_publish_update(p_session_id uuid, p_session_secret text, p_action text, p_payload jsonb DEFAULT '{}'::jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'extensions', 'public'
AS $function$
declare
 v_action text:=lower(trim(coalesce(p_action,''))); v_class_key text:=nullif(trim(coalesce(p_payload->>'class_key','')),''); v_term text:=nullif(trim(coalesce(p_payload->>'term','')),''); v_academic_session text:=nullif(trim(coalesce(p_payload->>'academic_session','')),''); v_subject_index integer; v_published boolean; v_auth jsonb; v_person_id uuid;
begin
 begin v_subject_index:=nullif(p_payload->>'subject_index','')::integer; exception when others then return jsonb_build_object('ok',false,'code','RESULT_SUBJECT_INDEX_INVALID'); end;
 if v_action not in ('results.publish','results.unpublish') or v_class_key is null or v_term is null or v_academic_session is null or v_subject_index is null then return jsonb_build_object('ok',false,'code','RESULT_PUBLISH_PAYLOAD_INVALID'); end if;
 v_auth:=public.school_result_authorize(p_session_id,p_session_secret,v_action,v_class_key,v_subject_index,v_academic_session,v_term);
 if coalesce((v_auth->>'ok')::boolean,false) is not true then return v_auth; end if;
 v_person_id:=(v_auth->>'person_id')::uuid;
 v_published:=case when v_action='results.unpublish' then false else lower(coalesce(p_payload->>'published','true')) in ('true','1','yes') end;
 if v_published then
  insert into public.published_subjects(class_key,academic_session,term,subject_index) values(v_class_key,v_academic_session,v_term,v_subject_index) on conflict(class_key,academic_session,term,subject_index) do nothing;
 else
  delete from public.published_subjects where class_key=v_class_key and academic_session=v_academic_session and term=v_term and subject_index=v_subject_index;
 end if;
 insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,after_data,details)
 values('result_session',v_person_id::text,case when v_published then 'result.subject.published' else 'result.subject.unpublished' end,'published_subjects',v_class_key||':'||v_academic_session||':'||v_term||':'||v_subject_index::text,jsonb_build_object('published',v_published),jsonb_build_object('source','school_result_api','class_key',v_class_key,'academic_session',v_academic_session,'term',v_term,'subject_index',v_subject_index));
 return jsonb_build_object('ok',true,'code','RESULT_PUBLISH_UPDATED','published',v_published,'class_key',v_class_key,'academic_session',v_academic_session,'term',v_term,'subject_index',v_subject_index);
exception when others then return jsonb_build_object('ok',false,'code','RESULT_PUBLISH_UPDATE_FAILED');
end;
$function$;

CREATE OR REPLACE FUNCTION public.school_result_api(p_session_id uuid, p_session_secret text, p_action text, p_payload jsonb DEFAULT '{}'::jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'extensions', 'public'
AS $function$
declare
  v_action text := lower(trim(coalesce(p_action, '')));
  v_payload jsonb := coalesce(p_payload, '{}'::jsonb);
  v_student_id uuid;
  v_subject_index integer;
  v_ca1 numeric;
  v_ca2 numeric;
  v_ca3 numeric;
  v_exam numeric;
begin
  if v_action in ('results.publish', 'results.unpublish') then
    return public.school_result_publish_update(p_session_id,p_session_secret,v_action,v_payload);
  end if;

  if v_action = 'scores.enter' then
    begin
      v_student_id := (v_payload ->> 'student_id')::uuid;
      v_subject_index := nullif(v_payload ->> 'subject_index', '')::integer;
      v_ca1 := nullif(v_payload ->> 'ca1', '')::numeric;
      v_ca2 := nullif(v_payload ->> 'ca2', '')::numeric;
      v_ca3 := nullif(v_payload ->> 'ca3', '')::numeric;
      v_exam := nullif(v_payload ->> 'exam', '')::numeric;
    exception when others then
      return jsonb_build_object('ok', false, 'code', 'RESULT_SCORE_PAYLOAD_INVALID');
    end;

    return public.school_result_score_update(
      p_session_id,
      p_session_secret,
      v_student_id,
      v_payload ->> 'class_key',
      v_subject_index,
      v_payload ->> 'term',
      v_payload ->> 'academic_session',
      v_ca1,
      v_ca2,
      v_ca3,
      v_exam
    );
  end if;

  return public.school_result_api_legacy(
    p_session_id, p_session_secret, p_action, v_payload
  );
end;
$function$;

CREATE OR REPLACE FUNCTION public.school_result_external_score_correction(p_session_id uuid, p_session_secret text, p_student_id uuid, p_class_key text, p_subject_index integer, p_academic_session text, p_term text, p_component text, p_old_value numeric, p_new_value numeric, p_correction_reason text, p_audit_metadata jsonb, p_source_application text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'extensions', 'public'
AS $function$
declare
 v_session jsonb; v_auth jsonb; v_person_id uuid; v_staff_id uuid; v_request_id uuid:=gen_random_uuid(); v_before public.scores%rowtype; v_write jsonb; v_current numeric; v_ca1 numeric; v_ca2 numeric; v_ca3 numeric; v_exam numeric; v_component text:=lower(trim(coalesce(p_component,''))); v_source text:=lower(trim(coalesce(p_source_application,'')));
begin
 v_session:=public.school_identity_session_validate(p_session_id,p_session_secret,'results');
 if coalesce((v_session->>'ok')::boolean,false) is not true then return v_session; end if;
 v_person_id:=(v_session->>'person_id')::uuid;
 select s.id into v_staff_id from public.staff_attendance_profiles s where s.central_person_id=v_person_id and s.registration_status='active' and s.employment_status='active' order by s.id limit 1;
 if v_staff_id is null then return jsonb_build_object('ok',false,'code','RESULT_EMPLOYMENT_NOT_ACTIVE'); end if;
 if v_source not in ('chatgpt_work','approved_management_tool') then return jsonb_build_object('ok',false,'code','RESULT_CORRECTION_SOURCE_NOT_ALLOWED'); end if;
 if nullif(trim(coalesce(p_correction_reason,'')),'') is null or length(trim(p_correction_reason))>1000 or p_audit_metadata is null or jsonb_typeof(p_audit_metadata)<>'object' then return jsonb_build_object('ok',false,'code','RESULT_CORRECTION_METADATA_INVALID'); end if;
 if p_student_id is null or nullif(trim(coalesce(p_class_key,'')),'') is null or p_subject_index is null or p_subject_index<0 or nullif(trim(coalesce(p_academic_session,'')),'') is null or nullif(trim(coalesce(p_term,'')),'') is null or v_component not in ('ca1','ca2','ca3','exam') then return jsonb_build_object('ok',false,'code','RESULT_CORRECTION_PAYLOAD_INVALID'); end if;
 if (p_new_value is not null and (p_new_value<0 or p_new_value>100)) or (p_old_value is not null and (p_old_value<0 or p_old_value>100)) then return jsonb_build_object('ok',false,'code','RESULT_SCORE_RANGE_INVALID'); end if;
 v_auth:=public.school_result_authorize(p_session_id,p_session_secret,'results.manage',trim(p_class_key),p_subject_index,trim(p_academic_session),trim(p_term));
 if coalesce((v_auth->>'ok')::boolean,false) is not true then return v_auth; end if;
 if not exists(select 1 from public.result_subject_catalog r where r.class_key=trim(p_class_key) and r.subject_index=p_subject_index) then return jsonb_build_object('ok',false,'code','RESULT_SUBJECT_NOT_ASSIGNED'); end if;
 if not exists(select 1 from public.students s where s.id=p_student_id and s.class_key=trim(p_class_key) and not coalesce(s.archived,false)) then return jsonb_build_object('ok',false,'code','RESULT_STUDENT_CLASS_MISMATCH'); end if;
 select s.* into v_before from public.scores s where s.student_id=p_student_id and s.class_key=trim(p_class_key) and s.subject_index=p_subject_index and s.academic_session=trim(p_academic_session) and s.term=trim(p_term) for update;
 if not found then return jsonb_build_object('ok',false,'code','RESULT_SCORE_RECORD_NOT_FOUND'); end if;
 v_current:=case v_component when 'ca1' then v_before.ca1 when 'ca2' then v_before.ca2 when 'ca3' then v_before.ca3 when 'exam' then v_before.exam end;
 if v_current is distinct from p_old_value then
  insert into public.school_result_score_audit(request_id,actor_person_id,staff_id,student_id,class_key,subject_index,academic_session,term,component,old_value,new_value,old_record,action_type,source_application,success,failure_code,correction_reason,audit_metadata)
  values(v_request_id,v_person_id,v_staff_id,p_student_id,trim(p_class_key),p_subject_index,trim(p_academic_session),trim(p_term),v_component,v_current,p_new_value,to_jsonb(v_before),'external_score_correction_rejected',v_source,false,'RESULT_OLD_VALUE_MISMATCH',p_correction_reason,p_audit_metadata);
  return jsonb_build_object('ok',false,'code','RESULT_OLD_VALUE_MISMATCH','request_id',v_request_id);
 end if;
 v_ca1:=v_before.ca1;v_ca2:=v_before.ca2;v_ca3:=v_before.ca3;v_exam:=v_before.exam;
 if v_component='ca1' then v_ca1:=p_new_value; elsif v_component='ca2' then v_ca2:=p_new_value; elsif v_component='ca3' then v_ca3:=p_new_value; else v_exam:=p_new_value; end if;
 v_write:=public.school_result_score_update(p_session_id,p_session_secret,p_student_id,trim(p_class_key),p_subject_index,trim(p_term),trim(p_academic_session),v_ca1,v_ca2,v_ca3,v_exam);
 if coalesce((v_write->>'ok')::boolean,false) is not true or coalesce((v_write->>'persisted')::boolean,false) is not true then return v_write||jsonb_build_object('request_id',v_request_id); end if;
 insert into public.school_result_score_audit(request_id,actor_person_id,staff_id,student_id,class_key,subject_index,academic_session,term,component,old_value,new_value,old_record,new_record,action_type,source_application,success,correction_reason,audit_metadata)
 values(v_request_id,v_person_id,v_staff_id,p_student_id,trim(p_class_key),p_subject_index,trim(p_academic_session),trim(p_term),v_component,v_current,p_new_value,to_jsonb(v_before),v_write->'score','external_score_correction',v_source,true,p_correction_reason,p_audit_metadata);
 return v_write||jsonb_build_object('code','RESULT_SCORE_CORRECTION_SAVED','request_id',v_request_id,'source_application',v_source,'correction_reason',p_correction_reason);
exception when others then return jsonb_build_object('ok',false,'code','RESULT_SCORE_CORRECTION_FAILED','request_id',v_request_id);
end;
$function$;

revoke all on function public.school_result_api_legacy(uuid,text,text,jsonb) from public,anon,authenticated;
revoke all on function public.school_result_publish_update(uuid,text,text,jsonb) from public,anon,authenticated;
revoke all on function public.school_result_context_set(uuid,text,text,text,text) from public,authenticated;
revoke all on function public.school_result_context_read(uuid,text) from public,authenticated;
revoke all on function public.school_result_external_score_correction(uuid,text,uuid,text,integer,text,text,text,numeric,numeric,text,jsonb,text) from public,authenticated;
grant execute on function public.school_result_context_set(uuid,text,text,text,text) to anon;
grant execute on function public.school_result_context_read(uuid,text) to anon;
grant execute on function public.school_result_external_score_correction(uuid,text,uuid,text,integer,text,text,text,numeric,numeric,text,jsonb,text) to anon;

comment on table public.school_result_context is 'Server-held authoritative class/session/term context for each Result session. settings.term is only a pre-selection default.';
comment on table public.school_result_score_audit is 'Private audit trail for canonical Result score writes and authorised corrections; document-only changes are not Result corrections.';
