-- Central Registry owns session transitions and student progression.
--
-- The transition is deliberately one audited transaction. It updates the
-- existing student/enrollment rows in place, creates one next-session
-- enrollment per existing student, and leaves Result Portal scores and
-- historical rows untouched. The system function is not browser-callable;
-- the session-bound management wrapper is the only application entry point.

create table if not exists public.school_academic_transition_runs (
  id uuid primary key default gen_random_uuid(),
  source_session text not null,
  source_term text not null,
  target_session text not null,
  target_term text not null,
  transition_status text not null default 'applied'
    check (transition_status in ('applied','failed')),
  promotion_config jsonb not null default '{}'::jsonb,
  promoted_count integer not null default 0,
  retained_count integer not null default 0,
  graduated_count integer not null default 0,
  actor_person_id uuid references public.school_people(id),
  reason text,
  created_at timestamptz not null default now(),
  completed_at timestamptz,
  unique (source_session, source_term, target_session, target_term, transition_status)
);

create index if not exists school_academic_transition_runs_history_idx
  on public.school_academic_transition_runs (created_at desc);

alter table public.school_academic_transition_runs enable row level security;
revoke all on table public.school_academic_transition_runs from public, anon, authenticated;

create table if not exists public.school_student_progression_decisions (
  id uuid primary key default gen_random_uuid(),
  transition_run_id uuid not null references public.school_academic_transition_runs(id),
  student_id uuid not null references public.students(id),
  person_id uuid not null references public.school_people(id),
  source_session text not null,
  source_class_key text not null,
  target_session text not null,
  target_class_key text,
  decision text not null
    check (decision in ('promoted','retained','graduated')),
  average_percentage numeric(6,2),
  minimum_percentage numeric(6,2),
  decision_reason text not null,
  created_at timestamptz not null default now(),
  unique (transition_run_id, student_id)
);

create index if not exists school_student_progression_decisions_student_idx
  on public.school_student_progression_decisions (student_id, created_at desc);
create index if not exists school_student_progression_decisions_context_idx
  on public.school_student_progression_decisions (source_session, source_class_key, created_at desc);

alter table public.school_student_progression_decisions enable row level security;
revoke all on table public.school_student_progression_decisions from public, anon, authenticated;

create or replace function public.school_academic_next_session(p_session text)
returns text
language sql
immutable
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
  select case
    when trim(coalesce(p_session, '')) ~ '^[0-9]{4}/[0-9]{4}$'
    then (split_part(trim(p_session), '/', 1)::integer + 1)::text || '/' ||
         (split_part(trim(p_session), '/', 2)::integer + 1)::text
    else ''
  end;
$function$;

revoke all on function public.school_academic_next_session(text)
  from public, anon, authenticated;

create or replace function public.school_academic_default_promotion_target(p_class_key text)
returns text
language sql
immutable
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
  select case trim(coalesce(p_class_key, ''))
    when 'creche' then 'kg1'
    when 'kg1' then 'kg2'
    when 'kg2' then 'nursery1'
    when 'nursery1' then 'nursery2'
    when 'nursery2' then 'primary1'
    when 'primary1' then 'primary2'
    when 'primary2' then 'primary3'
    when 'primary3' then 'primary4'
    when 'primary4' then 'primary5'
    when 'primary5' then 'jss1'
    when 'jss1' then 'jss2'
    when 'jss2' then 'jss3'
    when 'jss3' then 'ss1-general'
    when 'ss1-general' then 'ss2-science'
    when 'ss2-science' then 'ss3-science'
    when 'ss2-arts' then 'ss3-arts'
    when 'ss2-business' then 'ss3-arts'
    when 'ss3-science' then ''
    when 'ss3-arts' then ''
    else ''
  end;
$function$;

revoke all on function public.school_academic_default_promotion_target(text)
  from public, anon, authenticated;

create or replace function public.school_academic_transition_apply(
  p_source_session text,
  p_source_term text,
  p_target_session text,
  p_target_term text,
  p_actor_person_id uuid default null,
  p_reason text default 'Central Registry academic session transition'
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_source_session text := trim(coalesce(p_source_session, ''));
  v_source_term text := trim(coalesce(p_source_term, ''));
  v_target_session text := trim(coalesce(p_target_session, ''));
  v_target_term text := trim(coalesce(p_target_term, ''));
  v_reason text := nullif(trim(coalesce(p_reason, '')), '');
  v_request_id uuid := gen_random_uuid();
  v_run_id uuid;
  v_config jsonb := '{}'::jsonb;
  v_promotion_config jsonb := '{}'::jsonb;
  v_rule jsonb;
  v_source_count integer;
  v_promoted_count integer := 0;
  v_retained_count integer := 0;
  v_graduated_count integer := 0;
  v_average numeric;
  v_minimum numeric;
  v_target_class text;
  v_decision text;
  v_decision_reason text;
  v_student record;
begin
  if v_source_session !~ '^[0-9]{4}/[0-9]{4}$'
     or v_target_session !~ '^[0-9]{4}/[0-9]{4}$'
     or v_source_term <> '3rd Term'
     or v_target_term <> '1st Term'
     or v_source_session = v_target_session
     or public.school_academic_next_session(v_source_session) <> v_target_session then
    return jsonb_build_object('ok', false, 'code', 'ACADEMIC_TRANSITION_CONTEXT_INVALID');
  end if;
  if v_reason is null or length(v_reason) < 8 then
    return jsonb_build_object('ok', false, 'code', 'ACADEMIC_TRANSITION_REASON_REQUIRED');
  end if;

  perform pg_advisory_xact_lock(hashtext('wts-academic-transition|' || v_source_session || '|' || v_target_session));

  if exists (
    select 1 from public.school_academic_transition_runs r
    where r.source_session = v_source_session
      and r.source_term = v_source_term
      and r.target_session = v_target_session
      and r.target_term = v_target_term
      and r.transition_status = 'applied'
  ) then
    select r.id into v_run_id
    from public.school_academic_transition_runs r
    where r.source_session = v_source_session
      and r.source_term = v_source_term
      and r.target_session = v_target_session
      and r.target_term = v_target_term
      and r.transition_status = 'applied'
    order by r.created_at desc
    limit 1;
    return jsonb_build_object(
      'ok', true,
      'code', 'ACADEMIC_TRANSITION_ALREADY_APPLIED',
      'run_id', v_run_id,
      'current', public.school_academic_current()
    );
  end if;

  select coalesce(value::jsonb, '{}'::jsonb)
    into v_config
  from public.settings
  where key = 'app_config';
  v_promotion_config := coalesce(v_config -> 'promotionCfg', '{}'::jsonb);

  select count(*) into v_source_count
  from public.school_student_enrollments e
  where e.academic_session = v_source_session
    and e.enrollment_status = 'active';
  if coalesce(v_source_count, 0) = 0 then
    return jsonb_build_object('ok', false, 'code', 'ACADEMIC_TRANSITION_SOURCE_EMPTY');
  end if;

  if exists (
    select 1 from public.school_student_enrollments e
    where e.academic_session = v_target_session
  ) then
    return jsonb_build_object('ok', false, 'code', 'ACADEMIC_TRANSITION_TARGET_NOT_EMPTY');
  end if;

  if not exists (select 1 from public.school_academic_sessions where session_name = v_source_session) then
    return jsonb_build_object('ok', false, 'code', 'ACADEMIC_SOURCE_SESSION_NOT_FOUND');
  end if;
  if not exists (select 1 from public.school_academic_sessions where session_name = v_target_session) then
    insert into public.school_academic_sessions(session_name, display_name, session_status)
    values (v_target_session, v_target_session, 'active');
  end if;

  -- Backfill the already-used source terms without dates. Dates are not the
  -- authority for this workflow; the official session/term rows are.
  insert into public.school_academic_terms(
    academic_session, term_name, term_status, is_current, metadata
  ) values (
    v_source_session, '1st Term', 'closed', false,
    jsonb_build_object('source', 'result_history_backfill')
  ) on conflict (academic_session, term_name) do nothing;
  insert into public.school_academic_terms(
    academic_session, term_name, term_status, is_current, metadata
  ) values (
    v_source_session, v_source_term, 'open', false,
    jsonb_build_object('source', 'central_registry_transition')
  ) on conflict (academic_session, term_name) do nothing;
  insert into public.school_academic_terms(
    academic_session, term_name, term_status, is_current, metadata
  ) values (
    v_target_session, v_target_term, 'open', false,
    jsonb_build_object('source', 'central_registry_transition')
  ) on conflict (academic_session, term_name) do nothing;

  -- Validate configured destinations before changing any student rows.
  if exists (
    with destinations as (
      select distinct e.class_key,
        coalesce(
          nullif(trim(v_promotion_config -> e.class_key ->> 'target'), ''),
          public.school_academic_default_promotion_target(e.class_key)
        ) as target_class_key
      from public.school_student_enrollments e
      where e.academic_session = v_source_session
        and e.enrollment_status = 'active'
    )
    select 1
    from destinations d
    where d.target_class_key <> ''
      and not exists (
        select 1 from public.school_classes c
        where c.class_key = d.target_class_key and c.is_active
      )
  ) then
    return jsonb_build_object('ok', false, 'code', 'ACADEMIC_TRANSITION_TARGET_CLASS_INVALID');
  end if;

  insert into public.school_academic_transition_runs(
    source_session, source_term, target_session, target_term,
    transition_status, promotion_config, actor_person_id, reason
  ) values (
    v_source_session, v_source_term, v_target_session, v_target_term,
    'applied', v_promotion_config, p_actor_person_id, v_reason
  ) returning id into v_run_id;

  -- The legacy current row may still say 2nd Term. Move the calendar through
  -- the real 3rd Term row first, then close it when the new session opens.
  update public.school_academic_terms t
  set is_current = false,
      term_status = case when t.term_status = 'open' then 'closed' else t.term_status end,
      closed_at = case when t.term_status = 'open' then coalesce(t.closed_at, now()) else t.closed_at end,
      updated_at = now()
  where t.is_current;
  update public.school_academic_terms t
  set is_current = true, term_status = 'open', closed_at = null, updated_at = now()
  where t.academic_session = v_source_session and t.term_name = v_source_term;

  for v_student in
    with source_students as (
      select e.id as enrollment_id, e.person_id, e.student_id, e.class_key,
             s.name, s.admno
      from public.school_student_enrollments e
      join public.students s on s.id = e.student_id
      where e.academic_session = v_source_session
        and e.enrollment_status = 'active'
    ),
    published as (
      select distinct p.class_key, p.subject_index
      from public.published_subjects p
      where p.academic_session = v_source_session and p.term = v_source_term
    ),
    score_rows as (
      select sc.student_id, sc.class_key, sc.subject_index,
             least(30, coalesce(sc.ca1, 0) + coalesce(sc.ca2, 0) + coalesce(sc.ca3, 0))
               + coalesce(sc.exam, 0) as mark
      from public.scores sc
      where sc.academic_session = v_source_session and sc.term = v_source_term
        and (sc.ca1 is not null or sc.ca2 is not null or sc.ca3 is not null or sc.exam is not null)
    ),
    averages as (
      select ss.*,
             case when count(sr.student_id) = 0 then null::numeric
                  else round(avg(sr.mark), 2) end as average_percentage
      from source_students ss
      left join score_rows sr
        on sr.student_id = ss.student_id and sr.class_key = ss.class_key
       and (
         not exists (select 1 from published p where p.class_key = ss.class_key)
         or exists (select 1 from published p where p.class_key = ss.class_key and p.subject_index = sr.subject_index)
       )
      group by ss.enrollment_id, ss.person_id, ss.student_id, ss.class_key, ss.name, ss.admno
    )
    select * from averages order by class_key, name, student_id
  loop
    v_rule := coalesce(v_promotion_config -> v_student.class_key, '{}'::jsonb);
    v_target_class := nullif(trim(coalesce(v_rule ->> 'target', '')), '');
    if v_target_class is null then
      v_target_class := nullif(public.school_academic_default_promotion_target(v_student.class_key), '');
    end if;
    v_average := v_student.average_percentage;
    v_minimum := null;

    if v_student.class_key in ('jss1', 'jss2', 'ss1-general') then
      v_minimum := coalesce(
        nullif(trim(coalesce(v_rule ->> 'minimumPct', '')), '')::numeric,
        nullif(trim(coalesce(v_rule ->> 'repeatPct', '')), '')::numeric,
        0
      );
      v_minimum := greatest(0, least(100, v_minimum));
      if v_average is not null and v_average >= v_minimum then
        v_decision := 'promoted';
        v_decision_reason := 'Met the class minimum average percentage.';
      else
        v_decision := 'retained';
        v_target_class := v_student.class_key;
        v_decision_reason := case when v_average is null
          then 'No 3rd Term average was available; retained for review.'
          else 'Below the class minimum average percentage.' end;
      end if;
    elsif v_target_class is null then
      v_decision := 'graduated';
      v_decision_reason := 'Completed the final senior secondary class.';
    else
      v_decision := 'promoted';
      v_decision_reason := 'Automatic class progression.';
    end if;

    insert into public.school_student_progression_decisions(
      transition_run_id, student_id, person_id, source_session, source_class_key,
      target_session, target_class_key, decision, average_percentage,
      minimum_percentage, decision_reason
    ) values (
      v_run_id, v_student.student_id, v_student.person_id, v_source_session, v_student.class_key,
      v_target_session, case when v_decision = 'graduated' then null else v_target_class end,
      v_decision, v_average, v_minimum, v_decision_reason
    );

    update public.school_student_enrollments e
    set enrollment_status = v_decision,
        ended_on = current_date,
        metadata = coalesce(e.metadata, '{}'::jsonb) || jsonb_build_object(
          'transition_run_id', v_run_id,
          'decision', v_decision,
          'average_percentage', v_average,
          'minimum_percentage', v_minimum
        ),
        updated_at = now()
    where e.id = v_student.enrollment_id;

    if v_decision = 'graduated' then
      update public.students s
      set archived = true,
          archived_at = now(),
          archived_reason = 'Graduated after ' || v_source_session || ' 3rd Term',
          lifecycle_status = 'graduated',
          previous_class_key = v_student.class_key,
          updated_at = now()
      where s.id = v_student.student_id;
      v_graduated_count := v_graduated_count + 1;
    else
      insert into public.school_student_enrollments(
        person_id, student_id, academic_session, class_key, enrollment_status,
        started_on, source, metadata
      ) values (
        v_student.person_id, v_student.student_id, v_target_session, v_target_class, 'active',
        current_date, 'central_registry_transition', jsonb_build_object(
          'transition_run_id', v_run_id,
          'decision', v_decision,
          'source_session', v_source_session,
          'source_class_key', v_student.class_key,
          'average_percentage', v_average,
          'minimum_percentage', v_minimum
        )
      );
      update public.students s
      set class_key = v_target_class,
          archived = false,
          archived_at = null,
          archived_reason = null,
          lifecycle_status = 'active',
          previous_class_key = case when v_target_class <> v_student.class_key then v_student.class_key else s.previous_class_key end,
          updated_at = now()
      where s.id = v_student.student_id;
      if v_decision = 'promoted' then
        v_promoted_count := v_promoted_count + 1;
      else
        v_retained_count := v_retained_count + 1;
      end if;
    end if;
  end loop;

  update public.school_academic_terms
  set is_current = false, term_status = 'closed', closed_at = coalesce(closed_at, now()), updated_at = now()
  where academic_session = v_source_session and term_name = v_source_term;
  update public.school_academic_terms
  set is_current = true, term_status = 'open', closed_at = null, updated_at = now()
  where academic_session = v_target_session and term_name = v_target_term;
  update public.school_academic_sessions
  set session_status = 'archived', updated_at = now()
  where session_name = v_source_session;
  update public.school_academic_sessions
  set session_status = 'active', updated_at = now()
  where session_name = v_target_session;

  v_config := jsonb_set(
    jsonb_set(
      jsonb_set(
        jsonb_set(coalesce(v_config, '{}'::jsonb), '{session}', to_jsonb(v_target_session), true),
        '{term}', to_jsonb(v_target_term), true
      ),
      '{promotionSourceSession}', to_jsonb(v_source_session), true
    ),
    '{promotionTargetSession}', to_jsonb(v_target_session), true
  );
  insert into public.settings(key, value)
  values ('session', v_target_session), ('term', v_target_term), ('app_config', v_config::text)
  on conflict (key) do update set value = excluded.value;

  update public.school_academic_transition_runs
  set promoted_count = v_promoted_count,
      retained_count = v_retained_count,
      graduated_count = v_graduated_count,
      completed_at = now()
  where id = v_run_id;

  -- Any old context-scoped staff access is no longer current. The next term
  -- can receive fresh allocations from Central Registry without carrying old
  -- permissions across a session boundary implicitly.
  perform public.school_registry_refresh_current_allocation_scopes(v_target_session, v_target_term, p_actor_person_id);

  insert into public.school_registry_audit(
    actor_type, actor_id, action, entity_type, entity_id, request_id,
    before_data, after_data, details
  ) values (
    case when p_actor_person_id is null then 'system' else 'person' end,
    case when p_actor_person_id is null then null else p_actor_person_id::text end,
    'academic.session_transition_applied', 'school_academic_transition_run', v_run_id::text, v_request_id,
    jsonb_build_object('session', v_source_session, 'term', v_source_term),
    jsonb_build_object('session', v_target_session, 'term', v_target_term),
    jsonb_build_object(
      'reason', v_reason,
      'promoted', v_promoted_count,
      'retained', v_retained_count,
      'graduated', v_graduated_count,
      'promotion_rules', v_promotion_config
    )
  );

  return jsonb_build_object(
    'ok', true,
    'code', 'ACADEMIC_TRANSITION_APPLIED',
    'run_id', v_run_id,
    'source_session', v_source_session,
    'source_term', v_source_term,
    'target_session', v_target_session,
    'target_term', v_target_term,
    'promoted', v_promoted_count,
    'retained', v_retained_count,
    'graduated', v_graduated_count,
    'current', public.school_academic_current(),
    'request_id', v_request_id
  );
exception when others then
  return jsonb_build_object('ok', false, 'code', 'ACADEMIC_TRANSITION_FAILED', 'detail', sqlerrm);
end;
$function$;

revoke all on function public.school_academic_transition_apply(text, text, text, text, uuid, text)
  from public, anon, authenticated, service_role;

create or replace function public.school_academic_transition_management_session_api(
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
  v_actor_person_id uuid;
  v_action text := lower(trim(coalesce(p_action, '')));
  v_current jsonb;
  v_source_session text;
  v_target_session text;
  v_reason text;
  v_config jsonb := '{}'::jsonb;
  v_result jsonb;
begin
  v_session := public.school_identity_session_validate(p_session_id, p_session_secret, 'central_registry');
  if coalesce((v_session ->> 'ok')::boolean, false) is not true then
    return v_session;
  end if;
  v_actor_person_id := wts_internal.central_management_actor(v_session);
  if v_actor_person_id is null then
    return jsonb_build_object('ok', false, 'code', 'MANAGEMENT_ACCESS_DENIED');
  end if;

  v_current := public.school_academic_current();
  v_source_session := coalesce(nullif(trim(p_payload ->> 'sourceSession'), ''), v_current ->> 'academic_session');
  v_target_session := coalesce(nullif(trim(p_payload ->> 'targetSession'), ''), public.school_academic_next_session(v_source_session));

  if v_action = 'read' then
    select coalesce(value::jsonb, '{}'::jsonb) into v_config
    from public.settings where key = 'app_config';
    return jsonb_build_object(
      'ok', true,
      'code', 'ACADEMIC_TRANSITION_READ',
      'current', v_current,
      'next', jsonb_build_object(
        'source_session', v_source_session,
        'source_term', '3rd Term',
        'target_session', v_target_session,
        'target_term', '1st Term'
      ),
      'promotion_rules', coalesce(v_config -> 'promotionCfg', '{}'::jsonb),
      'last_transition', (
        select to_jsonb(x) from (
          select r.id, r.source_session, r.source_term, r.target_session, r.target_term,
                 r.transition_status, r.promoted_count, r.retained_count, r.graduated_count,
                 r.reason, r.created_at, r.completed_at
          from public.school_academic_transition_runs r
          order by r.created_at desc limit 1
        ) x
      )
    );
  end if;

  if v_action in ('transition', 'carryforward', 'carry_forward') then
    v_reason := nullif(trim(coalesce(p_payload ->> 'reason', '')), '');
    if v_reason is null then v_reason := 'Central Registry carried students into the next academic session'; end if;
    v_result := public.school_academic_transition_apply(
      v_source_session, '3rd Term', v_target_session, '1st Term', v_actor_person_id, v_reason
    );
    return v_result;
  end if;

  return jsonb_build_object('ok', false, 'code', 'UNKNOWN_ACTION');
end;
$function$;

revoke all on function public.school_academic_transition_management_session_api(uuid, text, text, jsonb)
  from public, authenticated;
grant execute on function public.school_academic_transition_management_session_api(uuid, text, text, jsonb)
  to anon;

-- Read-only Results archive. This is intentionally independent of the current
-- student.class_key, so a student who moved classes remains visible in the
-- session and section where the historical record was created.
create or replace function public.school_result_history_read(
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
  v_auth jsonb;
  v_permissions text[];
  v_action text := lower(trim(coalesce(p_action, '')));
  v_session text := nullif(trim(coalesce(p_payload ->> 'academic_session', '')), '');
  v_term text := nullif(trim(coalesce(p_payload ->> 'term', '')), '');
  v_class_key text := nullif(trim(coalesce(p_payload ->> 'class_key', '')), '');
  v_student_id uuid;
  v_rows jsonb;
begin
  begin
    if nullif(p_payload ->> 'student_id', '') is not null then
      v_student_id := (p_payload ->> 'student_id')::uuid;
    end if;
  exception when others then
    return jsonb_build_object('ok', false, 'code', 'RESULT_HISTORY_FILTER_INVALID');
  end;

  v_auth := public.school_result_authorize(p_session_id, p_session_secret, 'identity.context');
  if coalesce((v_auth ->> 'ok')::boolean, false) is not true then return v_auth; end if;
  v_permissions := coalesce(array(select jsonb_array_elements_text(v_auth -> 'permissions')), array[]::text[]);
  if not public.school_result_permission_allowed(v_permissions, 'results.view_assigned')
     and not public.school_result_permission_allowed(v_permissions, 'results.manage') then
    return jsonb_build_object('ok', false, 'code', 'RESULT_PERMISSION_DENIED', 'required_permission', 'results.view_assigned');
  end if;

  if v_action = 'read' then
    select coalesce(jsonb_agg(to_jsonb(x) order by x.academic_session desc,
      case x.term when '1st Term' then 1 when '2nd Term' then 2 when '3rd Term' then 3 else 9 end), '[]'::jsonb)
      into v_rows
    from (
      select distinct c.academic_session, c.term, c.term_status, c.is_current,
        (select count(*) from public.school_student_enrollments e where e.academic_session = c.academic_session) as enrolled_students,
        (select count(*) from public.school_student_enrollments e where e.academic_session = c.academic_session and e.enrollment_status = 'graduated') as graduating_students
      from (
        select t.academic_session, t.term_name as term, t.term_status, t.is_current
        from public.school_academic_terms t
        union all
        select distinct s.academic_session, s.term, 'archived'::text, false from public.scores s
        union all
        select distinct e.academic_session, '3rd Term', 'archived'::text, false from public.school_student_enrollments e
      ) c
      where not c.is_current
    ) x;
    return jsonb_build_object(
      'ok', true,
      'code', 'RESULT_HISTORY_READ',
      'read_only', true,
      'contexts', v_rows,
      'transitions', coalesce((select jsonb_agg(to_jsonb(r) order by r.created_at desc) from public.school_academic_transition_runs r), '[]'::jsonb)
    );
  end if;

  if v_session is null then return jsonb_build_object('ok', false, 'code', 'RESULT_HISTORY_SESSION_REQUIRED'); end if;

  if v_action in ('students', 'graduates') then
    if v_action = 'students' and v_class_key is null then
      return jsonb_build_object('ok', false, 'code', 'RESULT_HISTORY_CLASS_REQUIRED');
    end if;
    select coalesce(jsonb_agg(to_jsonb(x) order by x.name), '[]'::jsonb)
      into v_rows
    from (
      select s.id, s.name, s.gender, s.admno, s.house, s.age, s.photo,
             s.created_at, s.archived, s.archived_at, s.archived_reason,
             s.previous_class_key, s.lifecycle_status, s.admission_date,
             s.admission_source, s.updated_at, s.student_number_status,
             e.class_key as historical_class_key, e.enrollment_status,
             e.started_on, e.ended_on, e.metadata
      from public.school_student_enrollments e
      join public.students s on s.id = e.student_id
      where e.academic_session = v_session
        and (v_action = 'graduates' and (e.enrollment_status = 'graduated' or e.class_key in ('ss3-arts','ss3-science'))
             or v_action = 'students' and e.class_key = v_class_key)
        and (v_student_id is null or e.student_id = v_student_id)
    ) x;
    return jsonb_build_object('ok', true, 'code', 'RESULT_HISTORY_STUDENTS_READ', 'read_only', true, 'rows', v_rows);
  end if;

  return jsonb_build_object('ok', false, 'code', 'RESULT_HISTORY_ACTION_NOT_ALLOWED');
end;
$function$;

revoke all on function public.school_result_history_read(uuid, text, text, jsonb)
  from public, authenticated;
grant execute on function public.school_result_history_read(uuid, text, text, jsonb)
  to anon, service_role;
