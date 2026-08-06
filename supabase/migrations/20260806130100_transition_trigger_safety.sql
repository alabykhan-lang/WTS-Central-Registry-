-- The legacy student trigger mirrors class changes into the configured
-- current session. A session transition must set that session before changing
-- students, otherwise the trigger can manufacture a second source enrollment.
-- Preserve the original implementation under a private name and wrap it with
-- a settings guard. The management API keeps its existing function name.

do $migration$
declare
  v_definition text;
begin
  if to_regprocedure('public.school_academic_transition_apply(text,text,text,text,uuid,text)') is not null
     and to_regprocedure('public.school_academic_transition_apply_legacy(text,text,text,text,uuid,text)') is null then
    select pg_get_functiondef(p.oid)
      into v_definition
    from pg_proc p
    where p.oid = to_regprocedure('public.school_academic_transition_apply(text,text,text,text,uuid,text)');
    v_definition := replace(
      v_definition,
      'FUNCTION public.school_academic_transition_apply(',
      'FUNCTION public.school_academic_transition_apply_legacy('
    );
    execute v_definition;
  end if;
end;
$migration$;

revoke all on function public.school_academic_transition_apply_legacy(text, text, text, text, uuid, text)
  from public, anon, authenticated, service_role;

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
  v_previous_session text;
  v_previous_term text;
  v_result jsonb;
begin
  select value into v_previous_session from public.settings where key = 'session';
  select value into v_previous_term from public.settings where key = 'term';

  -- school_registry_after_student() reads this value while the legacy body
  -- updates students. It must see the target session before those updates.
  insert into public.settings(key, value)
  values ('session', trim(coalesce(p_target_session, ''))), ('term', trim(coalesce(p_target_term, '')))
  on conflict (key) do update set value = excluded.value;

  v_result := public.school_academic_transition_apply_legacy(
    p_source_session, p_source_term, p_target_session, p_target_term,
    p_actor_person_id, p_reason
  );

  if coalesce((v_result ->> 'ok')::boolean, false) is not true
     and coalesce(v_result ->> 'code', '') <> 'ACADEMIC_TRANSITION_ALREADY_APPLIED' then
    insert into public.settings(key, value)
    values ('session', coalesce(v_previous_session, '')), ('term', coalesce(v_previous_term, ''))
    on conflict (key) do update set value = excluded.value;
  end if;
  return v_result;
exception when others then
  insert into public.settings(key, value)
  values ('session', coalesce(v_previous_session, '')), ('term', coalesce(v_previous_term, ''))
  on conflict (key) do update set value = excluded.value;
  return jsonb_build_object('ok', false, 'code', 'ACADEMIC_TRANSITION_FAILED');
end;
$function$;

revoke all on function public.school_academic_transition_apply(text, text, text, text, uuid, text)
  from public, anon, authenticated, service_role;

-- Repair only rows created by the audited run while its trigger guard was not
-- present. These are not deleted: they are retained as archived transition
-- artifacts and excluded from current enrollment counts.
with run as (
  select id, created_at, source_session, target_session
  from public.school_academic_transition_runs
  where source_session = '2025/2026'
    and target_session = '2026/2027'
    and transition_status = 'applied'
  order by created_at desc
  limit 1
)
update public.school_student_enrollments e
set enrollment_status = 'archived',
    ended_on = coalesce(e.ended_on, current_date),
    metadata = coalesce(e.metadata, '{}'::jsonb) || jsonb_build_object(
      'transition_artifact', true,
      'transition_artifact_reason', 'Legacy student trigger mirror created during session transition repair'
    ),
    updated_at = now()
from run
where e.academic_session = run.source_session
  and e.enrollment_status = 'active'
  and e.created_at >= run.created_at
  and e.metadata ->> 'transition_run_id' is null;

with run as (
  select id, source_session, target_session
  from public.school_academic_transition_runs
  where source_session = '2025/2026'
    and target_session = '2026/2027'
    and transition_status = 'applied'
  order by created_at desc
  limit 1
)
update public.school_student_enrollments e
set enrollment_status = 'active', updated_at = now()
from run
where e.academic_session = run.target_session
  and e.source = 'central_registry_transition'
  and e.metadata ->> 'transition_run_id' = run.id::text
  and e.enrollment_status = 'promoted';
