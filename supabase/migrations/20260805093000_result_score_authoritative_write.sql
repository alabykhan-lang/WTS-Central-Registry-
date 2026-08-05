-- Authoritative Result score writes and non-public score audit.
-- This migration changes only Result score persistence and its audit trail.
-- It does not create or alter identities, grants, pupils, classes, subjects,
-- Attendance data, Notification data, or existing score values.

begin;

do $migration$
begin
  if exists (
    select 1 from pg_constraint
    where conrelid = 'public.scores'::regclass
      and conname = 'scores_upsert_key'
  ) then
    alter table public.scores drop constraint scores_upsert_key;
  end if;

  if not exists (
    select 1 from pg_constraint
    where conrelid = 'public.scores'::regclass
      and conname = 'scores_component_range_check'
  ) then
    alter table public.scores add constraint scores_component_range_check
    check (
      (ca1 is null or (ca1 >= 0 and ca1 <= 100))
      and (ca2 is null or (ca2 >= 0 and ca2 <= 100))
      and (ca3 is null or (ca3 >= 0 and ca3 <= 100))
      and (exam is null or (exam >= 0 and exam <= 100))
    );
  end if;
end
$migration$;

create table if not exists public.school_result_score_audit (
  id uuid primary key default gen_random_uuid(),
  request_id uuid not null,
  actor_person_id uuid,
  staff_id uuid,
  student_id uuid,
  class_key text,
  subject_index integer,
  academic_session text,
  term text,
  component text not null,
  old_value numeric,
  new_value numeric,
  old_record jsonb,
  new_record jsonb,
  action_type text not null,
  source_application text not null default 'result_portal',
  success boolean not null,
  failure_code text,
  created_at timestamptz not null default now()
);

create index if not exists school_result_score_audit_student_created_idx
  on public.school_result_score_audit(student_id, created_at desc);

create index if not exists school_result_score_audit_request_idx
  on public.school_result_score_audit(request_id);

alter table public.school_result_score_audit enable row level security;
revoke all on table public.school_result_score_audit from public, anon, authenticated;

create or replace function public.school_result_score_update(
  p_session_id uuid,
  p_session_secret text,
  p_student_id uuid,
  p_class_key text,
  p_subject_index integer,
  p_term text,
  p_academic_session text,
  p_ca1 numeric,
  p_ca2 numeric,
  p_ca3 numeric,
  p_exam numeric
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
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
    p_session_id, p_session_secret, 'results'
  );
  if coalesce((v_session ->> 'ok')::boolean, false) is not true then
    return v_session;
  end if;

  v_person_id := (v_session ->> 'person_id')::uuid;
  select s.id into v_staff_id
  from public.staff_attendance_profiles s
  where s.central_person_id = v_person_id
  order by s.id limit 1;

  v_auth := public.school_result_authorize(
    p_session_id, p_session_secret, 'scores.enter',
    p_class_key, p_subject_index, p_academic_session, p_term
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
      actor_type, actor_id, action, entity_type, entity_id, request_id, details
    ) values (
      'result_session', v_person_id::text, 'result.score.write_failed',
      'scores', p_student_id::text, v_request_id,
      jsonb_build_object(
        'staff_id', v_staff_id, 'person_id', v_person_id,
        'class_key', p_class_key, 'subject_index', p_subject_index,
        'academic_session', p_academic_session, 'term', p_term,
        'source_application', 'result_portal', 'success', false,
        'failure_code', coalesce(v_auth ->> 'code', 'RESULT_SCORE_WRITE_REJECTED')
      )
    );

    return v_auth || jsonb_build_object('request_id', v_request_id);
  end if;

  if p_student_id is null
     or nullif(trim(coalesce(p_class_key, '')), '') is null
     or p_subject_index is null or p_subject_index < 0
     or nullif(trim(coalesce(p_term, '')), '') is null
     or nullif(trim(coalesce(p_academic_session, '')), '') is null then
    v_failure_code := 'RESULT_SCORE_PAYLOAD_INVALID';
  elsif not exists (
    select 1 from public.result_subject_catalog r
    where r.class_key = trim(p_class_key) and r.subject_index = p_subject_index
  ) then
    v_failure_code := 'RESULT_SUBJECT_NOT_ASSIGNED';
  else
    select s.class_key into v_current_class
    from public.students s
    where s.id = p_student_id and coalesce(s.archived, false) = false;

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
      actor_type, actor_id, action, entity_type, entity_id, request_id, details
    ) values (
      'result_session', v_person_id::text, 'result.score.write_failed',
      'scores', p_student_id::text, v_request_id,
      jsonb_build_object(
        'staff_id', v_staff_id, 'person_id', v_person_id,
        'class_key', p_class_key, 'subject_index', p_subject_index,
        'academic_session', p_academic_session, 'term', p_term,
        'source_application', 'result_portal', 'success', false,
        'failure_code', v_failure_code
      )
    );

    return jsonb_build_object(
      'ok', false, 'code', v_failure_code, 'request_id', v_request_id
    );
  end if;

  select to_jsonb(s), s.id into v_before, v_score_id
  from public.scores s
  where s.student_id = p_student_id
    and s.subject_index = p_subject_index
    and s.term = trim(p_term)
  for update;

  begin
    insert into public.scores(
      student_id, class_key, subject_index, term, ca1, ca2, ca3, exam
    ) values (
      p_student_id, trim(p_class_key), p_subject_index, trim(p_term),
      p_ca1, p_ca2, p_ca3, p_exam
    )
    on conflict (student_id, subject_index, term) do update
    set class_key = excluded.class_key,
        ca1 = excluded.ca1, ca2 = excluded.ca2,
        ca3 = excluded.ca3, exam = excluded.exam
    returning id into v_score_id;

    select to_jsonb(s) into v_after
    from public.scores s where s.id = v_score_id;
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
        'staff_id', v_staff_id, 'person_id', v_person_id,
        'class_key', p_class_key, 'subject_index', p_subject_index,
        'academic_session', p_academic_session, 'term', p_term,
        'source_application', 'result_portal', 'success', false,
        'failure_code', 'RESULT_SCORE_SAVE_FAILED'
      )
    );

    return jsonb_build_object(
      'ok', false, 'code', 'RESULT_SCORE_SAVE_FAILED', 'request_id', v_request_id
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
      then 'result.score.entered' else 'result.score.corrected' end,
    'scores', v_score_id::text, v_request_id, v_before, v_after,
    jsonb_build_object(
      'staff_id', v_staff_id, 'person_id', v_person_id,
      'student_id', p_student_id, 'class_key', trim(p_class_key),
      'subject_index', p_subject_index,
      'academic_session', trim(p_academic_session), 'term', trim(p_term),
      'source_application', 'result_portal', 'success', true
    )
  );

  return jsonb_build_object(
    'ok', true, 'code', 'RESULT_SCORE_SAVED',
    'request_id', v_request_id, 'persisted', true,
    'student_id', p_student_id, 'class_key', trim(p_class_key),
    'subject_index', p_subject_index, 'term', trim(p_term),
    'academic_session', trim(p_academic_session),
    'score', jsonb_build_object(
      'id', v_after -> 'id', 'student_id', v_after -> 'student_id',
      'class_key', v_after -> 'class_key',
      'subject_index', v_after -> 'subject_index',
      'term', v_after -> 'term', 'ca1', v_after -> 'ca1',
      'ca2', v_after -> 'ca2', 'ca3', v_after -> 'ca3',
      'exam', v_after -> 'exam'
    )
  );
exception when others then
  return jsonb_build_object(
    'ok', false, 'code', 'RESULT_SCORE_SAVE_FAILED',
    'request_id', v_request_id
  );
end;
$function$;

revoke all on function public.school_result_score_update(
  uuid, text, uuid, text, integer, text, text, numeric, numeric, numeric, numeric
) from public, anon, authenticated;

grant execute on function public.school_result_score_update(
  uuid, text, uuid, text, integer, text, text, numeric, numeric, numeric, numeric
) to anon, service_role;

commit;
