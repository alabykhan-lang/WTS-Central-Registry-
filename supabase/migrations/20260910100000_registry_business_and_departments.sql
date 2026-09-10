-- Deterministic senior-secondary readiness corrections.
-- This migration preserves student, enrollment and progression history while
-- correcting the verified SS2 Business -> SS3 Business transition.

alter table public.students
  add column if not exists department_code text;

do $migration$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'students_department_code_check'
      and conrelid = 'public.students'::regclass
  ) then
    alter table public.students
      add constraint students_department_code_check
      check (department_code is null or department_code in ('arts','science','business','general'));
  end if;
end
$migration$;

comment on column public.students.department_code is
  'Optional senior-secondary academic stream selected from verified school records.';

-- Existing class keys are authoritative for the deterministic stream values.
-- Unknown/general students remain NULL until management assigns a verified
-- stream from the profile workflow.
update public.students
set department_code = case
  when lower(class_key) in ('ss2-arts','ss3-arts') then 'arts'
  when lower(class_key) in ('ss2-science','ss3-science') then 'science'
  when lower(class_key) in ('ss2-business','ss3-business') then 'business'
  else department_code
end,
updated_at = now()
where department_code is null
  and lower(class_key) in ('ss2-arts','ss3-arts','ss2-science','ss3-science','ss2-business','ss3-business');

-- Keep the approved class catalog explicit and normalized.
insert into public.school_classes(class_key, display_name, section, sort_order, is_active, stage_code)
values ('ss3-business', 'SS 3 Business', 'secondary', 420, true, 'secondary')
on conflict (class_key) do update
set display_name = excluded.display_name,
    section = excluded.section,
    sort_order = excluded.sort_order,
    is_active = true,
    stage_code = excluded.stage_code;

-- Carry every existing SS2 Business subject into SS3 Business without
-- overwriting any SS3 row management has already configured.
insert into public.result_subject_catalog(class_key, subject_index, subject_name, aliases, active)
select 'ss3-business', r.subject_index, r.subject_name, r.aliases, r.active
from public.result_subject_catalog r
where r.class_key = 'ss2-business'
on conflict (class_key, subject_index) do nothing;

-- Ensure both the promotion rule and the SS3 Business app configuration are
-- complete, while preserving unrelated operator-managed configuration.
do $migration$
declare
  v_before jsonb;
  v_after jsonb;
  v_depts jsonb;
  v_promotion jsonb;
  v_ss2 jsonb;
  v_ss3 jsonb;
  v_subjects jsonb;
begin
  v_before := wts_internal.school_registry_setting_json('app_config');
  if v_before is null then
    return;
  end if;

  v_promotion := case when jsonb_typeof(v_before->'promotionCfg') = 'object'
    then v_before->'promotionCfg' else '{}'::jsonb end;
  v_promotion := v_promotion || jsonb_build_object(
    'ss2-business',
    case when jsonb_typeof(v_promotion->'ss2-business') = 'object'
      then v_promotion->'ss2-business' else '{}'::jsonb end
      || jsonb_build_object('target','ss3-business')
  );
  v_after := jsonb_set(v_before, '{promotionCfg}', v_promotion, true);

  v_depts := case when jsonb_typeof(v_after->'depts') = 'object'
    then v_after->'depts' else '{}'::jsonb end;
  v_ss2 := case when jsonb_typeof(v_depts->'ss2-business') = 'object'
    then v_depts->'ss2-business' else '{}'::jsonb end;
  v_ss3 := case when jsonb_typeof(v_depts->'ss3-business') = 'object'
    then v_depts->'ss3-business' else '{}'::jsonb end;
  v_ss3 := jsonb_set(v_ss3, '{label}', to_jsonb('SS3 - Business'::text), true);
  v_subjects := case when jsonb_typeof(v_ss2->'subjects') = 'array'
    and jsonb_array_length(v_ss2->'subjects') > 0 then v_ss2->'subjects' else
      coalesce((select jsonb_agg(r.subject_name order by r.subject_index)
        from public.result_subject_catalog r
        where r.class_key='ss2-business' and r.active), '[]'::jsonb)
    end;
  if jsonb_array_length(v_subjects) > 0 then
    v_ss3 := jsonb_set(v_ss3, '{subjects}', v_subjects, true);
  end if;
  v_after := jsonb_set(v_after, '{depts}', v_depts || jsonb_build_object('ss3-business', v_ss3), true);

  if v_after is distinct from v_before then
    update public.settings set value=v_after::text where key='app_config';
    insert into public.school_registry_audit(
      actor_type,actor_id,action,entity_type,entity_id,before_data,after_data,details
    ) values (
      'system','registry_business_readiness','configuration.business_stream_normalized',
      'setting','app_config',v_before,v_after,
      jsonb_build_object('preservedUnrelatedConfiguration',true)
    );
  end if;
end
$migration$;

-- Make the immutable fallback agree with the approved Business structure even
-- when an older installation has not yet materialized app_config.
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
    when 'ss2-business' then 'ss3-business'
    when 'ss3-science' then ''
    when 'ss3-arts' then ''
    when 'ss3-business' then ''
    else ''
  end;
$function$;

revoke all on function public.school_academic_default_promotion_target(text)
  from public, anon, authenticated;

-- The two active rows below are identified only by their verified historical
-- source class and transition metadata. No names or broad class populations
-- are guessed. The original values are retained in audit before_data and in
-- enrollment metadata so this correction is reversible and reviewable.
do $migration$
declare
  v_row record;
  v_after_student jsonb;
  v_after_enrollment jsonb;
  v_after_decision jsonb;
begin
  for v_row in
    select distinct on (s.id)
      s.id as student_id,
      s.class_key as old_class_key,
      s.previous_class_key,
      to_jsonb(s) as before_student,
      e.id as enrollment_id,
      to_jsonb(e) as before_enrollment,
      d.id as decision_id,
      to_jsonb(d) as before_decision
    from public.students s
    join public.school_student_enrollments e
      on e.student_id=s.id
     and e.enrollment_status='active'
     and e.class_key='ss3-arts'
     and e.metadata->>'source_class_key'='ss2-business'
    left join public.school_student_progression_decisions d
      on d.student_id=s.id
     and d.source_class_key='ss2-business'
     and d.target_class_key='ss3-arts'
    where not s.archived
      and s.class_key='ss3-arts'
      and s.previous_class_key='ss2-business'
    order by s.id,e.started_on desc,e.created_at desc,d.created_at desc nulls last
  loop
    v_after_decision := null;
    update public.students
    set class_key='ss3-business',
        department_code='business',
        updated_at=now()
    where id=v_row.student_id;

    update public.school_student_enrollments
    set class_key='ss3-business',
        metadata=coalesce(metadata,'{}'::jsonb)
          || jsonb_build_object(
            'department_correction',true,
            'corrected_from_class_key','ss3-arts',
            'corrected_to_class_key','ss3-business',
            'correction_source','verified_ss2_business_history'
          ),
        updated_at=now()
    where id=v_row.enrollment_id;

    if v_row.decision_id is not null then
      update public.school_student_progression_decisions
      set target_class_key='ss3-business',
          decision_reason=coalesce(decision_reason,'')
            || ' Corrected from SS3 Arts to the verified SS3 Business stream.'
      where id=v_row.decision_id;
    end if;

    select to_jsonb(s) into v_after_student from public.students s where s.id=v_row.student_id;
    select to_jsonb(e) into v_after_enrollment from public.school_student_enrollments e where e.id=v_row.enrollment_id;
    if v_row.decision_id is not null then
      select to_jsonb(d) into v_after_decision from public.school_student_progression_decisions d where d.id=v_row.decision_id;
    end if;

    insert into public.school_registry_audit(
      actor_type,actor_id,action,entity_type,entity_id,before_data,after_data,details
    ) values (
      'system','registry_business_readiness','student.business_stream_corrected','student',v_row.student_id::text,
      jsonb_build_object('student',v_row.before_student,'enrollment',v_row.before_enrollment,'progressionDecision',v_row.before_decision),
      jsonb_build_object('student',v_after_student,'enrollment',v_after_enrollment,'progressionDecision',v_after_decision),
      jsonb_build_object('sourceClass','ss2-business','incorrectTarget','ss3-arts','correctTarget','ss3-business','historicalEvidencePreserved',true)
    );
  end loop;
end
$migration$;
