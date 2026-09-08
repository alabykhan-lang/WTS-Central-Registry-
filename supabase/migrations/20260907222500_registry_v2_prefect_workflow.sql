-- Student Executive Council / prefect lifecycle.

create table if not exists public.school_prefect_bootstrap (
  id boolean primary key default true check (id),
  completed_at timestamptz,
  completed_by_person_id uuid references public.school_people(id),
  source text,
  metadata jsonb not null default '{}'::jsonb
);

create table if not exists public.school_prefect_cycles (
  id uuid primary key default gen_random_uuid(),
  academic_session text not null,
  source_term text not null check (source_term = '3rd Term'),
  target_session text not null,
  cycle_status text not null default 'open' check (cycle_status in ('open','submitted','approved','activated','closed')),
  opened_by_person_id uuid references public.school_people(id),
  approved_by_person_id uuid references public.school_people(id),
  opened_at timestamptz not null default now(),
  approved_at timestamptz,
  activated_at timestamptz,
  reason text,
  metadata jsonb not null default '{}'::jsonb,
  unique (academic_session, target_session)
);

create table if not exists public.school_prefect_candidates (
  id uuid primary key default gen_random_uuid(),
  cycle_id uuid not null references public.school_prefect_cycles(id) on delete cascade,
  student_id uuid not null references public.students(id),
  portfolio_code text not null default 'student_executive_council' references public.school_portfolio_catalog(portfolio_code),
  candidate_status text not null default 'candidate' check (candidate_status in ('candidate','selected','approved','rejected','activated')),
  office_name text,
  notes text,
  selected_by_person_id uuid references public.school_people(id),
  selected_at timestamptz,
  approved_by_person_id uuid references public.school_people(id),
  approved_at timestamptz,
  created_at timestamptz not null default now(),
  unique (cycle_id, student_id, portfolio_code)
);

alter table public.school_prefect_bootstrap enable row level security;
alter table public.school_prefect_cycles enable row level security;
alter table public.school_prefect_candidates enable row level security;
revoke all on table public.school_prefect_bootstrap, public.school_prefect_cycles, public.school_prefect_candidates from public, anon, authenticated;

create or replace function public.school_registry_prefect_bootstrap(p_actor_person_id uuid, p_assignments jsonb default '[]'::jsonb)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_item jsonb;
  v_student uuid;
  v_session text;
  v_office text;
  v_existing uuid;
  v_count integer := 0;
begin
  if not wts_internal.school_registry_is_protected_actor(p_actor_person_id) then return jsonb_build_object('ok',false,'code','REGISTRY_CAPABILITY_DENIED'); end if;
  if exists(select 1 from public.school_prefect_bootstrap where id=true and completed_at is not null) then return jsonb_build_object('ok',false,'code','PREFECT_BOOTSTRAP_ALREADY_COMPLETED'); end if;
  if jsonb_typeof(coalesce(p_assignments,'[]'::jsonb)) <> 'array' then return jsonb_build_object('ok',false,'code','PREFECT_BOOTSTRAP_ASSIGNMENTS_REQUIRED'); end if;
  if jsonb_array_length(coalesce(p_assignments,'[]'::jsonb)) = 0 then return jsonb_build_object('ok',false,'code','PREFECT_BOOTSTRAP_ASSIGNMENTS_REQUIRED'); end if;
  if jsonb_array_length(coalesce(p_assignments,'[]'::jsonb)) > 100 then return jsonb_build_object('ok',false,'code','PREFECT_BOOTSTRAP_TOO_LARGE'); end if;
  if (select count(*) from jsonb_array_elements(p_assignments)) <> (select count(distinct (value->>'studentId')||E'\x1f'||lower(trim(coalesce(value->>'officeName','')))) from jsonb_array_elements(p_assignments)) then return jsonb_build_object('ok',false,'code','PREFECT_BOOTSTRAP_DUPLICATE_APPOINTMENT'); end if;
  select value into v_session from public.settings where key='session';
  if nullif(trim(coalesce(v_session,'')),'') is null then return jsonb_build_object('ok',false,'code','ACADEMIC_CONTEXT_INCOMPLETE'); end if;

  -- Validate the complete verified document before changing a single
  -- appointment. A malformed later row must never leave a partial import.
  for v_item in select value from jsonb_array_elements(coalesce(p_assignments,'[]'::jsonb)) loop
    begin v_student := (v_item->>'studentId')::uuid; exception when others then return jsonb_build_object('ok',false,'code','PREFECT_STUDENT_INVALID'); end;
    v_office := nullif(trim(coalesce(v_item->>'officeName','')),'');
    if v_office is null or length(v_office)<2 or length(v_office)>120 then return jsonb_build_object('ok',false,'code','PREFECT_OFFICE_REQUIRED'); end if;
    if not exists(select 1 from public.students s where s.id=v_student and not s.archived and s.class_key='ss3-general') then
      -- Bootstrap accepts the already selected SS3 student records only; no
      -- synthetic student or merit decision is created.
      if not exists(select 1 from public.students s where s.id=v_student and not s.archived and s.class_key like 'ss3-%') then return jsonb_build_object('ok',false,'code','PREFECT_BOOTSTRAP_STUDENT_INVALID'); end if;
    end if;
  end loop;

  for v_item in select value from jsonb_array_elements(p_assignments) loop
    v_student := (v_item->>'studentId')::uuid;
    v_office := trim(v_item->>'officeName');
    v_existing := null;
    select a.id into v_existing
    from public.school_portfolio_assignments a
    where a.portfolio_code='student_executive_council' and a.student_id=v_student
      and a.academic_session is not distinct from v_session and a.assignment_status='active'
      and lower(trim(coalesce(a.office_name,'')))=lower(v_office)
    order by a.created_at desc limit 1 for update;
    if v_existing is null then
      insert into public.school_portfolio_assignments(portfolio_code,holder_type,student_id,holder_person_id,academic_session,scope_type,office_name,assigned_by_person_id,reason,metadata)
      select 'student_executive_council','student',s.id,s.central_person_id,v_session,'self',v_office,p_actor_person_id,'Verified current SS3 Student Executive Council appointment',jsonb_build_object('source','verified_current_ss3_import','appointment_status','active')
      from public.students s where s.id=v_student and not s.archived;
    else
      update public.school_portfolio_assignments
      set office_name=v_office,
          reason='Verified current SS3 Student Executive Council appointment',
          metadata=metadata||jsonb_build_object('source','verified_current_ss3_import','appointment_status','active'),
          updated_at=now()
      where id=v_existing;
    end if;
    v_count := v_count + 1;
  end loop;
  insert into public.school_prefect_bootstrap(id,completed_at,completed_by_person_id,source,metadata) values(true,now(),p_actor_person_id,'verified_current_ss3_import',jsonb_build_object('academic_session',v_session,'appointments',v_count)) on conflict(id) do update set completed_at=excluded.completed_at,completed_by_person_id=excluded.completed_by_person_id,source=excluded.source,metadata=public.school_prefect_bootstrap.metadata||excluded.metadata;
  return jsonb_build_object('ok',true,'code','PREFECT_BOOTSTRAP_COMPLETED','registered',v_count,'academicSession',v_session);
end;
$function$;

revoke all on function public.school_registry_prefect_bootstrap(uuid,jsonb) from public, anon, authenticated;

create or replace function public.school_registry_prefect_activate(p_transition_run_id uuid)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_run public.school_academic_transition_runs%rowtype;
  v_candidate record;
  v_cycle_id uuid;
  v_count integer := 0;
begin
  select * into v_run from public.school_academic_transition_runs where id=p_transition_run_id;
  if not found then return jsonb_build_object('ok',false,'code','TRANSITION_NOT_FOUND'); end if;
  if v_run.transition_status <> 'applied' then return jsonb_build_object('ok',false,'code','TRANSITION_NOT_APPLIED'); end if;
  select cy.id into v_cycle_id
  from public.school_prefect_cycles cy
  where cy.academic_session=v_run.source_session
    and cy.source_term=v_run.source_term
    and cy.target_session=v_run.target_session
    and cy.cycle_status='approved'
  order by cy.approved_at desc nulls last
  limit 1;
  if v_cycle_id is null then return jsonb_build_object('ok',false,'code','PREFECT_CYCLE_NOT_APPROVED'); end if;
  if exists(
    select 1 from public.school_prefect_candidates c
    where c.cycle_id=v_cycle_id and c.candidate_status='approved'
      and nullif(trim(coalesce(c.office_name,'')),'') is null
  ) then return jsonb_build_object('ok',false,'code','PREFECT_OFFICES_REQUIRED'); end if;
  update public.school_portfolio_assignments
  set assignment_status='ended',effective_until=now(),metadata=metadata||jsonb_build_object('appointment_status','ended','ended_by_transition_run_id',p_transition_run_id),updated_at=now()
  where portfolio_code='student_executive_council'
    and holder_type='student'
    and assignment_status='active'
    and (academic_session is null or academic_session <> v_run.target_session);
  for v_candidate in select c.*,cy.target_session from public.school_prefect_candidates c join public.school_prefect_cycles cy on cy.id=c.cycle_id where cy.id=v_cycle_id and c.candidate_status='approved' loop
    insert into public.school_portfolio_assignments(portfolio_code,holder_type,student_id,holder_person_id,academic_session,scope_type,office_name,assigned_by_person_id,reason,metadata)
    select 'student_executive_council','student',s.id,s.central_person_id,v_run.target_session,'self',v_candidate.office_name,v_candidate.approved_by_person_id,'Annual Student Executive Council activation',jsonb_build_object('source','annual_selection','cycle_id',v_candidate.cycle_id,'appointment_status','active')
    from public.students s where s.id=v_candidate.student_id and not s.archived on conflict do nothing;
    update public.school_prefect_candidates set candidate_status='activated' where id=v_candidate.id;
    v_count := v_count + 1;
  end loop;
  update public.school_prefect_cycles set cycle_status='activated',activated_at=now() where id=v_cycle_id;
  return jsonb_build_object('ok',true,'code','PREFECT_ASSIGNMENTS_ACTIVATED','activated',v_count);
end;
$function$;

revoke all on function public.school_registry_prefect_activate(uuid) from public, anon, authenticated;
