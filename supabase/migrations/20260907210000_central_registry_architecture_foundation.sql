-- Central Registry v2 additive architecture foundation.
-- Preserves existing identities, student rows, permanent numbers, grants,
-- allocations and academic history. No destructive student SQL is present.

alter table public.school_classes
  add column if not exists stage_code text;

-- Existing production rows may contain legacy section labels or a malformed
-- stage value. Normalize only values we can prove; leave unknown rows NULL so
-- the additive migration remains applicable and the Registry can surface a
-- configuration warning instead of guessing a real school classification.
update public.school_classes
set stage_code = case lower(trim(stage_code))
  when 'early_childhood' then 'early_childhood'
  when 'primary' then 'primary'
  when 'secondary' then 'secondary'
  else null
end
where stage_code is not null;

do $migration$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'school_classes_stage_code_check'
      and conrelid = 'public.school_classes'::regclass
  ) then
    alter table public.school_classes
      add constraint school_classes_stage_code_check
      check (stage_code is null or stage_code in ('early_childhood','primary','secondary'));
  end if;
end
$migration$;

update public.school_classes
set stage_code = case
  when lower(class_key) in ('creche','kg1','kg2','nursery1','nursery2') then 'early_childhood'
  when lower(class_key) like 'primary%' then 'primary'
  when lower(class_key) like 'jss%' or lower(class_key) like 'ss%' then 'secondary'
  else case lower(trim(coalesce(section, '')))
    when 'early_childhood' then 'early_childhood'
    when 'early childhood' then 'early_childhood'
    when 'primary' then 'primary'
    when 'secondary' then 'secondary'
    else null
  end
end
where stage_code is null;

update public.school_classes
set display_name = case lower(class_key)
  when 'creche' then 'Creche'
  when 'kg1' then 'KG 1'
  when 'kg2' then 'KG 2'
  when 'nursery1' then 'Nursery 1'
  when 'nursery2' then 'Nursery 2'
  when 'primary1' then 'Primary 1'
  when 'primary2' then 'Primary 2'
  when 'primary3' then 'Primary 3'
  when 'primary4' then 'Primary 4'
  when 'primary5' then 'Primary 5'
  when 'jss1' then 'JSS 1'
  when 'jss2' then 'JSS 2'
  when 'jss3' then 'JSS 3'
  when 'ss1-general' then 'SS 1 General'
  when 'ss2-science' then 'SS 2 Science'
  when 'ss2-arts' then 'SS 2 Arts'
  when 'ss2-business' then 'SS 2 Business'
  when 'ss3-science' then 'SS 3 Science'
  when 'ss3-arts' then 'SS 3 Arts'
  when 'ss3-business' then 'SS 3 Business'
  else coalesce(nullif(trim(display_name), ''), initcap(replace(class_key, '-', ' ')))
end,
sort_order = case lower(class_key)
  when 'creche' then 10 when 'kg1' then 20 when 'kg2' then 30
  when 'nursery1' then 40 when 'nursery2' then 50
  when 'primary1' then 100 when 'primary2' then 110 when 'primary3' then 120
  when 'primary4' then 130 when 'primary5' then 140
  when 'jss1' then 200 when 'jss2' then 210 when 'jss3' then 220
  when 'ss1-general' then 300 when 'ss2-science' then 310 when 'ss2-arts' then 320
  when 'ss2-business' then 330 when 'ss3-science' then 400 when 'ss3-arts' then 410
  when 'ss3-business' then 420 else 900 end
where lower(class_key) not like 'archive-%';

update public.school_classes set is_active = false where lower(class_key) like 'archive-%';

insert into public.school_classes(class_key, display_name, section, sort_order, is_active, stage_code)
values ('ss3-business', 'SS 3 Business', 'secondary', 420, true, 'secondary')
on conflict (class_key) do update
set display_name = excluded.display_name,
    section = excluded.section,
    sort_order = excluded.sort_order,
    is_active = true,
    stage_code = excluded.stage_code;

-- Carry the verified Business subject structure forward without overwriting
-- any SS3 Business subject rows that management may already have configured.
insert into public.result_subject_catalog(class_key, subject_index, subject_name, aliases, active)
select 'ss3-business', r.subject_index, r.subject_name, r.aliases, r.active
from public.result_subject_catalog r
where r.class_key = 'ss2-business'
on conflict (class_key, subject_index) do nothing;

alter table public.staff_attendance_profiles
  add column if not exists signature_path text,
  add column if not exists signature_uploaded_at timestamptz,
  add column if not exists emergency_contact text;

comment on column public.staff_attendance_profiles.emergency_contact is
  'Self-maintained emergency contact supplied by the staff member; Registry never invents this value.';

create table if not exists public.school_portfolio_catalog (
  portfolio_code text primary key,
  portfolio_name text not null,
  holder_type text not null check (holder_type in ('staff','student')),
  jurisdiction text not null check (jurisdiction in ('school','stage','class','self','none')),
  is_protected boolean not null default false,
  is_singleton boolean not null default false,
  is_active boolean not null default true,
  sort_order integer not null default 100,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.school_portfolio_assignments (
  id uuid primary key default gen_random_uuid(),
  portfolio_code text not null references public.school_portfolio_catalog(portfolio_code),
  holder_type text not null check (holder_type in ('staff','student')),
  staff_id uuid references public.staff_attendance_profiles(id),
  student_id uuid references public.students(id),
  holder_person_id uuid references public.school_people(id),
  academic_session text,
  scope_type text not null default 'school' check (scope_type in ('school','stage','class','self')),
  stage_code text,
  class_key text references public.school_classes(class_key),
  office_name text,
  assignment_status text not null default 'active' check (assignment_status in ('active','ended','revoked')),
  effective_from timestamptz not null default now(),
  effective_until timestamptz,
  assigned_by_person_id uuid references public.school_people(id),
  reason text not null default 'Central Registry portfolio assignment',
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (effective_until is null or effective_until > effective_from),
  check ((holder_type = 'staff' and staff_id is not null and student_id is null)
      or (holder_type = 'student' and student_id is not null and staff_id is null)),
  check ((scope_type = 'stage' and stage_code is not null and class_key is null)
      or (scope_type = 'class' and class_key is not null)
      or (scope_type in ('school','self')))
);

alter table public.school_portfolio_assignments
  add column if not exists office_name text;

do $migration$
begin
  if not exists (
    select 1 from pg_constraint
    where conname='school_portfolio_assignments_office_name_check'
      and conrelid='public.school_portfolio_assignments'::regclass
  ) then
    alter table public.school_portfolio_assignments
      add constraint school_portfolio_assignments_office_name_check
      check (office_name is null or length(trim(office_name)) between 2 and 120);
  end if;
end
$migration$;

create index if not exists school_portfolio_assignments_active_holder_idx
  on public.school_portfolio_assignments(holder_type, staff_id, student_id, assignment_status, effective_from);
create index if not exists school_portfolio_assignments_scope_idx
  on public.school_portfolio_assignments(scope_type, stage_code, class_key, assignment_status);
create index if not exists school_portfolio_assignments_active_person_idx
  on public.school_portfolio_assignments(holder_person_id, assignment_status, effective_from)
  where holder_person_id is not null;

create table if not exists public.school_registry_capability_catalog (
  capability_code text primary key,
  capability_name text not null,
  description text not null,
  is_protected boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists public.school_portfolio_capabilities (
  portfolio_code text not null references public.school_portfolio_catalog(portfolio_code) on delete cascade,
  capability_code text not null references public.school_registry_capability_catalog(capability_code) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (portfolio_code, capability_code)
);

create table if not exists public.school_portfolio_stage_scopes (
  portfolio_code text not null references public.school_portfolio_catalog(portfolio_code) on delete cascade,
  stage_code text not null check (stage_code in ('early_childhood','primary','secondary')),
  created_at timestamptz not null default now(),
  primary key (portfolio_code, stage_code)
);

create table if not exists public.school_portal_access_policy (
  app_code text primary key references public.school_portal_catalog(app_code),
  entry_policy text not null check (entry_policy in ('all_active_staff','senior_management','configured_only')),
  default_access_role text not null default 'staff',
  automatic_entry boolean not null default false,
  policy_version integer not null default 1,
  is_active boolean not null default true,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.school_module_operating_controls (
  app_code text primary key references public.school_portal_catalog(app_code),
  operating_mode text not null check (operating_mode in ('active','read_only','pilot','disabled')),
  reason text not null,
  updated_by_person_id uuid references public.school_people(id),
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.school_portal_feature_policy (
  app_code text not null references public.school_portal_catalog(app_code) on delete cascade,
  feature_code text not null,
  minimum_capability text,
  protected boolean not null default false,
  default_enabled boolean not null default false,
  created_at timestamptz not null default now(),
  primary key (app_code, feature_code)
);

create table if not exists public.school_registry_request_outcomes (
  request_id uuid primary key,
  actor_person_id uuid references public.school_people(id),
  operation text not null,
  outcome jsonb not null,
  created_at timestamptz not null default now()
);

alter table public.school_portfolio_catalog enable row level security;
alter table public.school_portfolio_assignments enable row level security;
alter table public.school_registry_capability_catalog enable row level security;
alter table public.school_portfolio_capabilities enable row level security;
alter table public.school_portfolio_stage_scopes enable row level security;
alter table public.school_portal_access_policy enable row level security;
alter table public.school_module_operating_controls enable row level security;
alter table public.school_portal_feature_policy enable row level security;
alter table public.school_registry_request_outcomes enable row level security;

revoke all on table public.school_portfolio_catalog,
  public.school_portfolio_assignments,
  public.school_registry_capability_catalog,
  public.school_portfolio_capabilities,
  public.school_portfolio_stage_scopes,
  public.school_portal_access_policy,
  public.school_module_operating_controls,
  public.school_portal_feature_policy,
  public.school_registry_request_outcomes
from public, anon, authenticated;

insert into public.school_portfolio_catalog(portfolio_code, portfolio_name, holder_type, jurisdiction, is_protected, is_singleton, sort_order)
values
  ('developer','Developer / System Owner','staff','school',true,true,10),
  ('proprietor','Proprietor','staff','school',true,true,20),
  ('director','Director','staff','school',false,false,30),
  ('principal','Principal','staff','school',false,true,40),
  ('vice_principal','Vice Principal','staff','school',false,false,50),
  ('director_primary','Director of Primary School Affairs','staff','stage',false,true,60),
  ('headmistress','Headmistress','staff','stage',false,true,70),
  ('assistant_headmistress','Assistant Headmistress','staff','stage',false,false,80),
  ('bursar','Bursar','staff','self',false,false,90),
  ('class_teacher','Class Teacher','staff','class',false,false,100),
  ('subject_teacher','Subject Teacher','staff','self',false,false,110),
  ('student_executive_council','Student Executive Council','student','self',false,false,200)
on conflict (portfolio_code) do update set
  portfolio_name = excluded.portfolio_name,
  holder_type = excluded.holder_type,
  jurisdiction = excluded.jurisdiction,
  is_protected = excluded.is_protected,
  is_singleton = excluded.is_singleton,
  sort_order = excluded.sort_order,
  updated_at = now();

-- System ownership remains explicit authorization data. It is not a school
-- office and must not be assignable or visible as an ordinary portfolio.
update public.school_portfolio_catalog
set metadata = metadata || jsonb_build_object('visibility','technical_only'),
    updated_at = now()
where portfolio_code = 'developer';

insert into public.school_registry_capability_catalog(capability_code, capability_name, description, is_protected)
values
  ('registry.enter','Enter Central Registry','Open the role-aware Central Registry shell.',false),
  ('students.school.read','Read school students','Read students across the school.',false),
  ('students.stage.read','Read stage students','Read students in permitted stages.',false),
  ('students.class.read','Read allocated class students','Read students in allocated classes.',false),
  ('students.school.manage','Manage school students','Create, update, archive and restore school students.',false),
  ('students.class.manage','Manage allocated class students','Maintain only students in allocated classes.',false),
  ('staff.school.read','Read school staff','Read the school staff directory.',false),
  ('staff.stage.read','Read stage staff','Read staff allocated to permitted stages.',false),
  ('profile.self.read','Read own profile','Read the actor profile.',false),
  ('profile.self.update','Update own profile','Update permitted personal fields.',false),
  ('profile.signature.update','Upload own signature','Upload a private signature image.',false),
  ('allocations.read','Read allocations','Read permitted allocations.',false),
  ('allocations.school.manage','Manage school allocations','Manage class and subject allocations.',true),
  ('allocations.early_childhood.manage','Manage early-childhood allocations','Manage early-childhood class allocations.',false),
  ('portal_access.manage','Manage portal access','Manage connected module entry and roles.',true),
  ('portal.operating_mode.manage','Manage portal operating mode','Place approved portals on hold or return them to normal operation.',true),
  ('academic_calendar.read','Read academic calendar','Read official academic context.',false),
  ('academic_calendar.manage','Manage academic calendar','Create, close and transition academic context.',true),
  ('portfolio.self.read','Read own portfolios','Read actor portfolio assignments.',false),
  ('portfolio.manage','Manage portfolios','Manage portfolio definitions and assignments.',true),
  ('student.prefect.manage','Manage prefect cycle','Run the annual Student Executive Council workflow.',true),
  ('portal.results.admin','Administer Results','Unlock Results settings, smart recording and full write.',true),
  ('attendance.setup','Attendance setup','Configure Attendance.',true),
  ('attendance.qr_generation','Generate attendance QR','Generate Attendance QR codes.',true)
on conflict (capability_code) do update set
  capability_name = excluded.capability_name,
  description = excluded.description,
  is_protected = excluded.is_protected;

insert into public.school_portfolio_capabilities(portfolio_code, capability_code)
select x.portfolio_code, x.capability_code
from (values
  ('developer','students.school.read'),('developer','students.school.manage'),('developer','staff.school.read'),('developer','allocations.read'),('developer','allocations.school.manage'),('developer','portal_access.manage'),('developer','portal.operating_mode.manage'),('developer','academic_calendar.manage'),('developer','portfolio.manage'),('developer','student.prefect.manage'),('developer','portal.results.admin'),('developer','attendance.setup'),('developer','attendance.qr_generation'),
  ('proprietor','students.school.read'),('proprietor','students.school.manage'),('proprietor','staff.school.read'),('proprietor','allocations.read'),('proprietor','allocations.school.manage'),('proprietor','portal_access.manage'),('proprietor','academic_calendar.manage'),('proprietor','portfolio.manage'),('proprietor','student.prefect.manage'),('proprietor','portal.results.admin'),
  ('director','students.school.read'),('director','students.school.manage'),('director','staff.school.read'),('director','allocations.read'),('director','academic_calendar.read'),
  ('principal','students.school.read'),('principal','students.school.manage'),('principal','staff.school.read'),('principal','allocations.read'),('principal','academic_calendar.read'),
  ('vice_principal','students.school.read'),('vice_principal','students.school.manage'),('vice_principal','staff.school.read'),('vice_principal','allocations.read'),('vice_principal','academic_calendar.read'),
  ('director_primary','students.stage.read'),('director_primary','staff.stage.read'),('director_primary','allocations.read'),
  ('headmistress','students.stage.read'),('headmistress','staff.stage.read'),('headmistress','allocations.read'),('headmistress','allocations.early_childhood.manage'),
  ('assistant_headmistress','students.stage.read'),('assistant_headmistress','staff.stage.read'),('assistant_headmistress','allocations.read'),('assistant_headmistress','allocations.early_childhood.manage'),
  ('class_teacher','students.class.read'),('class_teacher','students.class.manage'),('class_teacher','allocations.read'),
  ('subject_teacher','allocations.read'),('bursar','profile.self.read')
) as x(portfolio_code, capability_code)
where exists (select 1 from public.school_portfolio_catalog p where p.portfolio_code = x.portfolio_code)
  and exists (select 1 from public.school_registry_capability_catalog c where c.capability_code = x.capability_code)
on conflict do nothing;

insert into public.school_portfolio_stage_scopes(portfolio_code, stage_code)
values
  ('director_primary','early_childhood'),('director_primary','primary'),
  ('headmistress','early_childhood'),('assistant_headmistress','early_childhood')
on conflict do nothing;

insert into public.school_portal_access_policy(app_code, entry_policy, default_access_role, automatic_entry)
values
  ('central_registry','all_active_staff','staff',true),
  ('results','all_active_staff','staff',true),
  ('attendance','configured_only','attendance_admin',false),
  ('notifications','configured_only','staff',false),
  ('finance','configured_only','staff',false),
  ('staff_self_service','all_active_staff','staff',true)
on conflict (app_code) do update set
  entry_policy = excluded.entry_policy,
  default_access_role = excluded.default_access_role,
  automatic_entry = excluded.automatic_entry,
  policy_version = public.school_portal_access_policy.policy_version + 1,
  updated_at = now();

insert into public.school_module_operating_controls(app_code, operating_mode, reason, metadata)
values
  ('central_registry','active','Central Registry is the active system of record.',jsonb_build_object('policy','registry_v2')),
  ('results','read_only','Result recording is on management hold; authorised staff may view existing results.',jsonb_build_object('policy','management_hold')),
  ('attendance','pilot','Attendance is restricted to the audited technical developer account for the SS2 pilot.',jsonb_build_object('pilot_scope','SS2','technical_account_only',true)),
  ('notifications','disabled','Notifications are not in operational use pending management policy approval.',jsonb_build_object('policy','disabled_pending_approval')),
  ('finance','disabled','Finance is not exposed through the current staff workspace.',jsonb_build_object('policy','not_in_current_workspace')),
  ('staff_self_service','active','Staff Workspace is active.',jsonb_build_object('policy','staff_entry'))
on conflict (app_code) do nothing;

insert into public.school_portal_feature_policy(app_code, feature_code, minimum_capability, protected, default_enabled)
values
  ('results','settings','portal.results.admin',true,false),
  ('results','smart_recording','portal.results.admin',true,false),
  ('results','full_write','portal.results.admin',true,false),
  ('attendance','setup','attendance.setup',true,false),
  ('attendance','qr_generation','attendance.qr_generation',true,false)
on conflict (app_code, feature_code) do update set
  minimum_capability = excluded.minimum_capability,
  protected = excluded.protected,
  default_enabled = excluded.default_enabled;

create or replace function wts_internal.school_registry_session_entitlements(
  p_session_id uuid,
  p_session_secret text
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
  v_now timestamptz := now();
  v_capabilities text[] := array['registry.enter','profile.self.read','profile.self.update','profile.signature.update','academic_calendar.read','portfolio.self.read'];
  v_portfolios text[] := array[]::text[];
  v_stage_scopes text[] := array[]::text[];
  v_class_scopes text[] := array[]::text[];
  v_subject_scopes jsonb := '[]'::jsonb;
  v_authority jsonb := '{}'::jsonb;
  v_authority_portfolio text;
  v_current jsonb := '{}'::jsonb;
begin
  select s.* into v_session
  from public.school_identity_sessions s
  where s.id = p_session_id
    and s.target_app_code = 'central_registry'
    and s.revoked_at is null
    and s.expires_at > v_now
    and encode(digest(coalesce(p_session_secret,''), 'sha256'), 'hex') = s.secret_hash;
  if not found then return jsonb_build_object('ok',false,'code','REGISTRY_SESSION_REQUIRED'); end if;

  select p.* into v_person from public.school_people p where p.id = v_session.person_id;
  select s.* into v_staff from public.staff_attendance_profiles s
  where s.central_person_id = v_session.person_id order by s.created_at limit 1;
  if v_person.id is null or v_person.person_status <> 'active'
     or v_staff.id is null or v_staff.registration_status <> 'active'
     or v_staff.employment_status <> 'active' then
    return jsonb_build_object('ok',false,'code','REGISTRY_IDENTITY_NOT_ACTIVE');
  end if;
  -- All active staff enter by default, but an explicit Registry revocation is
  -- authoritative and must take effect on the very next request.
  if exists (
    select 1
    from public.school_access_grants g
    where g.person_id = v_person.id
      and g.app_code = 'central_registry'
      and not (
        g.grant_status = 'active'
        and (g.valid_from is null or g.valid_from <= v_now)
        and (g.valid_until is null or g.valid_until > v_now)
      )
  ) then
    return jsonb_build_object('ok',false,'code','REGISTRY_ACCESS_NOT_GRANTED');
  end if;

  begin
    v_authority := coalesce(wts_internal.institutional_authority(v_person.id), '{}'::jsonb);
  exception when undefined_function then
    v_authority := '{}'::jsonb;
  end;

  select coalesce(array_agg(distinct a.portfolio_code order by a.portfolio_code), array[]::text[])
    into v_portfolios
  from public.school_portfolio_assignments a
  join public.school_portfolio_catalog pc on pc.portfolio_code=a.portfolio_code
  where a.holder_type = 'staff' and a.staff_id = v_staff.id
    and coalesce(pc.metadata->>'visibility','school') <> 'technical_only'
    and a.assignment_status = 'active' and a.effective_from <= v_now
    and (a.effective_until is null or a.effective_until > v_now);
  if coalesce((v_authority ->> 'active')::boolean,false) is true then
    v_authority_portfolio := case lower(coalesce(v_authority ->> 'classification',''))
      when 'system_owner' then 'developer'
      else lower(coalesce(v_authority ->> 'classification',''))
    end;
  end if;
  v_portfolios := array(
    select distinct p from unnest(coalesce(v_portfolios,array[]::text[]) || array['staff']) p where p <> ''
  );

  -- Institutional authority is an existing protected identity foundation,
  -- not a browser-supplied portfolio row. Map it into the same catalog so the
  -- owner/proprietor retain their approved school-wide controls even when no
  -- v2 assignment has yet been materialized for them.
  select coalesce(array_agg(distinct pc.capability_code order by pc.capability_code), array[]::text[])
    into v_capabilities
  from public.school_portfolio_capabilities pc
  where pc.portfolio_code = any(
    coalesce(v_portfolios, array[]::text[])
      || case when nullif(v_authority_portfolio,'') is null then array[]::text[] else array[v_authority_portfolio] end
  );
  v_capabilities := array(
    select distinct c from unnest(coalesce(v_capabilities,array[]::text[]) || array['registry.enter','profile.self.read','profile.self.update','profile.signature.update','academic_calendar.read','portfolio.self.read']) c where c <> ''
  );

  select coalesce(array_agg(distinct a.stage_code order by a.stage_code), array[]::text[])
    into v_stage_scopes
  from public.school_portfolio_assignments a
  join public.school_portfolio_stage_scopes s on s.portfolio_code = a.portfolio_code and s.stage_code = a.stage_code
  where a.holder_type = 'staff' and a.staff_id = v_staff.id
    and a.scope_type = 'stage' and a.stage_code is not null
    and a.assignment_status = 'active' and a.effective_from <= v_now
    and (a.effective_until is null or a.effective_until > v_now);

  v_current := public.school_academic_current();
  select coalesce(array_agg(distinct x.class_key order by x.class_key), array[]::text[])
    into v_class_scopes
  from (
    select a.class_key
    from public.school_staff_class_allocations a
    where a.person_id = v_person.id and a.allocation_status = 'active'
      and a.effective_from <= v_now and (a.effective_until is null or a.effective_until > v_now)
      and a.academic_session = (v_current ->> 'academic_session')
      and a.term_name = (v_current ->> 'term')
    union
    select a.class_key
    from public.school_portfolio_assignments a
    where a.holder_type = 'staff' and a.staff_id = v_staff.id
      and a.scope_type = 'class' and a.class_key is not null
      and a.assignment_status = 'active' and a.effective_from <= v_now
      and (a.effective_until is null or a.effective_until > v_now)
  ) x;
  if coalesce(array_length(v_class_scopes,1),0) > 0 then
    v_capabilities := array_append(v_capabilities,'students.class.read');
    v_capabilities := array_append(v_capabilities,'students.class.manage');
  end if;

  select coalesce(jsonb_agg(jsonb_build_object('class_key',a.class_key,'subject_index',a.subject_index) order by a.class_key,a.subject_index), '[]'::jsonb)
    into v_subject_scopes
  from public.school_staff_subject_allocations a
  where a.person_id = v_person.id and a.allocation_status = 'active'
    and a.effective_from <= v_now and (a.effective_until is null or a.effective_until > v_now)
    and a.academic_session = (v_current ->> 'academic_session')
    and a.term_name = (v_current ->> 'term');

  return jsonb_build_object(
    'ok',true,
    'actor',jsonb_build_object('personId',v_person.id,'staffId',v_staff.id,'staffNumber',v_staff.staff_number,'fullName',v_staff.full_name,'designation',case when lower(coalesce(v_staff.designation,'')) ~ '(super[ _-]*administrator|system[ _-]*owner|developer)' then null else v_staff.designation end,'photo',v_staff.photo,'signaturePath',v_staff.signature_path),
    'academicContext',jsonb_build_object('session',v_current->>'academic_session','term',v_current->>'term','termStatus',v_current->>'term_status'),
    'entitlements',jsonb_build_object('capabilities',coalesce(v_capabilities,array[]::text[]),'portfolios',coalesce(v_portfolios,array[]::text[]),'stageScopes',coalesce(v_stage_scopes,array[]::text[]),'classScopes',coalesce(v_class_scopes,array[]::text[]),'subjectScopes',v_subject_scopes,'technicalPrivileges',case when coalesce((v_authority->>'active')::boolean,false) then jsonb_build_object('active',true,'classification',v_authority->>'classification','source','institutional_authority') else jsonb_build_object('active',false) end),
    'portalPolicies',(select coalesce(jsonb_agg(to_jsonb(p) order by p.app_code),'[]'::jsonb) from public.school_portal_access_policy p where p.is_active),
    'flags',jsonb_build_object('guardianReadiness',true)
  );
end;
$function$;

revoke all on function wts_internal.school_registry_session_entitlements(uuid,text) from public, anon, authenticated;
