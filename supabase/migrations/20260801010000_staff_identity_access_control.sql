-- WTS staff identity, role and permission control.
--
-- This is deliberately additive. It extends the existing Central Registry
-- identity chain and does not alter students, scores, legacy Result Portal
-- accounts or password hashes. The Result Portal hardening migration remains
-- a separate, coordinated release because its core tables are still used by a
-- browser client through direct Data API calls.

-- Public-directory fields remain opt-in. Active employment never publishes a
-- person automatically.
alter table public.staff_attendance_profiles
  add column if not exists public_visibility_approved boolean not null default false,
  add column if not exists public_display_name text,
  add column if not exists public_display_role text,
  add column if not exists public_display_order integer,
  add column if not exists public_visibility_approved_at timestamptz,
  add column if not exists public_visibility_approved_by_person_id uuid references public.school_people(id);

-- A role describes a responsibility. It does not itself grant a module or an
-- action. Explicit grants below remain the source of enforceable access.
create table if not exists public.school_system_role_catalog (
  role_code text primary key,
  role_name text not null,
  description text not null,
  is_assignable boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.school_permission_catalog (
  permission_code text primary key,
  app_code text not null references public.school_portal_catalog(app_code),
  module_code text not null,
  module_name text not null,
  action_code text not null check (action_code in ('view','create','edit','submit','review','approve','publish','delete','export','administer')),
  description text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (app_code, module_code, action_code)
);

-- Role templates are guidance only. They never create a live grant until an
-- authorised management user assigns explicit module permissions.
create table if not exists public.school_system_role_permissions (
  role_code text not null references public.school_system_role_catalog(role_code) on delete cascade,
  permission_code text not null references public.school_permission_catalog(permission_code) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (role_code, permission_code)
);

create table if not exists public.school_staff_role_assignments (
  id uuid primary key default gen_random_uuid(),
  person_id uuid not null references public.school_people(id),
  role_code text not null references public.school_system_role_catalog(role_code),
  assignment_status text not null default 'active' check (assignment_status in ('active','suspended','revoked','expired')),
  effective_from timestamptz not null default now(),
  effective_until timestamptz,
  assigned_by_person_id uuid references public.school_people(id),
  assigned_at timestamptz not null default now(),
  revoked_by_person_id uuid references public.school_people(id),
  revoked_at timestamptz,
  revocation_reason text,
  reason text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (person_id, role_code),
  check (effective_until is null or effective_until > effective_from)
);

-- Scopes provide the class and subject boundaries used by Result Management.
-- The subject foreign key deliberately reuses the existing, real
-- result_subject_catalog maintained for the Result Portal.
create table if not exists public.school_staff_access_scopes (
  id uuid primary key default gen_random_uuid(),
  person_id uuid not null references public.school_people(id),
  app_code text not null references public.school_portal_catalog(app_code),
  scope_type text not null check (scope_type in ('class','subject')),
  class_key text not null references public.school_classes(class_key),
  subject_index integer,
  scope_status text not null default 'active' check (scope_status in ('active','suspended','revoked','expired')),
  effective_from timestamptz not null default now(),
  effective_until timestamptz,
  assigned_by_person_id uuid references public.school_people(id),
  assigned_at timestamptz not null default now(),
  revoked_by_person_id uuid references public.school_people(id),
  revoked_at timestamptz,
  revocation_reason text,
  reason text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check ((scope_type='class' and subject_index is null) or (scope_type='subject' and subject_index is not null and subject_index >= 0)),
  check (effective_until is null or effective_until > effective_from),
  foreign key (class_key, subject_index) references public.result_subject_catalog(class_key, subject_index)
);

alter table public.school_access_grants
  add column if not exists revoked_by_person_id uuid references public.school_people(id),
  add column if not exists revoked_at timestamptz,
  add column if not exists revocation_reason text;

create index if not exists school_staff_role_assignments_active_person_idx
  on public.school_staff_role_assignments (person_id, assignment_status, effective_from desc);
create index if not exists school_staff_access_scopes_active_person_idx
  on public.school_staff_access_scopes (person_id, app_code, scope_status, effective_from desc);
create index if not exists school_staff_access_scopes_class_subject_idx
  on public.school_staff_access_scopes (app_code, class_key, subject_index, scope_status);
create index if not exists school_registry_audit_staff_id_idx
  on public.school_registry_audit ((details->>'staff_id'), created_at desc);

alter table public.school_system_role_catalog enable row level security;
alter table public.school_permission_catalog enable row level security;
alter table public.school_system_role_permissions enable row level security;
alter table public.school_staff_role_assignments enable row level security;
alter table public.school_staff_access_scopes enable row level security;

insert into public.school_system_role_catalog(role_code, role_name, description) values
  ('teacher','Teacher','Delivers learning and receives only explicitly assigned teaching tools.'),
  ('class_teacher','Class Teacher','Holds explicit class-level responsibilities in addition to teaching work.'),
  ('principal','Principal','Receives only the approved academic and operational oversight permissions.'),
  ('vice_principal','Vice Principal','Receives delegated academic and operational permissions assigned by management.'),
  ('proprietor','Proprietor','Receives explicitly approved executive oversight permissions.'),
  ('registry_administrator','Registry Administrator','Maintains authorised Central Registry identity and admissions records.'),
  ('results_administrator','Results Administrator','Administers approved result workflows and release controls.'),
  ('attendance_administrator','Attendance Administrator','Manages approved attendance operations and reports.'),
  ('communications_administrator','Communications Administrator','Manages approved communications, templates and delivery follow-up.'),
  ('super_administrator','Super Administrator','Holds tightly controlled platform administration permissions with audit review.')
on conflict (role_code) do update set role_name=excluded.role_name,description=excluded.description,updated_at=now();

insert into public.school_permission_catalog(permission_code,app_code,module_code,module_name,action_code,description) values
  ('staff_profile.view','staff_self_service','staff_profile','Staff Profile','view','View the authorised staff profile.'),
  ('staff_profile.edit','staff_self_service','staff_profile','Staff Profile','edit','Edit authorised self-service profile fields.'),
  ('classes_subjects.view','results','classes_subjects','Classes and Subjects','view','View only assigned classes and subjects.'),
  ('result_entry.view','results','result_entry','Result Entry','view','Open authorised score-entry work.'),
  ('result_entry.create','results','result_entry','Result Entry','create','Create score entries within an authorised scope.'),
  ('result_entry.edit','results','result_entry','Result Entry','edit','Edit score entries within an authorised scope.'),
  ('result_entry.submit','results','result_entry','Result Entry','submit','Submit authorised completed score work for review.'),
  ('result_review.view','results','result_review','Result Review','view','View authorised result submissions for review.'),
  ('result_review.review','results','result_review','Result Review','review','Review authorised result submissions.'),
  ('result_approval.view','results','result_approval','Result Approval','view','View authorised results awaiting approval.'),
  ('result_approval.approve','results','result_approval','Result Approval','approve','Approve authorised result submissions.'),
  ('report_cards.view','results','report_cards','Report Card Generation','view','View authorised report-card generation tools.'),
  ('report_cards.generate','results','report_cards','Report Card Generation','create','Generate authorised report cards.'),
  ('report_cards.export','results','report_cards','Report Card Generation','export','Export authorised report cards.'),
  ('result_publishing.view','results','result_publishing','Result Publishing','view','View authorised result-publishing controls.'),
  ('result_publishing.publish','results','result_publishing','Result Publishing','publish','Publish authorised approved results.'),
  ('central_registry.view','central_registry','central_registry','Central Registry','view','View authorised Central Registry records.'),
  ('central_registry.administer','central_registry','central_registry','Central Registry','administer','Administer authorised Central Registry functions.'),
  ('student_records.view','central_registry','student_records','Student Records','view','View authorised student records.'),
  ('student_records.create','central_registry','student_records','Student Records','create','Create authorised student records.'),
  ('student_records.edit','central_registry','student_records','Student Records','edit','Edit authorised student records.'),
  ('student_records.export','central_registry','student_records','Student Records','export','Export authorised student records.'),
  ('staff_management.view','central_registry','staff_management','Staff Management','view','View authorised staff-management records.'),
  ('staff_management.create','central_registry','staff_management','Staff Management','create','Create authorised staff-management records.'),
  ('staff_management.edit','central_registry','staff_management','Staff Management','edit','Edit authorised staff-management records.'),
  ('staff_management.administer','central_registry','staff_management','Staff Management','administer','Administer role, permission and access assignments.'),
  ('attendance.view','attendance','attendance','Attendance','view','View authorised attendance information.'),
  ('attendance.create','attendance','attendance','Attendance','create','Create authorised attendance entries.'),
  ('attendance.edit','attendance','attendance','Attendance','edit','Edit authorised attendance entries.'),
  ('attendance.review','attendance','attendance','Attendance','review','Review authorised attendance exceptions.'),
  ('attendance.export','attendance','attendance','Attendance','export','Export authorised attendance reports.'),
  ('notifications.view','notifications','notifications','Notifications','view','View authorised communication work.'),
  ('notifications.create','notifications','notifications','Notifications','create','Create authorised notification drafts.'),
  ('notifications.edit','notifications','notifications','Notifications','edit','Edit authorised notifications.'),
  ('notifications.approve','notifications','notifications','Notifications','approve','Approve authorised notifications.'),
  ('notifications.publish','notifications','notifications','Notifications','publish','Send authorised notifications.'),
  ('reports.view','central_registry','reports','Reports','view','View authorised cross-system reports.'),
  ('reports.export','central_registry','reports','Reports','export','Export authorised cross-system reports.'),
  ('public_website_content.view','central_registry','public_website_content','Public Website Content','view','View approved public website content controls.'),
  ('public_website_content.create','central_registry','public_website_content','Public Website Content','create','Create authorised public content drafts.'),
  ('public_website_content.edit','central_registry','public_website_content','Public Website Content','edit','Edit authorised public content drafts.'),
  ('public_website_content.publish','central_registry','public_website_content','Public Website Content','publish','Publish approved public website content.'),
  ('system_administration.view','central_registry','system_administration','System Administration','view','View authorised system-administration controls.'),
  ('system_administration.administer','central_registry','system_administration','System Administration','administer','Administer approved platform settings and integrations.')
on conflict (permission_code) do update set
  app_code=excluded.app_code,module_code=excluded.module_code,module_name=excluded.module_name,
  action_code=excluded.action_code,description=excluded.description,updated_at=now();

-- This helper validates an opaque Central Registry session on every call. It
-- does not trust browser-only UI state and checks employment, identity, and
-- self-service access again so suspension and revocation take effect quickly.
create or replace function public.school_identity_current_staff_session(
  p_client_code text,
  p_client_secret text
)
returns uuid
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_client public.attendance_admin_clients%rowtype;
  v_person_id uuid;
begin
  select * into v_client
  from public.attendance_admin_clients
  where client_code=trim(p_client_code)
    and status='active'
    and central_person_id is not null
    and session_expires_at>now();

  if not found or encode(digest(p_client_secret,'sha256'),'hex')<>v_client.secret_hash then
    return null;
  end if;

  v_person_id:=v_client.central_person_id;
  if not exists(
    select 1
    from public.school_people p
    join public.staff_attendance_profiles s on s.central_person_id=p.id
    join public.school_identity_accounts i on i.person_id=p.id
    join public.school_identity_credentials c on c.identity_account_id=i.id
    join public.school_access_grants g on g.person_id=p.id
    where p.id=v_person_id
      and p.person_status='active'
      and s.registration_status='active'
      and s.employment_status='active'
      and i.account_status='active'
      and c.credential_status='active'
      and g.app_code='staff_self_service'
      and g.grant_status='active'
      and g.valid_from<=now()
      and (g.valid_until is null or g.valid_until>now())
  ) then
    return null;
  end if;

  update public.attendance_admin_clients
  set last_seen_at=now(),updated_at=now()
  where id=v_client.id;
  return v_person_id;
end;
$function$;

create or replace function public.school_staff_workspace_read_api(
  p_client_code text,
  p_client_secret text
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_person_id uuid;
  v_staff public.staff_attendance_profiles%rowtype;
  v_management boolean:=false;
begin
  v_person_id:=public.school_identity_current_staff_session(p_client_code,p_client_secret);
  if v_person_id is null then
    return jsonb_build_object('ok',false,'code','STAFF_SESSION_NOT_ACTIVE');
  end if;

  select * into v_staff from public.staff_attendance_profiles where central_person_id=v_person_id;
  v_management:=exists(
    select 1 from public.school_access_grants g
    where g.person_id=v_person_id
      and g.grant_status='active'
      and g.valid_from<=now()
      and (g.valid_until is null or g.valid_until>now())
      and ('access.manage'=any(g.permissions) or 'registry.manage'=any(g.permissions)
           or 'staff_management.administer'=any(g.permissions) or 'system_administration.administer'=any(g.permissions))
  );

  return jsonb_build_object(
    'ok',true,
    'person',jsonb_build_object(
      'staff_id',v_staff.id,'staff_number',v_staff.staff_number,'full_name',v_staff.full_name,
      'designation',v_staff.designation,'staff_category',v_staff.staff_category
    ),
    'management_access',v_management,
    'roles',coalesce((
      select jsonb_agg(jsonb_build_object('role_code',r.role_code,'role_name',c.role_name,'effective_from',r.effective_from,'effective_until',r.effective_until) order by c.role_name)
      from public.school_staff_role_assignments r
      join public.school_system_role_catalog c on c.role_code=r.role_code
      where r.person_id=v_person_id and r.assignment_status='active'
        and r.effective_from<=now() and (r.effective_until is null or r.effective_until>now())
    ),'[]'::jsonb),
    'grants',coalesce((
      select jsonb_agg(jsonb_build_object('app_code',g.app_code,'access_role',g.access_role,'permissions',g.permissions,'valid_until',g.valid_until) order by g.app_code)
      from public.school_access_grants g
      where g.person_id=v_person_id and g.grant_status='active'
        and g.valid_from<=now() and (g.valid_until is null or g.valid_until>now())
    ),'[]'::jsonb),
    'class_assignments',coalesce((
      select jsonb_agg(jsonb_build_object('class_key',s.class_key,'display_name',c.display_name,'effective_until',s.effective_until) order by c.sort_order,c.display_name)
      from public.school_staff_access_scopes s
      join public.school_classes c on c.class_key=s.class_key
      where s.person_id=v_person_id and s.app_code='results' and s.scope_type='class'
        and s.scope_status='active' and s.effective_from<=now() and (s.effective_until is null or s.effective_until>now())
    ),'[]'::jsonb),
    'subject_assignments',coalesce((
      select jsonb_agg(jsonb_build_object('class_key',s.class_key,'display_name',c.display_name,'subject_index',s.subject_index,'subject_name',r.subject_name,'effective_until',s.effective_until) order by c.sort_order,c.display_name,s.subject_index)
      from public.school_staff_access_scopes s
      join public.school_classes c on c.class_key=s.class_key
      join public.result_subject_catalog r on r.class_key=s.class_key and r.subject_index=s.subject_index
      where s.person_id=v_person_id and s.app_code='results' and s.scope_type='subject'
        and s.scope_status='active' and s.effective_from<=now() and (s.effective_until is null or s.effective_until>now())
    ),'[]'::jsonb),
    'result_portal',jsonb_build_object(
      'legacy_grant',exists(select 1 from public.school_access_grants g where g.person_id=v_person_id and g.app_code='results' and g.grant_status='active' and g.valid_from<=now() and (g.valid_until is null or g.valid_until>now())),
      'can_view_entry','result_entry.view'=any(coalesce((select g.permissions from public.school_access_grants g where g.person_id=v_person_id and g.app_code='results' limit 1),array[]::text[])),
      'can_create_entry','result_entry.create'=any(coalesce((select g.permissions from public.school_access_grants g where g.person_id=v_person_id and g.app_code='results' limit 1),array[]::text[])),
      'can_edit_entry','result_entry.edit'=any(coalesce((select g.permissions from public.school_access_grants g where g.person_id=v_person_id and g.app_code='results' limit 1),array[]::text[])),
      'can_submit','result_entry.submit'=any(coalesce((select g.permissions from public.school_access_grants g where g.person_id=v_person_id and g.app_code='results' limit 1),array[]::text[])),
      'can_review','result_review.review'=any(coalesce((select g.permissions from public.school_access_grants g where g.person_id=v_person_id and g.app_code='results' limit 1),array[]::text[])),
      'can_approve','result_approval.approve'=any(coalesce((select g.permissions from public.school_access_grants g where g.person_id=v_person_id and g.app_code='results' limit 1),array[]::text[])),
      'can_generate_cards','report_cards.generate'=any(coalesce((select g.permissions from public.school_access_grants g where g.person_id=v_person_id and g.app_code='results' limit 1),array[]::text[])),
      'can_publish','result_publishing.publish'=any(coalesce((select g.permissions from public.school_access_grants g where g.person_id=v_person_id and g.app_code='results' limit 1),array[]::text[]))
    )
  );
end;
$function$;

create or replace function public.school_access_management_read_api(
  p_client_code text,
  p_client_secret text,
  p_action text,
  p_payload jsonb default '{}'::jsonb
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_client_id uuid;
  v_search text:=lower(trim(coalesce(p_payload->>'search','')));
  v_staff_id uuid;
  v_person_id uuid;
begin
  v_client_id:=public.school_registry_verify_admin(p_client_code,p_client_secret,'access.manage');
  if v_client_id is null then return jsonb_build_object('ok',false,'code','MANAGEMENT_ACCESS_DENIED'); end if;

  if p_action='catalog' then
    return jsonb_build_object(
      'ok',true,
      'roles',coalesce((select jsonb_agg(jsonb_build_object('role_code',role_code,'role_name',role_name,'description',description) order by role_name) from public.school_system_role_catalog where is_assignable),'[]'::jsonb),
      'permissions',coalesce((select jsonb_agg(jsonb_build_object('permission_code',permission_code,'app_code',app_code,'module_code',module_code,'module_name',module_name,'action_code',action_code,'description',description) order by app_code,module_name,action_code) from public.school_permission_catalog),'[]'::jsonb),
      'portals',coalesce((select jsonb_agg(jsonb_build_object('app_code',app_code,'app_name',app_name,'default_roles',default_roles) order by app_name) from public.school_portal_catalog where is_active),'[]'::jsonb),
      'classes',coalesce((select jsonb_agg(jsonb_build_object('class_key',class_key,'display_name',display_name,'sort_order',sort_order) order by sort_order,display_name) from public.school_classes where is_active),'[]'::jsonb),
      'subjects',coalesce((select jsonb_agg(jsonb_build_object('class_key',class_key,'subject_index',subject_index,'subject_name',subject_name) order by class_key,subject_index) from public.result_subject_catalog where active),'[]'::jsonb)
    );
  end if;

  if p_action='staff' then
    return jsonb_build_object('ok',true,'staff',coalesce((
      select jsonb_agg(to_jsonb(x) order by x.full_name) from (
        select s.id as staff_id,s.central_person_id as person_id,s.staff_number,s.full_name,s.designation,s.staff_category,s.department,
          s.employment_status,s.registration_status,i.account_status,
          coalesce((select count(*) from public.school_access_grants g where g.person_id=s.central_person_id and g.grant_status='active' and g.valid_from<=now() and (g.valid_until is null or g.valid_until>now())),0) as active_module_count
        from public.staff_attendance_profiles s
        join public.school_identity_accounts i on i.person_id=s.central_person_id
        where s.central_person_id is not null
          and s.registration_status='active' and s.employment_status='active'
          and (v_search='' or lower(s.full_name) like '%'||v_search||'%' or lower(coalesce(s.staff_number,'')) like '%'||v_search||'%')
        order by s.full_name limit 200
      ) x
    ),'[]'::jsonb));
  end if;

  if p_action='staffAccessProfile' then
    begin v_staff_id:=(p_payload->>'staffId')::uuid; exception when others then return jsonb_build_object('ok',false,'code','INVALID_STAFF_ID'); end;
    select central_person_id into v_person_id from public.staff_attendance_profiles where id=v_staff_id;
    if v_person_id is null then return jsonb_build_object('ok',false,'code','STAFF_IDENTITY_NOT_LINKED'); end if;
    return jsonb_build_object(
      'ok',true,
      'staff',(select jsonb_build_object('staff_id',s.id,'person_id',s.central_person_id,'staff_number',s.staff_number,'full_name',s.full_name,'designation',s.designation,'staff_category',s.staff_category,'department',s.department,'employment_status',s.employment_status,'registration_status',s.registration_status,'public_visibility_approved',s.public_visibility_approved,'public_display_name',s.public_display_name,'public_display_role',s.public_display_role,'public_display_order',s.public_display_order,'account_status',i.account_status) from public.staff_attendance_profiles s join public.school_identity_accounts i on i.person_id=s.central_person_id where s.id=v_staff_id),
      'module_grants',coalesce((select jsonb_agg(jsonb_build_object('id',g.id,'app_code',g.app_code,'access_role',g.access_role,'permissions',g.permissions,'grant_status',g.grant_status,'valid_from',g.valid_from,'valid_until',g.valid_until,'granted_by_person_id',g.granted_by_person_id,'reason',g.reason,'revoked_by_person_id',g.revoked_by_person_id,'revoked_at',g.revoked_at,'revocation_reason',g.revocation_reason) order by g.app_code) from public.school_access_grants g where g.person_id=v_person_id),'[]'::jsonb),
      'role_assignments',coalesce((select jsonb_agg(jsonb_build_object('id',r.id,'role_code',r.role_code,'role_name',c.role_name,'assignment_status',r.assignment_status,'effective_from',r.effective_from,'effective_until',r.effective_until,'assigned_at',r.assigned_at,'reason',r.reason,'revoked_at',r.revoked_at,'revocation_reason',r.revocation_reason) order by c.role_name) from public.school_staff_role_assignments r join public.school_system_role_catalog c on c.role_code=r.role_code where r.person_id=v_person_id),'[]'::jsonb),
      'scopes',coalesce((select jsonb_agg(jsonb_build_object('id',x.id,'app_code',x.app_code,'scope_type',x.scope_type,'class_key',x.class_key,'display_name',x.display_name,'subject_index',x.subject_index,'subject_name',x.subject_name,'scope_status',x.scope_status,'effective_from',x.effective_from,'effective_until',x.effective_until,'reason',x.reason,'revoked_at',x.revoked_at,'revocation_reason',x.revocation_reason) order by x.app_code,x.display_name,x.subject_index nulls first) from (select s.id,s.app_code,s.scope_type,s.class_key,c.display_name,s.subject_index,r.subject_name,s.scope_status,s.effective_from,s.effective_until,s.reason,s.revoked_at,s.revocation_reason from public.school_staff_access_scopes s join public.school_classes c on c.class_key=s.class_key left join public.result_subject_catalog r on r.class_key=s.class_key and r.subject_index=s.subject_index where s.person_id=v_person_id) x),'[]'::jsonb),
      'history',coalesce((select jsonb_agg(jsonb_build_object('id',a.id,'action',a.action,'entity_type',a.entity_type,'created_at',a.created_at,'details',a.details) order by a.created_at desc) from (select * from public.school_registry_audit where details->>'staff_id'=v_staff_id::text or details->>'person_id'=v_person_id::text order by created_at desc limit 100) a),'[]'::jsonb)
    );
  end if;

  return jsonb_build_object('ok',false,'code','UNKNOWN_ACTION');
end;
$function$;

create or replace function public.school_access_management_write_api(
  p_client_code text,
  p_client_secret text,
  p_action text,
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
  v_request_id uuid:=gen_random_uuid();
  v_before jsonb;
  v_after jsonb;
  v_id uuid;
  v_app_code text;
  v_role text;
  v_enabled boolean;
  v_permissions text[]:=array[]::text[];
  v_reason text;
  v_from timestamptz:=now();
  v_until timestamptz;
  v_scope_type text;
  v_class_key text;
  v_subject_index integer;
  v_status text;
  v_role_code text;
begin
  v_client_id:=public.school_registry_verify_admin(p_client_code,p_client_secret,'access.manage');
  if v_client_id is null then return jsonb_build_object('ok',false,'code','MANAGEMENT_ACCESS_DENIED'); end if;
  select central_person_id into v_actor_person_id from public.attendance_admin_clients where id=v_client_id;
  if v_actor_person_id is null then return jsonb_build_object('ok',false,'code','MANAGEMENT_IDENTITY_MISSING'); end if;

  begin v_staff_id:=(p_payload->>'staffId')::uuid; exception when others then return jsonb_build_object('ok',false,'code','INVALID_STAFF_ID'); end;
  select central_person_id into v_person_id from public.staff_attendance_profiles where id=v_staff_id;
  if v_person_id is null then return jsonb_build_object('ok',false,'code','STAFF_IDENTITY_NOT_LINKED'); end if;
  v_reason:=nullif(trim(coalesce(p_payload->>'reason','')),'');

  if p_action='setModuleAccess' then
    v_app_code:=trim(coalesce(p_payload->>'appCode',''));
    v_role:=trim(coalesce(p_payload->>'accessRole',''));
    v_enabled:=coalesce((p_payload->>'enabled')::boolean,false);
    if not exists(select 1 from public.school_portal_catalog where app_code=v_app_code and is_active) then return jsonb_build_object('ok',false,'code','PORTAL_NOT_FOUND'); end if;
    if v_role='' then return jsonb_build_object('ok',false,'code','ACCESS_ROLE_REQUIRED'); end if;
    begin v_from:=coalesce(nullif(p_payload->>'effectiveFrom','')::timestamptz,now()); v_until:=nullif(p_payload->>'expiresAt','')::timestamptz; exception when others then return jsonb_build_object('ok',false,'code','INVALID_EFFECTIVE_OR_EXPIRY_DATE'); end;
    if v_until is not null and v_until<=v_from then return jsonb_build_object('ok',false,'code','EXPIRY_MUST_FOLLOW_EFFECTIVE_DATE'); end if;
    select coalesce(array_agg(distinct value order by value),array[]::text[]) into v_permissions from jsonb_array_elements_text(coalesce(p_payload->'permissions','[]'::jsonb)) value;
    if v_enabled and v_app_code<>'staff_self_service' and cardinality(v_permissions)=0 then return jsonb_build_object('ok',false,'code','AT_LEAST_ONE_ACTION_PERMISSION_REQUIRED'); end if;
    if exists(select 1 from unnest(v_permissions) p where not exists(select 1 from public.school_permission_catalog c where c.permission_code=p and c.app_code=v_app_code)) then return jsonb_build_object('ok',false,'code','UNKNOWN_OR_CROSS_PORTAL_PERMISSION'); end if;
    if v_app_code='staff_self_service' and v_enabled then v_permissions:=array['staff_profile.view','staff_profile.edit']::text[]; end if;
    select to_jsonb(g) into v_before from public.school_access_grants g where g.person_id=v_person_id and g.app_code=v_app_code;
    if not v_enabled and exists(select 1 from public.school_access_grants g where g.person_id=v_person_id and g.app_code='central_registry' and g.grant_status='active' and coalesce((g.metadata->>'primary_registry_admin')::boolean,false)) then
      return jsonb_build_object('ok',false,'code','PRIMARY_SUPER_ADMIN_ACCESS_CANNOT_BE_REVOKED_HERE');
    end if;
    insert into public.school_access_grants(person_id,app_code,access_role,permissions,grant_status,valid_from,valid_until,granted_by_person_id,reason,metadata,revoked_by_person_id,revoked_at,revocation_reason)
    values(v_person_id,v_app_code,v_role,v_permissions,case when v_enabled then 'active' else 'revoked' end,case when v_enabled then v_from else now() end,case when v_enabled then v_until else now() end,v_actor_person_id,coalesce(v_reason,case when v_enabled then 'Assigned through Central Registry access management' else 'Revoked through Central Registry access management' end),jsonb_build_object('managed_from','central_registry_access_management','staff_id',v_staff_id),case when v_enabled then null else v_actor_person_id end,case when v_enabled then null else now() end,case when v_enabled then null else coalesce(v_reason,'Revoked through Central Registry access management') end)
    on conflict(person_id,app_code) do update set access_role=excluded.access_role,permissions=excluded.permissions,grant_status=excluded.grant_status,valid_from=excluded.valid_from,valid_until=excluded.valid_until,granted_by_person_id=case when excluded.grant_status='active' then excluded.granted_by_person_id else public.school_access_grants.granted_by_person_id end,reason=excluded.reason,metadata=public.school_access_grants.metadata||excluded.metadata,revoked_by_person_id=excluded.revoked_by_person_id,revoked_at=excluded.revoked_at,revocation_reason=excluded.revocation_reason,updated_at=now()
    returning id into v_id;
    if not v_enabled then
      update public.attendance_admin_clients set status='suspended',session_expires_at=null,updated_at=now() where central_person_id=v_person_id and session_source='central_identity';
    end if;
    select to_jsonb(g) into v_after from public.school_access_grants g where g.id=v_id;
    insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,request_id,before_data,after_data,details) values('person',v_actor_person_id::text,case when v_enabled then 'staff_access.module_granted' else 'staff_access.module_revoked' end,'school_access_grant',v_id::text,v_request_id,v_before,v_after,jsonb_build_object('staff_id',v_staff_id,'person_id',v_person_id,'app_code',v_app_code));
    return jsonb_build_object('ok',true,'code',case when v_enabled then 'MODULE_ACCESS_GRANTED' else 'MODULE_ACCESS_REVOKED' end,'request_id',v_request_id);
  end if;

  if p_action='setSystemRole' then
    v_role_code:=trim(coalesce(p_payload->>'roleCode',''));
    v_enabled:=coalesce((p_payload->>'enabled')::boolean,false);
    if not exists(select 1 from public.school_system_role_catalog where role_code=v_role_code and is_assignable) then return jsonb_build_object('ok',false,'code','SYSTEM_ROLE_NOT_FOUND'); end if;
    begin v_from:=coalesce(nullif(p_payload->>'effectiveFrom','')::timestamptz,now()); v_until:=nullif(p_payload->>'expiresAt','')::timestamptz; exception when others then return jsonb_build_object('ok',false,'code','INVALID_EFFECTIVE_OR_EXPIRY_DATE'); end;
    if v_until is not null and v_until<=v_from then return jsonb_build_object('ok',false,'code','EXPIRY_MUST_FOLLOW_EFFECTIVE_DATE'); end if;
    select to_jsonb(r) into v_before from public.school_staff_role_assignments r where r.person_id=v_person_id and r.role_code=v_role_code;
    insert into public.school_staff_role_assignments(person_id,role_code,assignment_status,effective_from,effective_until,assigned_by_person_id,assigned_at,revoked_by_person_id,revoked_at,revocation_reason,reason,metadata)
    values(v_person_id,v_role_code,case when v_enabled then 'active' else 'revoked' end,case when v_enabled then v_from else now() end,case when v_enabled then v_until else now() end,v_actor_person_id,now(),case when v_enabled then null else v_actor_person_id end,case when v_enabled then null else now() end,case when v_enabled then null else coalesce(v_reason,'Role revoked through Central Registry access management') end,v_reason,jsonb_build_object('managed_from','central_registry_access_management','staff_id',v_staff_id))
    on conflict(person_id,role_code) do update set assignment_status=excluded.assignment_status,effective_from=excluded.effective_from,effective_until=excluded.effective_until,assigned_by_person_id=excluded.assigned_by_person_id,assigned_at=excluded.assigned_at,revoked_by_person_id=excluded.revoked_by_person_id,revoked_at=excluded.revoked_at,revocation_reason=excluded.revocation_reason,reason=excluded.reason,metadata=public.school_staff_role_assignments.metadata||excluded.metadata,updated_at=now()
    returning id into v_id;
    select to_jsonb(r) into v_after from public.school_staff_role_assignments r where r.id=v_id;
    insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,request_id,before_data,after_data,details) values('person',v_actor_person_id::text,case when v_enabled then 'staff_access.role_assigned' else 'staff_access.role_revoked' end,'school_staff_role_assignment',v_id::text,v_request_id,v_before,v_after,jsonb_build_object('staff_id',v_staff_id,'person_id',v_person_id,'role_code',v_role_code));
    return jsonb_build_object('ok',true,'code',case when v_enabled then 'SYSTEM_ROLE_ASSIGNED' else 'SYSTEM_ROLE_REVOKED' end,'request_id',v_request_id);
  end if;

  if p_action='setScope' then
    v_app_code:=trim(coalesce(p_payload->>'appCode','results'));
    v_scope_type:=trim(coalesce(p_payload->>'scopeType',''));
    v_class_key:=trim(coalesce(p_payload->>'classKey',''));
    v_enabled:=coalesce((p_payload->>'enabled')::boolean,false);
    begin v_subject_index:=nullif(p_payload->>'subjectIndex','')::integer; v_from:=coalesce(nullif(p_payload->>'effectiveFrom','')::timestamptz,now()); v_until:=nullif(p_payload->>'expiresAt','')::timestamptz; exception when others then return jsonb_build_object('ok',false,'code','INVALID_SCOPE_OR_DATE'); end;
    if v_scope_type not in ('class','subject') or v_app_code<>'results' then return jsonb_build_object('ok',false,'code','UNSUPPORTED_SCOPE'); end if;
    if not exists(select 1 from public.school_classes where class_key=v_class_key and is_active) then return jsonb_build_object('ok',false,'code','ACTIVE_CLASS_NOT_FOUND'); end if;
    if v_scope_type='class' then v_subject_index:=null; elsif not exists(select 1 from public.result_subject_catalog where class_key=v_class_key and subject_index=v_subject_index and active) then return jsonb_build_object('ok',false,'code','ACTIVE_RESULT_SUBJECT_NOT_FOUND'); end if;
    if v_until is not null and v_until<=v_from then return jsonb_build_object('ok',false,'code','EXPIRY_MUST_FOLLOW_EFFECTIVE_DATE'); end if;
    select id,to_jsonb(s) into v_id,v_before from public.school_staff_access_scopes s where s.person_id=v_person_id and s.app_code=v_app_code and s.scope_type=v_scope_type and s.class_key=v_class_key and s.subject_index is not distinct from v_subject_index;
    if v_id is null and not v_enabled then return jsonb_build_object('ok',true,'code','SCOPE_ALREADY_NOT_ASSIGNED','request_id',v_request_id); end if;
    if v_id is null then
      insert into public.school_staff_access_scopes(person_id,app_code,scope_type,class_key,subject_index,scope_status,effective_from,effective_until,assigned_by_person_id,assigned_at,reason,metadata) values(v_person_id,v_app_code,v_scope_type,v_class_key,v_subject_index,'active',v_from,v_until,v_actor_person_id,now(),v_reason,jsonb_build_object('managed_from','central_registry_access_management','staff_id',v_staff_id)) returning id into v_id;
    else
      update public.school_staff_access_scopes set scope_status=case when v_enabled then 'active' else 'revoked' end,effective_from=case when v_enabled then v_from else effective_from end,effective_until=case when v_enabled then v_until else now() end,assigned_by_person_id=case when v_enabled then v_actor_person_id else assigned_by_person_id end,assigned_at=case when v_enabled then now() else assigned_at end,revoked_by_person_id=case when v_enabled then null else v_actor_person_id end,revoked_at=case when v_enabled then null else now() end,revocation_reason=case when v_enabled then null else coalesce(v_reason,'Scope revoked through Central Registry access management') end,reason=v_reason,updated_at=now() where id=v_id;
    end if;
    select to_jsonb(s) into v_after from public.school_staff_access_scopes s where s.id=v_id;
    insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,request_id,before_data,after_data,details) values('person',v_actor_person_id::text,case when v_enabled then 'staff_access.scope_assigned' else 'staff_access.scope_revoked' end,'school_staff_access_scope',v_id::text,v_request_id,v_before,v_after,jsonb_build_object('staff_id',v_staff_id,'person_id',v_person_id,'app_code',v_app_code,'scope_type',v_scope_type,'class_key',v_class_key,'subject_index',v_subject_index));
    return jsonb_build_object('ok',true,'code',case when v_enabled then 'SCOPE_ASSIGNED' else 'SCOPE_REVOKED' end,'request_id',v_request_id);
  end if;

  if p_action='setAccountStatus' then
    v_status:=trim(coalesce(p_payload->>'accountStatus',''));
    if v_status not in ('active','suspended') then return jsonb_build_object('ok',false,'code','INVALID_ACCOUNT_STATUS'); end if;
    if v_status='suspended' and exists(select 1 from public.school_access_grants g where g.person_id=v_person_id and g.app_code='central_registry' and g.grant_status='active' and coalesce((g.metadata->>'primary_registry_admin')::boolean,false)) then return jsonb_build_object('ok',false,'code','PRIMARY_SUPER_ADMIN_ACCOUNT_CANNOT_BE_SUSPENDED_HERE'); end if;
    select to_jsonb(i) into v_before from public.school_identity_accounts i where i.person_id=v_person_id;
    update public.school_identity_accounts set account_status=v_status,updated_at=now() where person_id=v_person_id returning id into v_id;
    if not found then return jsonb_build_object('ok',false,'code','IDENTITY_ACCOUNT_NOT_FOUND'); end if;
    if v_status='suspended' then update public.attendance_admin_clients set status='suspended',session_expires_at=null,updated_at=now() where central_person_id=v_person_id and session_source='central_identity'; end if;
    select to_jsonb(i) into v_after from public.school_identity_accounts i where i.id=v_id;
    insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,request_id,before_data,after_data,details) values('person',v_actor_person_id::text,case when v_status='suspended' then 'staff_access.account_suspended' else 'staff_access.account_restored' end,'school_identity_account',v_id::text,v_request_id,v_before,v_after,jsonb_build_object('staff_id',v_staff_id,'person_id',v_person_id,'reason',v_reason));
    return jsonb_build_object('ok',true,'code',case when v_status='suspended' then 'ACCOUNT_SUSPENDED' else 'ACCOUNT_RESTORED' end,'request_id',v_request_id);
  end if;

  if p_action='setPublicDirectoryVisibility' then
    v_enabled:=coalesce((p_payload->>'approved')::boolean,false);
    select to_jsonb(s) into v_before from public.staff_attendance_profiles s where s.id=v_staff_id;
    update public.staff_attendance_profiles set public_visibility_approved=v_enabled,public_display_name=nullif(trim(p_payload->>'displayName'),''),public_display_role=nullif(trim(p_payload->>'displayRole'),''),public_display_order=nullif(p_payload->>'displayOrder','')::integer,public_visibility_approved_at=case when v_enabled then now() else null end,public_visibility_approved_by_person_id=case when v_enabled then v_actor_person_id else null end,updated_at=now() where id=v_staff_id;
    select to_jsonb(s) into v_after from public.staff_attendance_profiles s where s.id=v_staff_id;
    insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,request_id,before_data,after_data,details) values('person',v_actor_person_id::text,case when v_enabled then 'staff_directory.visibility_approved' else 'staff_directory.visibility_removed' end,'staff_attendance_profile',v_staff_id::text,v_request_id,v_before,v_after,jsonb_build_object('staff_id',v_staff_id,'person_id',v_person_id));
    return jsonb_build_object('ok',true,'code','PUBLIC_DIRECTORY_VISIBILITY_UPDATED','request_id',v_request_id);
  end if;

  return jsonb_build_object('ok',false,'code','UNKNOWN_ACTION');
end;
$function$;

-- The browser may call only these guarded RPCs with the publishable key.
-- Tables stay RLS-protected and direct client access remains blocked.
revoke all on function public.school_identity_current_staff_session(text,text) from public, anon, authenticated;
revoke all on function public.school_staff_workspace_read_api(text,text) from public, anon, authenticated;
revoke all on function public.school_access_management_read_api(text,text,text,jsonb) from public, anon, authenticated;
revoke all on function public.school_access_management_write_api(text,text,text,jsonb) from public, anon, authenticated;
grant execute on function public.school_staff_workspace_read_api(text,text) to anon;
grant execute on function public.school_access_management_read_api(text,text,text,jsonb) to anon;
grant execute on function public.school_access_management_write_api(text,text,text,jsonb) to anon;
