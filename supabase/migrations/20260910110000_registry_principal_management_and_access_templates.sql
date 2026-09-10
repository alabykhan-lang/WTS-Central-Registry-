-- Registry management-role and profile access-template corrections.
--
-- A custom school portfolio is a visible designation.  It does not grant
-- access merely because of its name.  Management may explicitly attach one
-- of the approved, non-technical access templates to a custom staff portfolio;
-- the entitlement wrapper below then derives the same server-side scopes as
-- the corresponding canonical role.

-- Principal, Director and Vice Principal are management roles.  They retain
-- school-wide student visibility, and may manage the operational Registry
-- work areas.  The developer/proprietor technical gates remain separate.
insert into public.school_portfolio_capabilities(portfolio_code, capability_code)
select x.portfolio_code, x.capability_code
from (values
  ('director','allocations.school.manage'),
  ('director','academic_calendar.manage'),
  ('director','portfolio.manage'),
  ('principal','allocations.school.manage'),
  ('principal','academic_calendar.manage'),
  ('principal','portfolio.manage'),
  ('vice_principal','allocations.school.manage'),
  ('vice_principal','academic_calendar.manage'),
  ('vice_principal','portfolio.manage')
) as x(portfolio_code, capability_code)
where exists (select 1 from public.school_portfolio_catalog p where p.portfolio_code=x.portfolio_code and p.holder_type='staff')
  and exists (select 1 from public.school_registry_capability_catalog c where c.capability_code=x.capability_code)
on conflict do nothing;

-- Stage leaders may read their scoped student catalog, but the staff directory
-- remains self-only.  Allocation management and calendar management are
-- management-only; allocations.read is retained for class selectors used by
-- scoped student views.
delete from public.school_portfolio_capabilities
where portfolio_code in ('director_primary','headmistress','assistant_headmistress')
  and capability_code='staff.stage.read';
delete from public.school_portfolio_capabilities
where portfolio_code in ('headmistress','assistant_headmistress')
  and capability_code='allocations.early_childhood.manage';

comment on table public.school_portfolio_capabilities is
  'Canonical capability mappings. Custom profile portfolios require an explicit approved access template.';

create table if not exists public.school_registry_access_template_class_scopes (
  access_template_code text not null references public.school_portfolio_catalog(portfolio_code),
  class_key text not null references public.school_classes(class_key),
  created_at timestamptz not null default now(),
  primary key (access_template_code, class_key)
);

alter table public.school_registry_access_template_class_scopes enable row level security;
revoke all on table public.school_registry_access_template_class_scopes from public, anon, authenticated;

-- Headmistress and Assistant Headmistress cover early-childhood through
-- Primary 1: the canonical stage scope covers early-childhood and this class
-- scope adds the explicitly approved Primary 1 boundary.
insert into public.school_registry_access_template_class_scopes(access_template_code, class_key)
select x.access_template_code, 'primary1'
from (values ('headmistress'), ('assistant_headmistress')) as x(access_template_code)
where exists (select 1 from public.school_portfolio_catalog p where p.portfolio_code=x.access_template_code and p.holder_type='staff')
  and exists (select 1 from public.school_classes c where c.class_key='primary1' and c.is_active)
on conflict do nothing;

-- Replace the entitlement function through a wrapper so existing callers keep
-- their public contract while explicit custom access templates participate in
-- capability, stage and class scope derivation.
alter function wts_internal.school_registry_session_entitlements(uuid, text)
  rename to school_registry_session_entitlements_legacy;
revoke all on function wts_internal.school_registry_session_entitlements_legacy(uuid, text)
  from public, anon, authenticated;

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
  v_result jsonb;
  v_ent jsonb;
  v_staff_id uuid;
  v_templates text[] := array[]::text[];
  v_template_caps text[] := array[]::text[];
  v_template_stages text[] := array[]::text[];
  v_template_classes text[] := array[]::text[];
  v_existing_caps text[] := array[]::text[];
  v_existing_stages text[] := array[]::text[];
  v_existing_classes text[] := array[]::text[];
begin
  v_result := wts_internal.school_registry_session_entitlements_legacy(p_session_id, p_session_secret);
  if coalesce((v_result ->> 'ok')::boolean, false) is not true then return v_result; end if;
  v_ent := coalesce(v_result -> 'entitlements', '{}'::jsonb);
  begin
    v_staff_id := nullif(v_result -> 'actor' ->> 'staffId', '')::uuid;
  exception when invalid_text_representation then
    v_staff_id := null;
  end;
  if v_staff_id is null then return v_result; end if;

  select coalesce(array_agg(distinct nullif(trim(a.metadata ->> 'access_template_code'), '') order by nullif(trim(a.metadata ->> 'access_template_code'), '')), array[]::text[])
    into v_templates
  from public.school_portfolio_assignments a
  join public.school_portfolio_catalog c on c.portfolio_code=a.portfolio_code
  where a.holder_type='staff' and a.staff_id=v_staff_id
    and a.assignment_status='active' and a.effective_from <= now()
    and (a.effective_until is null or a.effective_until > now())
    and coalesce(c.metadata ->> 'visibility','school') <> 'technical_only'
    and nullif(trim(a.metadata ->> 'access_template_code'), '') is not null;

  if coalesce(array_length(v_templates,1),0) = 0 then return v_result; end if;

  select coalesce(array_agg(distinct p.capability_code order by p.capability_code), array[]::text[])
    into v_template_caps
  from public.school_portfolio_capabilities p
  where p.portfolio_code=any(v_templates);
  select coalesce(array_agg(distinct s.stage_code order by s.stage_code), array[]::text[])
    into v_template_stages
  from public.school_portfolio_stage_scopes s
  where s.portfolio_code=any(v_templates);
  select coalesce(array_agg(distinct x.class_key order by x.class_key), array[]::text[])
    into v_template_classes
  from public.school_registry_access_template_class_scopes x
  where x.access_template_code=any(v_templates);

  select coalesce(array_agg(distinct x.value order by x.value), array[]::text[])
    into v_existing_caps
  from jsonb_array_elements_text(coalesce(v_ent -> 'capabilities','[]'::jsonb)) x;
  select coalesce(array_agg(distinct x.value order by x.value), array[]::text[])
    into v_existing_stages
  from jsonb_array_elements_text(coalesce(v_ent -> 'stageScopes','[]'::jsonb)) x;
  select coalesce(array_agg(distinct x.value order by x.value), array[]::text[])
    into v_existing_classes
  from jsonb_array_elements_text(coalesce(v_ent -> 'classScopes','[]'::jsonb)) x;

  v_existing_caps := array(
    select distinct x from unnest(coalesce(v_existing_caps,array[]::text[]) || coalesce(v_template_caps,array[]::text[])) x where nullif(x,'') is not null order by x
  );
  v_existing_stages := array(
    select distinct x from unnest(coalesce(v_existing_stages,array[]::text[]) || coalesce(v_template_stages,array[]::text[])) x where nullif(x,'') is not null order by x
  );
  v_existing_classes := array(
    select distinct x from unnest(coalesce(v_existing_classes,array[]::text[]) || coalesce(v_template_classes,array[]::text[])) x where nullif(x,'') is not null order by x
  );
  if coalesce(array_length(v_existing_classes,1),0) > 0 then
    v_existing_caps := array(
      select distinct x from unnest(coalesce(v_existing_caps,array[]::text[]) || array['students.class.read','students.class.manage']) x where nullif(x,'') is not null order by x
    );
  end if;

  v_ent := jsonb_set(v_ent, '{capabilities}', to_jsonb(v_existing_caps), true);
  v_ent := jsonb_set(v_ent, '{stageScopes}', to_jsonb(v_existing_stages), true);
  v_ent := jsonb_set(v_ent, '{classScopes}', to_jsonb(v_existing_classes), true);
  v_ent := jsonb_set(v_ent, '{accessTemplates}', to_jsonb(v_templates), true);
  return jsonb_set(v_result, '{entitlements}', v_ent, true);
exception when others then
  -- A malformed optional template must never remove the base staff session;
  -- the legacy entitlement remains the safe fallback.
  return v_result;
end;
$function$;

revoke all on function wts_internal.school_registry_session_entitlements(uuid, text)
  from public, anon, authenticated;

-- Management-only reads for allocations and the academic calendar are enforced
-- at the database boundary, not just by hiding navigation buttons.  The
-- unrestricted implementation is retained privately for the wrapper.
alter function public.school_registry_read_v2(uuid, text, text, jsonb)
  rename to school_registry_read_v2_unrestricted;
revoke all on function public.school_registry_read_v2_unrestricted(uuid, text, text, jsonb)
  from public, anon, authenticated;

create or replace function public.school_registry_read_v2(
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
  v_ent jsonb;
  v_action text := lower(trim(coalesce(p_action,'')));
begin
  v_auth := wts_internal.school_registry_session_entitlements(p_session_id, p_session_secret);
  if coalesce((v_auth ->> 'ok')::boolean,false) is not true then return v_auth; end if;
  v_ent := coalesce(v_auth -> 'entitlements','{}'::jsonb);
  if v_action='allocations' and not wts_internal.school_registry_has_capability(v_ent,'allocations.school.manage') then
    return jsonb_build_object('ok',false,'code','REGISTRY_CAPABILITY_DENIED');
  end if;
  if v_action='calendar' and not wts_internal.school_registry_has_capability(v_ent,'academic_calendar.manage') then
    return jsonb_build_object('ok',false,'code','REGISTRY_CAPABILITY_DENIED');
  end if;
  return public.school_registry_read_v2_unrestricted(p_session_id, p_session_secret, p_action, p_payload);
end;
$function$;

revoke all on function public.school_registry_read_v2(uuid, text, text, jsonb)
  from public, authenticated;
grant execute on function public.school_registry_read_v2(uuid, text, text, jsonb) to anon;

-- Explicitly set or clear the approved access template on a custom staff
-- portfolio.  This endpoint never accepts technical developer authority.
create or replace function public.school_registry_profile_access_template_session_api(
  p_session_id uuid,
  p_session_secret text,
  p_target_type text,
  p_target_id uuid,
  p_assignment_id uuid,
  p_access_template_code text,
  p_request_id uuid default null
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public', 'wts_internal'
as $function$
declare
  v_auth jsonb;
  v_ent jsonb;
  v_actor uuid;
  v_staff public.staff_attendance_profiles%rowtype;
  v_assignment public.school_portfolio_assignments%rowtype;
  v_catalog public.school_portfolio_catalog%rowtype;
  v_template public.school_portfolio_catalog%rowtype;
  v_request uuid := coalesce(p_request_id, gen_random_uuid());
  v_template_code text := nullif(lower(trim(coalesce(p_access_template_code,''))), '');
  v_operation text := 'registry_profile:portfolio.access_template';
  v_before jsonb;
  v_after jsonb;
  v_result jsonb;
begin
  v_auth := wts_internal.school_registry_session_entitlements(p_session_id, p_session_secret);
  if coalesce((v_auth ->> 'ok')::boolean,false) is not true then return v_auth; end if;
  v_ent := coalesce(v_auth -> 'entitlements','{}'::jsonb);
  v_actor := nullif(v_auth -> 'actor' ->> 'personId','')::uuid;
  if lower(trim(coalesce(p_target_type,''))) <> 'staff' then
    return jsonb_build_object('ok',false,'code','ACCESS_TEMPLATE_STAFF_ONLY');
  end if;
  if not wts_internal.school_registry_has_capability(v_ent,'portfolio.manage') then
    return jsonb_build_object('ok',false,'code','REGISTRY_CAPABILITY_DENIED');
  end if;
  select * into v_staff from public.staff_attendance_profiles s
  where s.id=p_target_id and s.registration_status='active' and s.employment_status='active'
  for update;
  if not found then return jsonb_build_object('ok',false,'code','STAFF_NOT_FOUND'); end if;
  select a.* into v_assignment
  from public.school_portfolio_assignments a
  join public.school_portfolio_catalog c on c.portfolio_code=a.portfolio_code
  where a.id=p_assignment_id and a.staff_id=v_staff.id and a.assignment_status='active'
    and coalesce(c.metadata ->> 'custom','false')='true'
  for update;
  if not found then return jsonb_build_object('ok',false,'code','PORTFOLIO_ASSIGNMENT_NOT_FOUND'); end if;

  if v_template_code is not null then
    select * into v_template
    from public.school_portfolio_catalog c
    where c.portfolio_code=v_template_code and c.holder_type='staff' and c.is_active
      and c.portfolio_code in ('director','principal','vice_principal','director_primary','headmistress','assistant_headmistress','bursar','class_teacher','subject_teacher')
      and coalesce(c.metadata ->> 'visibility','school') <> 'technical_only';
    if not found then return jsonb_build_object('ok',false,'code','ACCESS_TEMPLATE_INVALID'); end if;
  end if;
  if exists (select 1 from public.school_registry_request_outcomes where request_id=v_request) then
    select outcome into v_result from public.school_registry_request_outcomes where request_id=v_request and actor_person_id=v_actor and operation=v_operation;
    if v_result is not null then return v_result; end if;
    return jsonb_build_object('ok',false,'code','IDEMPOTENCY_KEY_REUSED');
  end if;

  v_before := to_jsonb(v_assignment);
  update public.school_portfolio_assignments
  set metadata = case when v_template_code is null
    then coalesce(metadata,'{}'::jsonb) - 'access_template_code'
    else coalesce(metadata,'{}'::jsonb) || jsonb_build_object('access_template_code',v_template_code)
    end,
    updated_at=now()
  where id=v_assignment.id;
  select to_jsonb(a) into v_after from public.school_portfolio_assignments a where a.id=v_assignment.id;
  insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,request_id,before_data,after_data,details)
  values('person',v_actor::text,'profile.custom_portfolio_access_template_updated','school_portfolio_assignment',v_assignment.id::text,v_request,v_before,v_after,
    jsonb_build_object('target_id',v_staff.id,'access_template_code',v_template_code,'technical_authority_excluded',true));
  v_result := jsonb_build_object('ok',true,'code','PROFILE_ACCESS_TEMPLATE_UPDATED','assignmentId',v_assignment.id,'accessTemplateCode',v_template_code,'request_id',v_request);
  insert into public.school_registry_request_outcomes(request_id,actor_person_id,operation,outcome) values(v_request,v_actor,v_operation,v_result);
  return v_result;
exception when others then
  return jsonb_build_object('ok',false,'code','PROFILE_ACCESS_TEMPLATE_FAILED');
end;
$function$;

revoke all on function public.school_registry_profile_access_template_session_api(uuid,text,text,uuid,uuid,text,uuid)
  from public, authenticated;
grant execute on function public.school_registry_profile_access_template_session_api(uuid,text,text,uuid,uuid,text,uuid)
  to anon;

-- Add the selected template to profile-read payloads without exposing the
-- internal unrestricted function as a public endpoint.
alter function public.school_registry_profile_session_api(uuid,text,text,text,uuid,text,text,text,uuid,uuid)
  rename to school_registry_profile_session_api_legacy;
revoke all on function public.school_registry_profile_session_api_legacy(uuid,text,text,text,uuid,text,text,text,uuid,uuid)
  from public, authenticated;

create or replace function public.school_registry_profile_session_api(
  p_session_id uuid,
  p_session_secret text,
  p_action text,
  p_target_type text default null,
  p_target_id uuid default null,
  p_department_code text default null,
  p_portfolio_name text default null,
  p_portfolio_description text default null,
  p_assignment_id uuid default null,
  p_request_id uuid default null
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_result jsonb;
begin
  v_result := public.school_registry_profile_session_api_legacy(
    p_session_id,p_session_secret,p_action,p_target_type,p_target_id,p_department_code,
    p_portfolio_name,p_portfolio_description,p_assignment_id,p_request_id
  );
  if lower(trim(coalesce(p_action,'')))='read'
     and lower(trim(coalesce(p_target_type,'')))='staff'
     and coalesce((v_result ->> 'ok')::boolean,false) then
    v_result := jsonb_set(v_result, '{portfolios}', (
      select coalesce(jsonb_agg(item || case when coalesce(nullif(a.metadata ->> 'access_template_code',''), nullif(c.metadata ->> 'access_template_code','')) is null then '{}'::jsonb else jsonb_build_object('access_template_code',coalesce(nullif(a.metadata ->> 'access_template_code',''), nullif(c.metadata ->> 'access_template_code',''))) end), '[]'::jsonb)
      from jsonb_array_elements(coalesce(v_result -> 'portfolios','[]'::jsonb)) item
      left join public.school_portfolio_assignments a on a.id=(item ->> 'assignment_id')::uuid
      left join public.school_portfolio_catalog c on c.portfolio_code=item ->> 'portfolio_code'
    ), true);
  end if;
  return v_result;
exception when others then
  return jsonb_build_object('ok',false,'code','PROFILE_OPERATION_FAILED');
end;
$function$;

revoke all on function public.school_registry_profile_session_api(uuid,text,text,text,uuid,text,text,text,uuid,uuid)
  from public, authenticated;
grant execute on function public.school_registry_profile_session_api(uuid,text,text,text,uuid,text,text,text,uuid,uuid)
  to anon;
