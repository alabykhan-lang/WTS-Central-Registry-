-- Temporary operating policy: Registry and Results are the ordinary staff
-- services, Results is view-only by default, Attendance is a developer-only
-- SS2 pilot, and Notifications/Finance are not exposed. Historical grants and
-- sessions are retained as revoked records.

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
  v_requires_scope boolean := false;
  v_broad_access boolean := false;
  v_class_scope boolean := false;
  v_subject_scope boolean := false;
  v_context_required boolean := false;
  v_current jsonb;
  v_write_gate jsonb;
  v_operating_mode text := 'read_only';
  v_hold_exempt boolean := false;
begin
  v_session := public.school_identity_session_validate(p_session_id, p_session_secret, 'results');
  if coalesce((v_session ->> 'ok')::boolean, false) is not true then return v_session; end if;

  v_person_id := (v_session ->> 'person_id')::uuid;
  v_identity_account_id := (v_session ->> 'identity_account_id')::uuid;
  v_permissions := coalesce(array(select jsonb_array_elements_text(v_session -> 'permissions')), array[]::text[]);
  v_access_role := v_session ->> 'access_role';
  v_identity := public.school_result_identity_resolve(v_person_id, v_identity_account_id);
  if coalesce((v_identity ->> 'ok')::boolean, false) is not true then return v_identity; end if;
  select operating_mode into v_operating_mode from public.school_module_operating_controls where app_code='results';
  v_operating_mode := coalesce(v_operating_mode,'read_only');
  v_hold_exempt := wts_internal.school_registry_is_protected_actor(v_person_id);

  if v_operating_mode='read_only' and not v_hold_exempt then
    v_permissions := array(select distinct x.permission from unnest(v_permissions) as x(permission) where x.permission in ('result_entry.view','results.view_assigned'));
  end if;
  if v_action = 'identity.context' then
    return jsonb_build_object(
      'ok', true, 'code', 'RESULT_AUTHORIZED',
      'person_id', v_person_id, 'identity_account_id', v_identity_account_id,
      'access_role', v_access_role, 'permissions', v_permissions,
      'result_user', v_identity -> 'result_user', 'staff', v_identity -> 'staff',
      'expires_at', v_session -> 'expires_at', 'operating_mode',v_operating_mode,
      'read_only',v_operating_mode='read_only' and not v_hold_exempt
    );
  end if;

  if v_operating_mode='read_only' and not v_hold_exempt and v_action<>'results.view_assigned' then
    return jsonb_build_object('ok',false,'code','RESULT_SYSTEM_READ_ONLY','operating_mode',v_operating_mode);
  end if;
  if not public.school_result_permission_allowed(v_permissions, v_action) then
    return jsonb_build_object('ok', false, 'code', 'RESULT_PERMISSION_DENIED', 'required_permission', v_action);
  end if;

  v_broad_access := public.school_result_permission_allowed(v_permissions, 'results.manage');
  v_requires_scope := v_action in (
    'scores.enter', 'traits.enter', 'remarks.enter', 'results.view_assigned',
    'results.review', 'results.approve', 'results.publish', 'results.unpublish',
    'report_cards.generate', 'results.export'
  );
  if v_action = 'scores.enter' and p_subject_index is null then return jsonb_build_object('ok', false, 'code', 'RESULT_SUBJECT_SCOPE_REQUIRED'); end if;
  if v_requires_scope and not v_broad_access then
    if nullif(trim(coalesce(p_class_key, '')), '') is null then return jsonb_build_object('ok', false, 'code', 'RESULT_CLASS_SCOPE_REQUIRED'); end if;
    select exists(select 1 from public.school_staff_access_scopes s where s.person_id=v_person_id and s.app_code='results' and s.scope_type in ('class','subject') and s.class_key=trim(p_class_key) and s.scope_status='active' and (s.effective_from is null or s.effective_from<=now()) and (s.effective_until is null or s.effective_until>now()) and public.school_result_scope_context_matches(s.metadata,p_academic_session,p_term)) into v_class_scope;
    if not v_class_scope then return jsonb_build_object('ok', false, 'code', 'RESULT_CLASS_SCOPE_DENIED'); end if;
    if p_subject_index is not null then
      select exists(select 1 from public.school_staff_access_scopes s where s.person_id=v_person_id and s.app_code='results' and s.scope_type='subject' and s.class_key=trim(p_class_key) and s.subject_index=p_subject_index and s.scope_status='active' and (s.effective_from is null or s.effective_from<=now()) and (s.effective_until is null or s.effective_until>now()) and public.school_result_scope_context_matches(s.metadata,p_academic_session,p_term)) into v_subject_scope;
      if not v_subject_scope then return jsonb_build_object('ok', false, 'code', 'RESULT_SUBJECT_SCOPE_DENIED'); end if;
    end if;
  end if;

  v_context_required := v_action in ('results.publish','results.unpublish','scores.enter','traits.enter','remarks.enter','report_cards.generate','results.review','results.approve','results.export') or (v_action='results.manage' and nullif(trim(coalesce(p_class_key,'')),'') is not null);
  if v_context_required then
    if nullif(trim(coalesce(p_class_key,'')),'') is null or nullif(trim(coalesce(p_academic_session,'')),'') is null or nullif(trim(coalesce(p_term,'')),'') is null then return jsonb_build_object('ok',false,'code','RESULT_ACADEMIC_CONTEXT_REQUIRED'); end if;
    if trim(p_term) not in ('1st Term','2nd Term','3rd Term') then return jsonb_build_object('ok',false,'code','RESULT_TERM_INVALID'); end if;
    if not public.school_result_context_matches(p_session_id,trim(p_class_key),trim(p_academic_session),trim(p_term)) then return jsonb_build_object('ok',false,'code','RESULT_CONTEXT_MISMATCH'); end if;
    v_current := public.school_academic_current();
    if trim(p_academic_session)<>coalesce(v_current->>'academic_session','') or trim(p_term)<>coalesce(v_current->>'term','') then return jsonb_build_object('ok',false,'code','RESULT_ACADEMIC_CONTEXT_READ_ONLY','academic_session',v_current->>'academic_session','term',v_current->>'term'); end if;
    v_write_gate := public.school_academic_term_write_gate(trim(p_academic_session),trim(p_term));
    if coalesce((v_write_gate->>'ok')::boolean,false) is not true then return jsonb_build_object('ok',false,'code','RESULT_ACADEMIC_TERM_READ_ONLY','term_status',v_write_gate->>'term_status'); end if;
  end if;
  return jsonb_build_object('ok',true,'code','RESULT_AUTHORIZED','person_id',v_person_id,'identity_account_id',v_identity_account_id,'access_role',v_access_role,'permissions',v_permissions,'result_user',v_identity->'result_user','class_scope',v_class_scope,'subject_scope',v_subject_scope,'expires_at',v_session->'expires_at','operating_mode',v_operating_mode,'read_only',false);
end;
$function$;

revoke all on function public.school_result_authorize(uuid,text,text,text,integer,text,text) from public;
grant execute on function public.school_result_authorize(uuid,text,text,text,integer,text,text) to anon, authenticated, service_role;

create or replace function public.school_attendance_registry_roster_read_api(
  p_session_id uuid,
  p_session_secret text,
  p_academic_session text default null,
  p_term text default null,
  p_as_of_date date default current_date
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog','extensions','public'
as $function$
declare
  v_session jsonb; v_context jsonb; v_academic_session text; v_term text;
  v_as_of_date date:=coalesce(p_as_of_date,current_date);
  v_term_row public.school_academic_terms%rowtype; v_person_id uuid;
begin
  v_session:=public.school_identity_session_validate(p_session_id,p_session_secret,'attendance');
  if coalesce((v_session->>'ok')::boolean,false) is not true then return v_session; end if;
  v_person_id:=(v_session->>'person_id')::uuid;
  if not wts_internal.school_portal_entry_allowed(v_person_id,'attendance') then return jsonb_build_object('ok',false,'code','ATTENDANCE_PILOT_RESTRICTED'); end if;
  v_context:=public.school_academic_current();
  v_academic_session:=coalesce(nullif(trim(p_academic_session),''),v_context->>'academic_session');
  v_term:=coalesce(nullif(trim(p_term),''),v_context->>'term');
  select * into v_term_row from public.school_academic_terms t where t.academic_session=v_academic_session and t.term_name=v_term;
  if not found then return jsonb_build_object('ok',false,'code','OFFICIAL_ACADEMIC_TERM_NOT_FOUND'); end if;
  return jsonb_build_object(
    'ok',true,'code','CENTRAL_REGISTRY_ROSTER_READ',
    'requested',jsonb_build_object('academic_session',v_academic_session,'term',v_term,'as_of_date',v_as_of_date,'pilot_scope','SS2'),
    'official_context',v_context,
    'classes',coalesce((select jsonb_agg(jsonb_build_object('class_key',c.class_key,'display_name',c.display_name,'sort_order',c.sort_order) order by c.sort_order,c.display_name) from public.school_classes c where c.is_active and c.class_key like 'ss2-%'),'[]'::jsonb),
    'pupils',coalesce((select jsonb_agg(jsonb_build_object('person_id',e.person_id,'student_id',e.student_id,'admission_number',st.admno,'full_name',st.name,'pupil_status',st.lifecycle_status,'class_key',e.class_key,'valid_from',e.started_on,'valid_until',e.ended_on) order by e.class_key,st.name) from public.school_student_enrollments e join public.students st on st.id=e.student_id where e.academic_session=v_academic_session and e.class_key like 'ss2-%' and e.started_on<=v_as_of_date and (e.ended_on is null or e.ended_on>=v_as_of_date) and e.enrollment_status in ('active','promoted','retained') and not coalesce(st.archived,false) and st.lifecycle_status='active'),'[]'::jsonb),
    'staff',jsonb_build_array(jsonb_build_object('person_id',v_person_id,'staff_id',(select s.id from public.staff_attendance_profiles s where s.central_person_id=v_person_id and s.registration_status='active' and s.employment_status='active' order by s.created_at limit 1),'full_name',(select s.full_name from public.staff_attendance_profiles s where s.central_person_id=v_person_id and s.registration_status='active' and s.employment_status='active' order by s.created_at limit 1),'attendance_required',false)),
    'class_teachers',coalesce((select jsonb_agg(jsonb_build_object('person_id',a.person_id,'staff_id',a.staff_id,'class_key',a.class_key,'responsibility',a.responsibility,'effective_from',a.effective_from::date,'effective_until',a.effective_until::date) order by a.class_key,a.responsibility) from public.school_staff_class_allocations a where a.class_key like 'ss2-%' and a.allocation_status='active' and a.responsibility in ('class_teacher','assistant_class_teacher') and a.effective_from::date<=v_as_of_date and (a.effective_until is null or a.effective_until::date>=v_as_of_date) and (a.academic_session=v_academic_session or a.academic_session is null) and (a.term_name=v_term or a.term_name is null)),'[]'::jsonb),
    'attendance_grants',jsonb_build_array(jsonb_build_object('person_id',v_person_id,'access_role',v_session->>'access_role','permissions',v_session->'permissions')),
    'requested_by_person_id',v_person_id,'pilot_scope','SS2'
  );
end;
$function$;

revoke all on function public.school_attendance_registry_roster_read_api(uuid,text,text,text,date) from public, authenticated;
grant execute on function public.school_attendance_registry_roster_read_api(uuid,text,text,text,date) to anon;

create or replace function public.school_staff_self_service_session_api(p_session_id uuid,p_session_secret text,p_action text,p_payload jsonb default '{}'::jsonb)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog','extensions','public'
as $function$
declare
  v_session jsonb; v_person_id uuid; v_staff_id uuid; v_permissions text[]; v_staff public.staff_attendance_profiles%rowtype; v_completion integer;
begin
  v_session:=public.school_identity_session_validate(p_session_id,p_session_secret,'staff_self_service');
  if coalesce((v_session->>'ok')::boolean,false) is not true then return v_session; end if;
  begin v_person_id:=(v_session->>'person_id')::uuid; exception when others then return jsonb_build_object('ok',false,'code','CENTRAL_IDENTITY_NOT_ACTIVE'); end;
  select * into v_staff from public.staff_attendance_profiles where central_person_id=v_person_id and registration_status='active' and employment_status='active' limit 1;
  if not found then return jsonb_build_object('ok',false,'code','STAFF_NOT_ACTIVE'); end if;
  v_staff_id:=v_staff.id;
  select coalesce(array(select jsonb_array_elements_text(v_session->'permissions')),array[]::text[]) into v_permissions;
  if p_action='profile' then
    v_completion:=(case when nullif(trim(coalesce(v_staff.photo,'')),'') is not null then 20 else 0 end)+(case when nullif(trim(coalesce(v_staff.phone,'')),'') is not null then 20 else 0 end)+(case when nullif(trim(coalesce(v_staff.whatsapp_number,'')),'') is not null then 20 else 0 end)+(case when nullif(trim(coalesce(v_staff.address,'')),'') is not null then 20 else 0 end)+(case when nullif(trim(coalesce(v_staff.metadata->>'emergency_contact','')),'') is not null then 20 else 0 end);
    return jsonb_build_object('ok',true,'profile',jsonb_build_object('staff_id',v_staff.id,'person_id',v_staff.central_person_id,'staff_number',v_staff.staff_number,'full_name',v_staff.full_name,'email',v_staff.email,'official_email',v_staff.email,'phone',v_staff.phone,'whatsapp_number',v_staff.whatsapp_number,'address',v_staff.address,'emergency_contact',v_staff.metadata->>'emergency_contact','staff_category',v_staff.staff_category,'department',v_staff.department,'designation',v_staff.designation,'school_section',v_staff.school_section,'photo',v_staff.photo,'employment_status',v_staff.employment_status,'attendance_required',v_staff.attendance_required,'profile_completion',v_completion,'profile_missing',array_remove(array[case when nullif(trim(coalesce(v_staff.photo,'')),'') is null then 'Photograph' end,case when nullif(trim(coalesce(v_staff.phone,'')),'') is null then 'Phone' end,case when nullif(trim(coalesce(v_staff.whatsapp_number,'')),'') is null then 'WhatsApp number' end,case when nullif(trim(coalesce(v_staff.address,'')),'') is null then 'Address' end,case when nullif(trim(coalesce(v_staff.metadata->>'emergency_contact','')),'') is null then 'Emergency contact' end],null)),
      'portals',coalesce((select jsonb_agg(jsonb_build_object('app_code',p.app_code,'app_name',p.app_name,'description',p.description,'grant_status',g.grant_status,'access_role',g.access_role,'entry_allowed',true,'operating_mode',o.operating_mode) order by p.app_name) from public.school_portal_catalog p join public.school_access_grants g on g.person_id=v_person_id and g.app_code=p.app_code and g.grant_status='active' and (g.valid_from is null or g.valid_from<=now()) and (g.valid_until is null or g.valid_until>now()) join public.school_module_operating_controls o on o.app_code=p.app_code where p.is_active and wts_internal.school_portal_entry_allowed(v_person_id,p.app_code)),'[]'::jsonb));
  end if;
  if p_action='updateProfile' then
    if not (v_permissions @> array['profile.update']::text[]) then return jsonb_build_object('ok',false,'code','SELF_SERVICE_UPDATE_DENIED'); end if;
    if p_payload?'photo' and p_payload->>'photo' is not null and (length(p_payload->>'photo')>260000 or (p_payload->>'photo')!~'^data:image/[a-zA-Z0-9.+-]+;base64,') then return jsonb_build_object('ok',false,'code','PHOTOGRAPH_INVALID'); end if;
    update public.staff_attendance_profiles set phone=case when p_payload?'phone' then nullif(trim(p_payload->>'phone'),'') else phone end,whatsapp_number=case when p_payload?'whatsappNumber' then nullif(trim(p_payload->>'whatsappNumber'),'') else whatsapp_number end,address=case when p_payload?'address' then nullif(trim(p_payload->>'address'),'') else address end,photo=case when p_payload?'photo' then nullif(trim(p_payload->>'photo'),'') else photo end,metadata=case when p_payload?'emergencyContact' then jsonb_set(coalesce(metadata,'{}'::jsonb),'{emergency_contact}',coalesce(to_jsonb(nullif(trim(p_payload->>'emergencyContact'),'')),'null'::jsonb),true) else metadata end,updated_at=now() where id=v_staff_id;
    update public.school_people set primary_phone=case when p_payload?'phone' then nullif(trim(p_payload->>'phone'),'') else primary_phone end,photo_path=case when p_payload?'photo' then nullif(trim(p_payload->>'photo'),'') else photo_path end,updated_at=now() where id=v_person_id;
    return jsonb_build_object('ok',true,'code','STAFF_PROFILE_UPDATED','staff_id',v_staff_id);
  end if;
  return jsonb_build_object('ok',false,'code','UNKNOWN_ACTION');
exception when others then return jsonb_build_object('ok',false,'code','STAFF_SELF_SERVICE_FAILED');
end;
$function$;

revoke all on function public.school_staff_self_service_session_api(uuid,text,text,jsonb) from public, authenticated;
grant execute on function public.school_staff_self_service_session_api(uuid,text,text,jsonb) to anon;

-- Preserve grant records while revoking modules excluded from the present staff workspace.
with revoked as (
  update public.school_access_grants g set grant_status='revoked',valid_until=coalesce(valid_until,now()),revoked_at=coalesce(revoked_at,now()),revocation_reason=coalesce(revocation_reason,'Module disabled by approved temporary operating policy'),updated_at=now()
  where g.grant_status='active' and (g.app_code in ('notifications','finance') or (g.app_code='attendance' and not wts_internal.school_registry_is_technical_actor(g.person_id))) returning g.*
)
insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,after_data,details)
select 'system','portal_policy_migration','staff_access.module_revoked','school_access_grant',r.id::text,to_jsonb(r),jsonb_build_object('app_code',r.app_code,'reason','temporary_operating_policy') from revoked r;

insert into public.school_access_grants(person_id,app_code,access_role,permissions,grant_status,valid_from,reason,metadata)
select p.id,'attendance','attendance_admin',array['dashboard.read','staff.read','reports.read','credentials.manage','staff.manage','devices.manage','staff.rules.manage','settings.manage','corrections.create','corrections.review','manual_entries.create','manual_entries.review']::text[],'active',now(),'Developer-only SS2 attendance pilot',jsonb_build_object('managed_from','pilot_policy','pilot_scope','SS2')
from public.school_people p where p.person_status='active' and wts_internal.school_registry_is_technical_actor(p.id)
on conflict(person_id,app_code) do update set access_role=excluded.access_role,permissions=excluded.permissions,grant_status='active',valid_from=now(),valid_until=null,reason=excluded.reason,metadata=public.school_access_grants.metadata||excluded.metadata,revoked_at=null,revocation_reason=null,updated_at=now();

update public.school_identity_sessions s set revoked_at=now(),revocation_reason='Portal restricted by temporary operating policy',last_seen_at=now()
where s.revoked_at is null and (s.target_app_code in ('notifications','finance') or (s.target_app_code='attendance' and not wts_internal.school_registry_is_technical_actor(s.person_id)));

update public.attendance_admin_clients c set status='suspended',session_expires_at=null,updated_at=now(),metadata=metadata||jsonb_build_object('suspended_by','temporary_operating_policy')
where c.status='active' and (c.central_person_id is null or not wts_internal.school_registry_is_technical_actor(c.central_person_id));

update public.school_sso_clients set is_active=false,updated_at=now() where client_id='notifications';

update public.school_sso_authorization_codes c set consumed_at=now(),consumed_by='portal_operating_mode_restricted'
where c.consumed_at is null and (c.target_app_code='notifications' or (c.target_app_code='attendance' and not wts_internal.school_registry_is_technical_actor(c.person_id)));
