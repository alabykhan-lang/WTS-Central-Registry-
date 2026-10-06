alter table public.school_result_staff_write_access add column if not exists write_scope text not null default 'default' check (write_scope in ('default', 'override'));

-- Update the update function
create or replace function public.school_result_staff_write_access_update(
  p_session_id uuid, p_session_secret text, p_person_id uuid,
  p_write_enabled boolean, p_write_scope text default 'default', p_reason text default null
) returns jsonb
language plpgsql security definer
set search_path to 'pg_catalog','extensions','public'
as $function$
declare v_auth jsonb; v_exists boolean; v_scope text;
begin
  v_auth:=public.school_result_authorize(p_session_id,p_session_secret,'results.manage');
  if coalesce((v_auth->>'ok')::boolean,false) is not true then return v_auth; end if;
  if p_person_id is null then return jsonb_build_object('ok',false,'code','RESULT_STAFF_WRITE_TARGET_REQUIRED'); end if;
  
  v_scope := case when coalesce(p_write_enabled, false) then coalesce(p_write_scope, 'default') else 'default' end;
  
  select exists(select 1 from public.school_access_grants g
    where g.app_code='results' and g.person_id=p_person_id and g.grant_status='active'
      and (g.valid_from is null or g.valid_from<=now())
      and (g.valid_until is null or g.valid_until>now())) into v_exists;
  if not v_exists then return jsonb_build_object('ok',false,'code','RESULT_STAFF_WRITE_TARGET_NOT_FOUND'); end if;
  
  insert into public.school_result_staff_write_access(app_code,person_id,write_enabled,write_scope,reason,updated_by,updated_at)
  values('results',p_person_id,coalesce(p_write_enabled,false),v_scope,nullif(trim(p_reason),''),(v_auth->>'person_id')::uuid,now())
  on conflict(app_code,person_id) do update set 
    write_enabled=excluded.write_enabled,
    write_scope=excluded.write_scope,
    reason=excluded.reason,
    updated_by=excluded.updated_by,
    updated_at=now();
    
  insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,after_data,details)
  values('person',(v_auth->>'person_id')::uuid,'results.staff_write_access.updated',
    'school_result_staff_write_access',p_person_id::text,
    jsonb_build_object('write_enabled',coalesce(p_write_enabled,false),'write_scope',v_scope,'reason',nullif(trim(p_reason),'')),
    jsonb_build_object('target_person_id',p_person_id,'app_code','results'));
    
  return jsonb_build_object('ok',true,'code','RESULT_STAFF_WRITE_ACCESS_UPDATED');
end;
$function$;

-- Update read function
create or replace function public.school_result_staff_write_access_read(p_session_id uuid,p_session_secret text)
returns jsonb
language plpgsql security definer
set search_path to 'pg_catalog','extensions','public'
as $function$
declare v_auth jsonb; v_policy jsonb;
begin
  v_auth:=public.school_result_authorize(p_session_id,p_session_secret,'results.manage');
  if coalesce((v_auth->>'ok')::boolean,false) is not true then return v_auth; end if;
  select to_jsonb(p) into v_policy from public.school_result_write_policies p where p.app_code='results';
  return jsonb_build_object('ok',true,'code','RESULT_STAFF_WRITE_ACCESS_LOADED',
    'policy',coalesce(v_policy,'{}'::jsonb),
    'rows',(
    select coalesce(jsonb_agg(jsonb_build_object(
      'person_id',g.person_id,'full_name',p.full_name,'staff_number',s.staff_number,
      'designation',s.designation,'registry_role',nullif(p.metadata->>'primary_role',''),
      'access_role',g.access_role,'results_access',true,
      'eligible_for_score_entry',(g.permissions && array['results.manage','scores.enter','result_entry.create','result_entry.edit','result_entry.submit']::text[]),
      'write_enabled',(public.school_result_write_enabled(g.person_id) or public.school_result_permission_allowed(g.permissions,'results.manage')),
      'has_override',exists(select 1 from public.school_result_staff_write_access a where a.app_code='results' and a.person_id=g.person_id),
      'write_scope',(select a.write_scope from public.school_result_staff_write_access a where a.app_code='results' and a.person_id=g.person_id)
    ) order by p.full_name),'[]'::jsonb)
    from public.school_access_grants g
      join public.school_people p on p.id=g.person_id
      left join public.staff_attendance_profiles s on s.central_person_id=p.id and s.registration_status='active' and s.employment_status='active'
    where g.app_code='results' and g.grant_status='active'
      and (g.valid_from is null or g.valid_from<=now())
      and (g.valid_until is null or g.valid_until>now())
  ));
end;
$function$;
create or replace function public.school_result_authorize(
  p_session_id uuid,p_session_secret text,p_action text,
  p_class_key text default null,p_subject_index integer default null,
  p_academic_session text default null,p_term text default null
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog','extensions','public'
as $function$
declare
  v_session jsonb; v_identity jsonb; v_person_id uuid; v_identity_account_id uuid;
  v_permissions text[]; v_access_role text; v_action text:=lower(trim(coalesce(p_action,'')));
  v_requires_scope boolean:=false; v_broad_access boolean:=false;
  v_class_scope boolean:=false; v_subject_scope boolean:=false;
  v_context_required boolean:=false; v_current jsonb; v_write_gate jsonb;
  v_operating_mode text:='read_only'; v_hold_exempt boolean:=false;
  v_write_enabled boolean:=false; v_can_write boolean:=false; v_entry_action boolean:=false;
begin
  v_session:=public.school_identity_session_validate(p_session_id,p_session_secret,'results');
  if coalesce((v_session->>'ok')::boolean,false) is not true then return v_session; end if;
  v_person_id:=(v_session->>'person_id')::uuid;
  v_identity_account_id:=(v_session->>'identity_account_id')::uuid;
  v_permissions:=coalesce(array(select jsonb_array_elements_text(v_session->'permissions')),array[]::text[]);
  v_access_role:=v_session->>'access_role';
  v_identity:=public.school_result_identity_resolve(v_person_id,v_identity_account_id);
  if coalesce((v_identity->>'ok')::boolean,false) is not true then return v_identity; end if;
  select operating_mode into v_operating_mode from public.school_module_operating_controls where app_code='results';
  v_operating_mode:=coalesce(v_operating_mode,'read_only');
  v_hold_exempt:=wts_internal.school_registry_is_protected_actor(v_person_id);

  v_entry_action:=v_action in ('scores.enter','smart.sheet.create','smart.scores.commit','traits.enter','remarks.enter','fees.update');
  v_write_enabled:=v_hold_exempt
    or public.school_result_permission_allowed(v_permissions,'results.manage')
    or public.school_result_write_enabled(v_person_id);
  v_can_write:=v_write_enabled and (
    public.school_result_permission_allowed(v_permissions,'scores.enter')
    or public.school_result_permission_allowed(v_permissions,'results.manage')
  );

  if not v_can_write then
    v_permissions:=array(
      select distinct x.permission from unnest(v_permissions) as x(permission)
      where x.permission not in ('scores.enter','result_entry.create','result_entry.edit',
        'result_entry.submit','traits.enter','remarks.enter','fees.update')
    );
  end if;

  if v_action='identity.context' then
    return jsonb_build_object(
      'ok',true,'code','RESULT_AUTHORIZED','person_id',v_person_id,
      'identity_account_id',v_identity_account_id,'access_role',v_access_role,
      'permissions',v_permissions,'result_user',v_identity->'result_user',
      'staff',v_identity->'staff','expires_at',v_session->'expires_at',
      'operating_mode',v_operating_mode,'read_only',not v_can_write,
      'result_write_enabled',v_can_write
    );
  end if;

  if v_entry_action and not v_can_write then
    return jsonb_build_object('ok',false,'code','RESULT_STAFF_WRITE_DISABLED',
      'operating_mode',v_operating_mode,'result_write_enabled',false);
  end if;
  if not public.school_result_permission_allowed(v_permissions,v_action) then
    return jsonb_build_object('ok',false,'code','RESULT_PERMISSION_DENIED','required_permission',v_action);
  end if;

  v_broad_access:=public.school_result_permission_allowed(v_permissions,'results.manage') or (v_can_write and coalesce((select write_scope from public.school_result_staff_write_access where app_code='results' and person_id=v_person_id), 'default') = 'override');
  v_requires_scope:=v_action in ('scores.enter','traits.enter','remarks.enter','results.view_assigned',
    'results.review','results.approve','results.publish','results.unpublish',
    'report_cards.generate','results.export');

  if v_action='scores.enter' and p_subject_index is null then
    return jsonb_build_object('ok',false,'code','RESULT_SUBJECT_SCOPE_REQUIRED');
  end if;

  if v_requires_scope and not v_broad_access then
    if nullif(trim(coalesce(p_class_key,'')),'') is null then
      return jsonb_build_object('ok',false,'code','RESULT_CLASS_SCOPE_REQUIRED');
    end if;
    select exists(select 1 from public.school_staff_access_scopes s
      where s.person_id=v_person_id and s.app_code='results'
        and s.scope_type in ('class','subject') and s.class_key=trim(p_class_key)
        and s.scope_status='active'
        and (s.effective_from is null or s.effective_from<=now())
        and (s.effective_until is null or s.effective_until>now())
        and public.school_result_scope_context_matches(s.metadata,p_academic_session,p_term))
      into v_class_scope;
    if not v_class_scope then return jsonb_build_object('ok',false,'code','RESULT_CLASS_SCOPE_DENIED'); end if;
    if p_subject_index is not null then
      select exists(select 1 from public.school_staff_access_scopes s
        where s.person_id=v_person_id and s.app_code='results'
          and s.scope_type='subject' and s.class_key=trim(p_class_key)
          and s.subject_index=p_subject_index and s.scope_status='active'
          and (s.effective_from is null or s.effective_from<=now())
          and (s.effective_until is null or s.effective_until>now())
          and public.school_result_scope_context_matches(s.metadata,p_academic_session,p_term))
        into v_subject_scope;
      if not v_subject_scope then return jsonb_build_object('ok',false,'code','RESULT_SUBJECT_SCOPE_DENIED'); end if;
    end if;
  end if;

  v_context_required:=v_action in ('results.publish','results.unpublish','scores.enter','traits.enter',
    'remarks.enter','report_cards.generate','results.review','results.approve','results.export')
    or (v_action='results.manage' and nullif(trim(coalesce(p_class_key,'')),'') is not null);
  if v_context_required then
    if nullif(trim(coalesce(p_class_key,'')),'') is null
      or nullif(trim(coalesce(p_academic_session,'')),'') is null
      or nullif(trim(coalesce(p_term,'')),'') is null
      then return jsonb_build_object('ok',false,'code','RESULT_ACADEMIC_CONTEXT_REQUIRED'); end if;
    if trim(p_term) not in ('1st Term','2nd Term','3rd Term') then
      return jsonb_build_object('ok',false,'code','RESULT_TERM_INVALID');
    end if;
    if not public.school_result_context_matches(p_session_id,trim(p_class_key),trim(p_academic_session),trim(p_term)) then
      return jsonb_build_object('ok',false,'code','RESULT_CONTEXT_MISMATCH');
    end if;
    v_current:=public.school_academic_current();
    if trim(p_academic_session)<>coalesce(v_current->>'academic_session','')
      or trim(p_term)<>coalesce(v_current->>'term','') then
      return jsonb_build_object('ok',false,'code','RESULT_ACADEMIC_CONTEXT_READ_ONLY',
        'academic_session',v_current->>'academic_session','term',v_current->>'term');
    end if;
    v_write_gate:=public.school_academic_term_write_gate(trim(p_academic_session),trim(p_term));
    if coalesce((v_write_gate->>'ok')::boolean,false) is not true then
      return jsonb_build_object('ok',false,'code','RESULT_ACADEMIC_TERM_READ_ONLY',
        'term_status',v_write_gate->>'term_status');
    end if;
  end if;

  return jsonb_build_object('ok',true,'code','RESULT_AUTHORIZED','person_id',v_person_id,
    'identity_account_id',v_identity_account_id,'access_role',v_access_role,
    'permissions',v_permissions,'result_user',v_identity->'result_user',
    'class_scope',v_class_scope,'subject_scope',v_subject_scope,
    'expires_at',v_session->'expires_at','operating_mode',v_operating_mode,
    'read_only',not v_can_write,'result_write_enabled',v_can_write);
end;
$function$;
create or replace function public.school_result_staff_write_access_bulk(
  p_session_id uuid,p_session_secret text,p_write_enabled boolean,p_write_scope text default 'default',p_reason text default null
) returns jsonb
language plpgsql security definer
set search_path to 'pg_catalog','extensions','public'
as $function$
declare v_auth jsonb; v_count integer;
begin
  v_auth:=public.school_result_authorize(p_session_id,p_session_secret,'results.manage');
  if coalesce((v_auth->>'ok')::boolean,false) is not true then return v_auth; end if;
  insert into public.school_result_write_policies(app_code,default_write_enabled,reason,updated_by,updated_at)
  values('results',coalesce(p_write_enabled,false),nullif(trim(p_reason),''),(v_auth->>'person_id')::uuid,now())
  on conflict(app_code) do update set default_write_enabled=excluded.default_write_enabled,
    reason=excluded.reason,updated_by=excluded.updated_by,updated_at=now();
  delete from public.school_result_staff_write_access a using public.school_access_grants g
    where g.app_code='results' and g.person_id=a.person_id and a.app_code='results';
  select count(*) into v_count from public.school_access_grants g where g.app_code='results' and g.grant_status='active';
  insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,after_data,details)
  values('person',(v_auth->>'person_id')::uuid,'results.staff_write_access.bulk_updated',
    'school_result_write_policies','results',
    jsonb_build_object('default_write_enabled',coalesce(p_write_enabled,false),'reason',nullif(trim(p_reason),'')),
    jsonb_build_object('active_grant_count',v_count));
  return jsonb_build_object('ok',true,'code','RESULT_STAFF_WRITE_ACCESS_BULK_UPDATED',
    'default_write_enabled',coalesce(p_write_enabled,false),'cleared_overrides',true,
    'active_grant_count',v_count);
end;
$function$;
