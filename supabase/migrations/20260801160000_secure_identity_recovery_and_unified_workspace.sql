-- Secure staff credential recovery and permission-filtered workspace reads.
--
-- This migration is additive. It does not create identities, grants, roles,
-- scopes, scores, students or a temporary identity table. Temporary passwords
-- are generated only inside a guarded server-side flow and are never written
-- to audit metadata.

create schema if not exists wts_internal;
revoke all on schema wts_internal from public;
grant usage on schema wts_internal to postgres, service_role;

-- Shared implementation for the authorised management reset and the exact,
-- one-time bootstrap recovery. It is intentionally kept outside the exposed
-- public schema and has no PUBLIC execute privilege.
create or replace function wts_internal.issue_temporary_credential(
  p_person_id uuid,
  p_reason text,
  p_actor_type text,
  p_actor_id text,
  p_bootstrap boolean default false
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_staff public.staff_attendance_profiles%rowtype;
  v_account public.school_identity_accounts%rowtype;
  v_credential public.school_identity_credentials%rowtype;
  v_login_name text;
  v_temp_password text;
  v_request_id uuid:=gen_random_uuid();
  v_before jsonb;
begin
  if nullif(trim(coalesce(p_reason,'')),'') is null then
    return jsonb_build_object('ok',false,'code','RESET_REASON_REQUIRED');
  end if;

  select * into v_staff
  from public.staff_attendance_profiles
  where central_person_id=p_person_id;
  if not found or v_staff.registration_status<>'active' or v_staff.employment_status<>'active' then
    return jsonb_build_object('ok',false,'code','STAFF_IDENTITY_NOT_ACTIVE');
  end if;

  select * into v_account
  from public.school_identity_accounts
  where person_id=p_person_id
  for update;
  if not found or v_account.account_status<>'active' then
    return jsonb_build_object('ok',false,'code','IDENTITY_ACCOUNT_NOT_ACTIVE');
  end if;

  if p_bootstrap and v_account.metadata ? 'bootstrap_recovery_issued_at' then
    return jsonb_build_object('ok',false,'code','BOOTSTRAP_RECOVERY_ALREADY_CONSUMED');
  end if;

  select * into v_credential
  from public.school_identity_credentials
  where identity_account_id=v_account.id
  for update;

  v_login_name:=coalesce(v_credential.login_name,v_staff.staff_number);
  v_temp_password:='Wts!'||upper(substr(encode(gen_random_bytes(6),'hex'),1,4))||lower(substr(encode(gen_random_bytes(6),'hex'),1,4))||'7';

  if found then
    v_before:=jsonb_build_object(
      'credential_status',v_credential.credential_status,
      'must_change_password',v_credential.must_change_password,
      'failed_attempts',v_credential.failed_attempts,
      'locked_until',v_credential.locked_until
    );
  else
    v_before:='{}'::jsonb;
  end if;

  insert into public.school_identity_credentials(
    identity_account_id,person_id,login_name,password_hash,credential_status,
    must_change_password,failed_attempts,locked_until,password_changed_at,updated_at
  ) values(
    v_account.id,p_person_id,v_login_name,crypt(v_temp_password,gen_salt('bf',12)),'active',
    true,0,null,now(),now()
  )
  on conflict(identity_account_id) do update
  set person_id=excluded.person_id,
      login_name=excluded.login_name,
      password_hash=excluded.password_hash,
      credential_status='active',
      must_change_password=true,
      failed_attempts=0,
      locked_until=null,
      password_changed_at=now(),
      updated_at=now();

  update public.school_identity_accounts
  set account_status='active',
      metadata=case
        when p_bootstrap then metadata||jsonb_build_object(
          'bootstrap_recovery_issued_at',now(),
          'bootstrap_recovery_status','issued'
        )
        else metadata||jsonb_build_object('last_password_reset_initiated_at',now())
      end,
      updated_at=now()
  where id=v_account.id;

  -- Invalidate every opaque session for the target identity. No secret is
  -- retained; the replacement hash is random and is not returned.
  update public.attendance_admin_clients
  set status='suspended',
      session_expires_at=null,
      secret_hash=encode(digest(encode(gen_random_bytes(32),'hex'),'sha256'),'hex'),
      updated_at=now()
  where central_person_id=p_person_id;

  insert into public.school_registry_audit(
    actor_type,actor_id,action,entity_type,entity_id,request_id,before_data,after_data,details
  ) values(
    p_actor_type,p_actor_id,
    case when p_bootstrap then 'identity.bootstrap_reset' else 'identity.password_reset' end,
    'identity_credential',v_account.id::text,v_request_id,
    v_before,
    jsonb_build_object('credential_status','active','must_change_password',true,'failed_attempts',0,'locked_until',null),
    jsonb_build_object(
      'person_id',p_person_id,
      'staff_id',v_staff.id,
      'login_name',v_login_name,
      'reason',trim(p_reason),
      'bootstrap',p_bootstrap
    )
  );

  return jsonb_build_object(
    'ok',true,
    'code',case when p_bootstrap then 'BOOTSTRAP_RECOVERY_ISSUED' else 'STAFF_PASSWORD_RESET' end,
    'staff_id',v_staff.id,
    'login_name',v_login_name,
    'temporary_password',v_temp_password,
    'must_change_password',true,
    'request_id',v_request_id,
    'warning','This temporary password is returned once and is not stored in audit data.'
  );
end;
$function$;

revoke all on function wts_internal.issue_temporary_credential(uuid,text,text,text,boolean) from public;

-- Management reset. The caller must already hold an active Central Registry
-- session with the real access.manage permission. This function is service
-- role only so it cannot be called from an anonymous browser RPC.
create or replace function public.school_identity_issue_temporary_password(
  p_client_code text,
  p_client_secret text,
  p_staff_id uuid,
  p_reason text
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_admin_client_id uuid;
  v_actor_person_id uuid;
  v_person_id uuid;
begin
  v_admin_client_id:=public.school_registry_verify_admin(p_client_code,p_client_secret,'access.manage');
  if v_admin_client_id is null then
    return jsonb_build_object('ok',false,'code','ADMIN_AUTH_OR_PERMISSION_FAILED');
  end if;

  select central_person_id into v_actor_person_id
  from public.attendance_admin_clients
  where id=v_admin_client_id;

  select central_person_id into v_person_id
  from public.staff_attendance_profiles
  where id=p_staff_id;
  if v_person_id is null then
    return jsonb_build_object('ok',false,'code','STAFF_IDENTITY_NOT_LINKED');
  end if;

  return wts_internal.issue_temporary_credential(
    v_person_id,trim(p_reason),'admin_client',v_actor_person_id::text,false
  );
end;
$function$;

-- One-time bootstrap recovery for the one confirmed existing super-admin
-- identity. The server route supplies the secret and calls this function with
-- service-role credentials; the function itself still refuses every other
-- person and refuses a second issuance after the account metadata is marked.
create or replace function public.school_identity_bootstrap_reset(
  p_staff_number text,
  p_login_email text,
  p_reason text
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_person_id uuid;
begin
  if trim(coalesce(p_staff_number,''))<>'WTS/STF/000008'
     or lower(trim(coalesce(p_login_email,'')))<>'alabykhan@gmail.com' then
    return jsonb_build_object('ok',false,'code','BOOTSTRAP_TARGET_NOT_ALLOWED');
  end if;

  select s.central_person_id into v_person_id
  from public.staff_attendance_profiles s
  join public.school_people p on p.id=s.central_person_id
  where s.staff_number='WTS/STF/000008'
    and lower(coalesce(s.email,''))='alabykhan@gmail.com'
    and lower(coalesce(p.primary_email,''))='alabykhan@gmail.com';
  if v_person_id is null then
    return jsonb_build_object('ok',false,'code','BOOTSTRAP_TARGET_NOT_FOUND');
  end if;

  return wts_internal.issue_temporary_credential(
    v_person_id,trim(p_reason),'bootstrap_recovery','bootstrap',true
  );
end;
$function$;

revoke execute on function wts_internal.issue_temporary_credential(uuid,text,text,text,boolean) from public, anon, authenticated;
revoke execute on function public.school_identity_issue_temporary_password(text,text,uuid,text) from public, anon, authenticated;
grant execute on function public.school_identity_issue_temporary_password(text,text,uuid,text) to service_role;
revoke execute on function public.school_identity_bootstrap_reset(text,text,text) from public, anon, authenticated;
grant execute on function public.school_identity_bootstrap_reset(text,text,text) to service_role;

-- The previous identity-admin write RPC could generate and return a temporary
-- password to an anonymous browser caller that happened to know an opaque
-- admin session. Remove that public execution path. The protected platform
-- route above is now the only reset issuer.
revoke execute on function public.school_identity_admin_write_api(text,text,text,jsonb) from public, anon, authenticated;
grant execute on function public.school_identity_admin_write_api(text,text,text,jsonb) to service_role;

-- Mark a bootstrap recovery complete when the owner replaces the temporary
-- credential. Only timestamps/status are stored; no password is stored.
create or replace function public.school_identity_change_password(
  p_login text,
  p_current_password text,
  p_new_password text
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_credential public.school_identity_credentials%rowtype;
begin
  if length(coalesce(p_new_password,''))<10 or p_new_password !~ '[A-Z]' or p_new_password !~ '[a-z]' or p_new_password !~ '[0-9]' then
    return jsonb_build_object('ok',false,'code','PASSWORD_REQUIREMENTS_NOT_MET');
  end if;

  select c.* into v_credential
  from public.school_identity_credentials c
  join public.school_identity_accounts i on i.id=c.identity_account_id
  left join public.staff_attendance_profiles s on s.central_person_id=c.person_id
  where lower(c.login_name)=lower(trim(p_login))
     or lower(coalesce(i.login_email,''))=lower(trim(p_login))
     or lower(coalesce(s.email,''))=lower(trim(p_login))
  limit 1 for update of c;
  if not found or v_credential.password_hash is null or v_credential.credential_status<>'active' or crypt(p_current_password,v_credential.password_hash)<>v_credential.password_hash then
    return jsonb_build_object('ok',false,'code','INVALID_CURRENT_PASSWORD');
  end if;

  if not exists(
    select 1
    from public.school_identity_accounts i
    join public.school_people p on p.id=i.person_id
    join public.staff_attendance_profiles s on s.central_person_id=p.id
    where i.id=v_credential.identity_account_id
      and i.account_status='active'
      and p.person_status='active'
      and s.registration_status='active'
      and s.employment_status='active'
  ) then
    return jsonb_build_object('ok',false,'code','ACCOUNT_NOT_ACTIVE');
  end if;

  update public.school_identity_credentials
  set password_hash=crypt(p_new_password,gen_salt('bf',12)),
      must_change_password=false,
      failed_attempts=0,
      locked_until=null,
      password_changed_at=now(),
      updated_at=now()
  where id=v_credential.id;

  update public.school_identity_accounts
  set metadata=case
      when metadata ? 'bootstrap_recovery_issued_at' then metadata||jsonb_build_object(
        'bootstrap_recovery_status','completed',
        'bootstrap_recovery_completed_at',now()
      )
      else metadata
    end,
    updated_at=now()
  where id=v_credential.identity_account_id;

  update public.attendance_admin_clients
  set status='suspended',
      session_expires_at=null,
      secret_hash=encode(digest(encode(gen_random_bytes(32),'hex'),'sha256'),'hex'),
      updated_at=now()
  where central_person_id=v_credential.person_id;

  return jsonb_build_object('ok',true,'code','PASSWORD_CHANGED','login_name',v_credential.login_name,'login_again',true);
end;
$function$;

-- Keep workspace responses permission-driven. In particular, class and subject
-- scope data is not returned unless the current person has an active Results
-- grant, and every Result action check ignores expired/revoked grants.
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
        and exists(select 1 from public.school_access_grants rg where rg.person_id=v_person_id and rg.app_code='results' and rg.grant_status='active' and rg.valid_from<=now() and (rg.valid_until is null or rg.valid_until>now()))
    ),'[]'::jsonb),
    'subject_assignments',coalesce((
      select jsonb_agg(jsonb_build_object('class_key',s.class_key,'display_name',c.display_name,'subject_index',s.subject_index,'subject_name',r.subject_name,'effective_until',s.effective_until) order by c.sort_order,c.display_name,s.subject_index)
      from public.school_staff_access_scopes s
      join public.school_classes c on c.class_key=s.class_key
      join public.result_subject_catalog r on r.class_key=s.class_key and r.subject_index=s.subject_index
      where s.person_id=v_person_id and s.app_code='results' and s.scope_type='subject'
        and s.scope_status='active' and s.effective_from<=now() and (s.effective_until is null or s.effective_until>now())
        and exists(select 1 from public.school_access_grants rg where rg.person_id=v_person_id and rg.app_code='results' and rg.grant_status='active' and rg.valid_from<=now() and (rg.valid_until is null or rg.valid_until>now()))
    ),'[]'::jsonb),
    'result_portal',jsonb_build_object(
      'legacy_grant',exists(select 1 from public.school_access_grants g where g.person_id=v_person_id and g.app_code='results' and g.grant_status='active' and g.valid_from<=now() and (g.valid_until is null or g.valid_until>now())),
      'can_view_entry',exists(select 1 from public.school_access_grants g where g.person_id=v_person_id and g.app_code='results' and g.grant_status='active' and g.valid_from<=now() and (g.valid_until is null or g.valid_until>now()) and 'result_entry.view'=any(g.permissions)),
      'can_create_entry',exists(select 1 from public.school_access_grants g where g.person_id=v_person_id and g.app_code='results' and g.grant_status='active' and g.valid_from<=now() and (g.valid_until is null or g.valid_until>now()) and 'result_entry.create'=any(g.permissions)),
      'can_edit_entry',exists(select 1 from public.school_access_grants g where g.person_id=v_person_id and g.app_code='results' and g.grant_status='active' and g.valid_from<=now() and (g.valid_until is null or g.valid_until>now()) and 'result_entry.edit'=any(g.permissions)),
      'can_submit',exists(select 1 from public.school_access_grants g where g.person_id=v_person_id and g.app_code='results' and g.grant_status='active' and g.valid_from<=now() and (g.valid_until is null or g.valid_until>now()) and 'result_entry.submit'=any(g.permissions)),
      'can_review',exists(select 1 from public.school_access_grants g where g.person_id=v_person_id and g.app_code='results' and g.grant_status='active' and g.valid_from<=now() and (g.valid_until is null or g.valid_until>now()) and 'result_review.review'=any(g.permissions)),
      'can_approve',exists(select 1 from public.school_access_grants g where g.person_id=v_person_id and g.app_code='results' and g.grant_status='active' and g.valid_from<=now() and (g.valid_until is null or g.valid_until>now()) and 'result_approval.approve'=any(g.permissions)),
      'can_generate_cards',exists(select 1 from public.school_access_grants g where g.person_id=v_person_id and g.app_code='results' and g.grant_status='active' and g.valid_from<=now() and (g.valid_until is null or g.valid_until>now()) and 'report_cards.generate'=any(g.permissions)),
      'can_publish',exists(select 1 from public.school_access_grants g where g.person_id=v_person_id and g.app_code='results' and g.grant_status='active' and g.valid_from<=now() and (g.valid_until is null or g.valid_until>now()) and 'result_publishing.publish'=any(g.permissions))
    )
  );
end;
$function$;
