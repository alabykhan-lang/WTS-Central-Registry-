-- WTS Central Registry security phase 1.
--
-- This migration deliberately leaves direct access to public.students unchanged.
-- That table is shared with the Results and Attendance systems and needs a
-- coordinated RLS migration after their direct-access requirements are mapped.

create or replace function public.school_registry_verify_admin(
  p_client_code text,
  p_client_secret text,
  p_permission text
)
returns uuid
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_client public.attendance_admin_clients%rowtype;
begin
  select * into v_client
  from public.attendance_admin_clients
  where client_code=trim(p_client_code)
    and status='active';

  if not found then return null; end if;
  if encode(digest(p_client_secret,'sha256'),'hex')<>v_client.secret_hash then return null; end if;

  if v_client.central_person_id is not null
     and (v_client.session_expires_at is null or v_client.session_expires_at<=now()) then
    update public.attendance_admin_clients
    set status='suspended',session_expires_at=null,updated_at=now()
    where id=v_client.id;
    return null;
  end if;

  if p_permission is not null
     and not (p_permission=any(v_client.permissions) or '*'=any(v_client.permissions)) then
    return null;
  end if;

  update public.attendance_admin_clients
  set last_seen_at=now(),
      session_expires_at=case
        when central_person_id is not null then now()+interval '8 hours'
        else session_expires_at
      end,
      updated_at=now()
  where id=v_client.id;

  return v_client.id;
end;
$function$;

create or replace function public.school_registry_admin_read_api(
  p_client_code text,
  p_client_secret text,
  p_action text,
  p_payload jsonb default '{}'::jsonb
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions'
as $function$
declare
  v_client public.attendance_admin_clients%rowtype;
  v_search text:=trim(coalesce(p_payload->>'search',''));
  v_class text:=trim(coalesce(p_payload->>'classKey',''));
  v_status text:=trim(coalesce(p_payload->>'status',''));
  v_person_id uuid;
  v_student_id uuid;
  v_result jsonb;
begin
  select * into v_client
  from public.attendance_admin_clients
  where client_code=trim(p_client_code) and status='active';

  if not found or encode(digest(p_client_secret,'sha256'),'hex')<>v_client.secret_hash then
    return jsonb_build_object('ok',false,'code','ADMIN_AUTH_FAILED');
  end if;
  if v_client.central_person_id is not null
     and (v_client.session_expires_at is null or v_client.session_expires_at<=now()) then
    update public.attendance_admin_clients
    set status='suspended',session_expires_at=null,updated_at=now()
    where id=v_client.id;
    return jsonb_build_object('ok',false,'code','ADMIN_SESSION_EXPIRED');
  end if;
  if not ('registry.read'=any(v_client.permissions) or '*'=any(v_client.permissions)) then
    return jsonb_build_object('ok',false,'code','ADMIN_PERMISSION_DENIED');
  end if;

  update public.attendance_admin_clients
  set last_seen_at=now(),
      session_expires_at=case
        when central_person_id is not null then now()+interval '8 hours'
        else session_expires_at
      end,
      updated_at=now()
  where id=v_client.id;

  if p_action='context' then
    return jsonb_build_object(
      'ok',true,
      'people',(select count(*) from public.school_people),
      'active_students',(select count(*) from public.students where archived=false),
      'archived_students',(select count(*) from public.students where archived=true),
      'active_staff',(select count(*) from public.staff_attendance_profiles where registration_status='active' and employment_status='active'),
      'archived_staff',(select count(*) from public.staff_attendance_profiles where registration_status='archived' or employment_status='exited'),
      'pending_admissions',(select count(*) from public.school_admission_applications where application_status in ('submitted','under_review','approved')),
      'pending_sync_events',(select count(*) from public.school_registry_outbox where event_status in ('pending','failed')),
      'classes',(select coalesce(jsonb_agg(to_jsonb(c) order by c.sort_order,c.display_name),'[]'::jsonb) from (select id,class_key,display_name,section,sort_order,is_active from public.school_classes where is_active=true) c),
      'applications',(select coalesce(jsonb_agg(to_jsonb(a) order by a.app_name),'[]'::jsonb) from (select app_code,app_name,description,supports_login,default_roles from public.school_portal_catalog where is_active=true) a),
      'access_summary',(select coalesce(jsonb_object_agg(app_code,total),'{}'::jsonb) from (select app_code,count(*) total from public.school_access_grants where grant_status='active' group by app_code) x)
    );
  end if;

  if p_action='students' then
    select jsonb_build_object('ok',true,'students',coalesce(jsonb_agg(to_jsonb(s) order by s.name),'[]'::jsonb))
    into v_result
    from (
      select st.id student_id,st.central_person_id person_id,st.name,st.gender,st.admno,st.class_key,
             st.archived,st.lifecycle_status,st.admission_date,st.admission_source,st.photo,
             (select count(*) from public.school_student_guardians g where g.student_id=st.id and g.status='active') guardian_count,
             (select count(*) from public.school_access_grants a where a.person_id=st.central_person_id and a.grant_status='active') access_count
      from public.students st
      where (v_class='' or st.class_key=v_class)
        and (v_status='' or (v_status='active' and st.archived=false) or (v_status='archived' and st.archived=true) or st.lifecycle_status=v_status)
        and (v_search='' or st.name ilike '%'||v_search||'%' or coalesce(st.admno,'') ilike '%'||v_search||'%')
      order by st.name
      limit 1500
    ) s;
    return v_result;
  end if;

  if p_action='staff' then
    select jsonb_build_object('ok',true,'staff',coalesce(jsonb_agg(to_jsonb(s) order by s.full_name),'[]'::jsonb))
    into v_result
    from (
      select sp.id staff_id,sp.central_person_id person_id,sp.staff_number,sp.full_name,sp.email,sp.phone,
             sp.staff_category,sp.department,sp.designation,sp.employment_status,sp.attendance_required,
             sp.registration_source,sp.registration_status,sp.photo,sp.whatsapp_number,sp.whatsapp_opt_in_status,
             sp.whatsapp_opt_in_at,sp.whatsapp_opt_in_source,sp.whatsapp_verified_at,sp.preferred_language,sp.pilot_enabled,
             (select count(*) from public.school_access_grants a where a.person_id=sp.central_person_id and a.grant_status='active') access_count,
             exists(select 1 from public.school_identity_accounts i where i.person_id=sp.central_person_id and i.account_status='active') has_login
      from public.staff_attendance_profiles sp
      where (v_status='' or sp.registration_status=v_status or sp.employment_status=v_status)
        and (v_search='' or sp.full_name ilike '%'||v_search||'%' or coalesce(sp.staff_number,'') ilike '%'||v_search||'%' or coalesce(sp.email,'') ilike '%'||v_search||'%')
      order by sp.full_name
      limit 1000
    ) s;
    return v_result;
  end if;

  if p_action='access' then
    begin v_person_id:=(p_payload->>'personId')::uuid;
    exception when others then return jsonb_build_object('ok',false,'code','INVALID_PERSON_ID'); end;
    return jsonb_build_object(
      'ok',true,
      'person',(select jsonb_build_object('id',id,'full_name',full_name,'status',person_status) from public.school_people where id=v_person_id),
      'grants',(select coalesce(jsonb_agg(to_jsonb(g) order by g.app_name),'[]'::jsonb) from (
        select a.id,a.app_code,c.app_name,a.access_role,a.permissions,a.grant_status,a.valid_from,a.valid_until,a.reason
        from public.school_access_grants a join public.school_portal_catalog c on c.app_code=a.app_code
        where a.person_id=v_person_id
      ) g),
      'account',(select to_jsonb(i) from (select id,auth_user_id,legacy_user_profile_id,login_email,account_status,identity_source,last_login_at from public.school_identity_accounts where person_id=v_person_id limit 1) i)
    );
  end if;

  if p_action='admissions' then
    select jsonb_build_object('ok',true,'applications',coalesce(jsonb_agg(to_jsonb(a) order by a.created_at desc),'[]'::jsonb))
    into v_result
    from (
      select id,application_number,desired_session,desired_class_key,student_full_name,gender,date_of_birth,
             guardian_full_name,guardian_relationship,guardian_phone,guardian_whatsapp,guardian_email,
             notification_consent,preferred_language,application_status,rejection_reason,linked_student_id,
             submitted_at,reviewed_at,enrolled_at,created_at
      from public.school_admission_applications
      where (v_status='' or application_status=v_status)
        and (v_search='' or student_full_name ilike '%'||v_search||'%' or application_number ilike '%'||v_search||'%' or coalesce(guardian_full_name,'') ilike '%'||v_search||'%')
      order by created_at desc
      limit 1000
    ) a;
    return v_result;
  end if;

  if p_action='guardians' then
    begin v_student_id:=(p_payload->>'studentId')::uuid;
    exception when others then return jsonb_build_object('ok',false,'code','INVALID_STUDENT_ID'); end;
    return jsonb_build_object('ok',true,'guardians',(
      select coalesce(jsonb_agg(to_jsonb(g) order by g.is_primary desc,g.full_name),'[]'::jsonb)
      from (
        select sg.id relationship_id,gd.id guardian_id,gd.full_name,gd.primary_phone,gd.whatsapp_phone,gd.email,
               sg.relationship,sg.is_primary,sg.is_legal_guardian,sg.notification_consent,sg.preferred_language,sg.status
        from public.school_student_guardians sg join public.school_guardians gd on gd.id=sg.guardian_id
        where sg.student_id=v_student_id
      ) g
    ));
  end if;

  if p_action='outbox' then
    select jsonb_build_object('ok',true,'events',coalesce(jsonb_agg(to_jsonb(o) order by o.created_at desc),'[]'::jsonb))
    into v_result
    from (
      select id,event_type,aggregate_type,aggregate_id,target_apps,event_status,attempts,available_at,processed_at,last_error,created_at
      from public.school_registry_outbox
      where (v_status='' or event_status=v_status)
      order by created_at desc limit 1000
    ) o;
    return v_result;
  end if;

  return jsonb_build_object('ok',false,'code','UNKNOWN_ACTION');
end;
$function$;

-- Internal trigger and helper functions remain executable by their owner and
-- privileged roles. Only direct Data API execution is removed.
revoke execute on function public.school_access_sync_admin_client_trigger() from public, anon, authenticated;
revoke execute on function public.school_registry_after_staff() from public, anon, authenticated;
revoke execute on function public.school_registry_after_student() from public, anon, authenticated;
revoke execute on function public.school_registry_before_staff() from public, anon, authenticated;
revoke execute on function public.school_registry_before_student() from public, anon, authenticated;
revoke execute on function public.school_registry_prevent_hard_delete() from public, anon, authenticated;
revoke execute on function public.school_staff_number_guard() from public, anon, authenticated;
revoke execute on function public.school_students_number_guard() from public, anon, authenticated;
revoke execute on function public.school_sync_staff_self_service_access() from public, anon, authenticated;
revoke execute on function public.school_registry_verify_admin(text,text,text) from public, anon, authenticated;
revoke execute on function public.school_registry_upsert_guardian(uuid,text,text,text,text,text,boolean,boolean,boolean,text) from public, anon, authenticated;
revoke execute on function public.school_sync_person_admin_client(uuid) from public, anon, authenticated;
revoke execute on function public.school_registry_current_session() from public, anon, authenticated;
revoke execute on function public.school_registry_gender(text) from public, anon, authenticated;
revoke execute on function public.school_normalize_nigerian_phone(text) from public, anon, authenticated;
