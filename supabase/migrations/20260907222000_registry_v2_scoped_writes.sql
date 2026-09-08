-- Registry v2 transactional writes. All authorization decisions are derived
-- from the server-side entitlement snapshot; browser payloads are data only.

create or replace function public.school_registry_write_v2(
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
  v_actor uuid;
  v_staff uuid;
  v_action text := lower(trim(coalesce(p_action,'')));
  v_request_id uuid;
  v_existing jsonb;
  v_result jsonb;
  v_student uuid;
  v_target_class text;
  v_source_class text;
  v_reason text;
  v_status text;
  v_app text;
  v_permissions text[] := array[]::text[];
  v_allowed_roles text[] := array[]::text[];
  v_staff_id uuid;
  v_person_id uuid;
  v_transition_id uuid;
  v_current jsonb;
  v_subject integer;
  v_subject_indexes integer[] := array[]::integer[];
  v_allocation_id uuid;
  v_item jsonb;
  v_row record;
  v_gate jsonb;
  v_count integer := 0;
begin
  v_auth := wts_internal.school_registry_session_entitlements(p_session_id,p_session_secret);
  if coalesce((v_auth ->> 'ok')::boolean,false) is not true then return v_auth; end if;
  v_ent := coalesce(v_auth -> 'entitlements','{}'::jsonb);
  v_actor := nullif(v_auth -> 'actor' ->> 'personId','')::uuid;
  v_staff := nullif(v_auth -> 'actor' ->> 'staffId','')::uuid;
  begin v_request_id := nullif(p_payload ->> 'requestId','')::uuid; exception when others then v_request_id := null; end;
  v_request_id := coalesce(v_request_id,gen_random_uuid());
  select outcome into v_existing
  from public.school_registry_request_outcomes
  where request_id=v_request_id and actor_person_id=v_actor and operation=v_action;
  if v_existing is not null then return v_existing; end if;
  if exists(select 1 from public.school_registry_request_outcomes where request_id=v_request_id) then
    return jsonb_build_object('ok',false,'code','IDEMPOTENCY_KEY_REUSED');
  end if;

  if v_action in ('profile.self.update','profile.update') then
    if not wts_internal.school_registry_has_capability(v_ent,'profile.self.update') then return jsonb_build_object('ok',false,'code','REGISTRY_CAPABILITY_DENIED'); end if;
    if p_payload ? 'photo' and length(coalesce(p_payload->>'photo','')) > 300 then return jsonb_build_object('ok',false,'code','PROFILE_PHOTO_PATH_INVALID'); end if;
    update public.staff_attendance_profiles set
      phone = case when p_payload ? 'phone' then nullif(left(trim(coalesce(p_payload->>'phone','')),40),'') else phone end,
      whatsapp_number = case when p_payload ? 'whatsappNumber' then nullif(left(trim(coalesce(p_payload->>'whatsappNumber','')),40),'') else whatsapp_number end,
      address = case when p_payload ? 'address' then nullif(left(trim(coalesce(p_payload->>'address','')),500),'') else address end,
      emergency_contact = case when p_payload ? 'emergencyContact' then nullif(left(trim(coalesce(p_payload->>'emergencyContact','')),240),'') else emergency_contact end,
      photo = case when p_payload ? 'photo' then nullif(trim(coalesce(p_payload->>'photo','')),'') else photo end,
      updated_at=now()
    where id=v_staff and central_person_id=v_actor and registration_status='active' and employment_status='active';
    if not found then return jsonb_build_object('ok',false,'code','REGISTRY_IDENTITY_NOT_ACTIVE'); end if;
    insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,request_id,details)
    values('person',v_actor::text,'staff.profile_self_updated','staff_attendance_profile',v_staff::text,v_request_id,jsonb_build_object('fields',array(select key from jsonb_each(p_payload) where key<>'requestId')));
    v_result := jsonb_build_object('ok',true,'code','PROFILE_UPDATED','request_id',v_request_id);
    insert into public.school_registry_request_outcomes values(v_request_id,v_actor,v_action,v_result,now()); return v_result;
  end if;

  if v_action='profile.signature.update' then
    if not wts_internal.school_registry_has_capability(v_ent,'profile.signature.update') then return jsonb_build_object('ok',false,'code','REGISTRY_CAPABILITY_DENIED'); end if;
    if nullif(trim(coalesce(p_payload->>'signaturePath','')),'') is null or length(p_payload->>'signaturePath') > 300 or (p_payload->>'signaturePath') !~ ('^staff-signatures/'||v_actor::text||'\.(png|jpe?g|webp)$') then return jsonb_build_object('ok',false,'code','SIGNATURE_PATH_INVALID'); end if;
    update public.staff_attendance_profiles set signature_path=p_payload->>'signaturePath',signature_uploaded_at=now(),updated_at=now() where id=v_staff and central_person_id=v_actor and registration_status='active' and employment_status='active';
    if not found then return jsonb_build_object('ok',false,'code','REGISTRY_IDENTITY_NOT_ACTIVE'); end if;
    insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,request_id,details)
    values('person',v_actor::text,'staff.signature_updated','staff_attendance_profile',v_staff::text,v_request_id,jsonb_build_object('signature_path',p_payload->>'signaturePath'));
    v_result := jsonb_build_object('ok',true,'code','SIGNATURE_SAVED','signaturePath',p_payload->>'signaturePath','request_id',v_request_id); insert into public.school_registry_request_outcomes values(v_request_id,v_actor,v_action,v_result,now()); return v_result;
  end if;

  if v_action in ('students.create','student.create') then
    v_target_class := nullif(trim(coalesce(p_payload->>'classKey','')),'');
    if not (wts_internal.school_registry_has_capability(v_ent,'students.school.manage') or (wts_internal.school_registry_has_capability(v_ent,'students.class.manage') and v_target_class in (select value from jsonb_array_elements_text(coalesce(v_ent->'classScopes','[]'::jsonb))))) then return jsonb_build_object('ok',false,'code','TARGET_CLASS_OUT_OF_SCOPE'); end if;
    if not exists(select 1 from public.school_classes c where c.class_key=v_target_class and c.is_active and lower(c.class_key) not like 'archive-%') then return jsonb_build_object('ok',false,'code','ACTIVE_CLASS_NOT_FOUND'); end if;
    if nullif(trim(coalesce(p_payload->>'name','')),'') is null then return jsonb_build_object('ok',false,'code','STUDENT_NAME_REQUIRED'); end if;
    if nullif(trim(coalesce(p_payload->>'admissionDate','')),'') is not null and (p_payload->>'admissionDate')::date > current_date then return jsonb_build_object('ok',false,'code','ADMISSION_DATE_FUTURE'); end if;
    insert into public.students(class_key,name,gender,house,age,photo,archived,lifecycle_status,admission_date,admission_source)
    values(v_target_class,left(trim(p_payload->>'name'),160),case lower(trim(coalesce(p_payload->>'gender',''))) when 'male' then 'Male' when 'female' then 'Female' else 'Unknown' end,nullif(trim(p_payload->>'house'),''),nullif(trim(p_payload->>'age'),''),nullif(trim(p_payload->>'photo'),''),false,'active',coalesce(nullif(p_payload->>'admissionDate','')::date,current_date),'central_registry') returning id into v_student;
    insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,request_id,after_data) select 'person',v_actor::text,'student.create','student',v_student::text,v_request_id,to_jsonb(s) from public.students s where s.id=v_student;
    v_result := jsonb_build_object('ok',true,'code','STUDENT_CREATED','studentId',v_student,'request_id',v_request_id);
    insert into public.school_registry_request_outcomes values(v_request_id,v_actor,v_action,v_result,now()); return v_result;
  end if;

  if v_action in ('students.update','student.update','students.archive','student.archive','students.restore','student.restore') then
    begin v_student := (p_payload->>'studentId')::uuid; exception when others then return jsonb_build_object('ok',false,'code','INVALID_STUDENT_ID'); end;
    select class_key into v_source_class from public.students where id=v_student for update;
    if v_source_class is null then return jsonb_build_object('ok',false,'code','STUDENT_NOT_FOUND'); end if;
    if not (wts_internal.school_registry_has_capability(v_ent,'students.school.manage') or (wts_internal.school_registry_has_capability(v_ent,'students.class.manage') and v_source_class in (select value from jsonb_array_elements_text(coalesce(v_ent->'classScopes','[]'::jsonb))))) then return jsonb_build_object('ok',false,'code','REGISTRY_SCOPE_DENIED'); end if;
    v_target_class := coalesce(nullif(trim(coalesce(p_payload->>'classKey','')),''),v_source_class);
    if v_action in ('students.update','student.update','students.restore','student.restore') and v_target_class <> v_source_class and not (wts_internal.school_registry_has_capability(v_ent,'students.school.manage') or v_target_class in (select value from jsonb_array_elements_text(coalesce(v_ent->'classScopes','[]'::jsonb)))) then return jsonb_build_object('ok',false,'code','TARGET_CLASS_OUT_OF_SCOPE'); end if;
    if v_action in ('students.update','student.update','students.restore','student.restore') and not exists(select 1 from public.school_classes c where c.class_key=v_target_class and c.is_active and lower(c.class_key) not like 'archive-%') then return jsonb_build_object('ok',false,'code','ACTIVE_CLASS_NOT_FOUND'); end if;
    if v_action in ('students.update','student.update') then
      update public.students set name=coalesce(nullif(trim(p_payload->>'name'),''),name),class_key=v_target_class,gender=case when nullif(trim(p_payload->>'gender'),'') is null then gender when lower(trim(p_payload->>'gender'))='male' then 'Male' when lower(trim(p_payload->>'gender'))='female' then 'Female' else 'Unknown' end,house=case when p_payload ? 'house' then nullif(trim(p_payload->>'house'),'') else house end,age=case when p_payload ? 'age' then nullif(trim(p_payload->>'age'),'') else age end,photo=case when p_payload ? 'photo' then nullif(trim(p_payload->>'photo'),'') else photo end,updated_at=now() where id=v_student;
      v_status := 'STUDENT_UPDATED';
    elsif v_action in ('students.archive','student.archive') then
      v_reason := nullif(trim(coalesce(p_payload->>'reason','')),'');
      if v_reason is null or length(v_reason)<8 then return jsonb_build_object('ok',false,'code','ARCHIVE_REASON_REQUIRED'); end if;
      v_status := coalesce(nullif(trim(p_payload->>'lifecycleStatus'),''),'archived');
      if v_status not in ('graduated','transferred','withdrawn','suspended','archived') then return jsonb_build_object('ok',false,'code','INVALID_LIFECYCLE_STATUS'); end if;
      update public.students set previous_class_key=class_key,archived=true,archived_at=now(),archived_reason=v_reason,lifecycle_status=v_status,updated_at=now() where id=v_student;
      v_status := 'STUDENT_ARCHIVED';
    else
      if not exists(select 1 from public.school_classes c where c.class_key=v_target_class and c.is_active and lower(c.class_key) not like 'archive-%') then return jsonb_build_object('ok',false,'code','ACTIVE_CLASS_NOT_FOUND'); end if;
      update public.students set archived=false,archived_at=null,archived_reason=null,lifecycle_status='active',class_key=v_target_class,updated_at=now() where id=v_student;
      v_status := 'STUDENT_RESTORED';
    end if;
    insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,request_id,after_data,details) select 'person',v_actor::text,lower(replace(v_status,'STUDENT_','student.')),'student',v_student::text,v_request_id,to_jsonb(s),jsonb_build_object('source_class',v_source_class,'target_class',v_target_class) from public.students s where s.id=v_student;
    v_result := jsonb_build_object('ok',true,'code',v_status,'studentId',v_student,'request_id',v_request_id);
    insert into public.school_registry_request_outcomes values(v_request_id,v_actor,v_action,v_result,now()); return v_result;
  end if;

  if v_action='guardian.upsert' then
    begin v_student := (p_payload->>'studentId')::uuid; exception when others then return jsonb_build_object('ok',false,'code','INVALID_STUDENT_ID'); end;
    select class_key into v_source_class from public.students where id=v_student;
    if v_source_class is null then return jsonb_build_object('ok',false,'code','STUDENT_NOT_FOUND'); end if;
    if not (wts_internal.school_registry_has_capability(v_ent,'students.school.manage') or wts_internal.school_registry_has_capability(v_ent,'students.class.manage') and v_source_class in (select value from jsonb_array_elements_text(coalesce(v_ent->'classScopes','[]'::jsonb)))) then return jsonb_build_object('ok',false,'code','REGISTRY_SCOPE_DENIED'); end if;
    if nullif(trim(coalesce(p_payload->>'fullName','')),'') is null then return jsonb_build_object('ok',false,'code','GUARDIAN_NAME_REQUIRED'); end if;
    if nullif(trim(coalesce(p_payload->>'phone','')),'') is null and nullif(trim(coalesce(p_payload->>'whatsappNumber','')),'') is null and nullif(trim(coalesce(p_payload->>'email','')),'') is null then return jsonb_build_object('ok',false,'code','GUARDIAN_CONTACT_REQUIRED'); end if;
    v_result := public.school_registry_upsert_guardian(v_student,left(trim(p_payload->>'fullName'),160),coalesce(nullif(trim(p_payload->>'relationship'),''),'Guardian'),nullif(trim(p_payload->>'phone'),''),nullif(trim(p_payload->>'whatsappNumber'),''),nullif(trim(p_payload->>'email'),''),coalesce((p_payload->>'isPrimary')::boolean,true),coalesce((p_payload->>'isLegalGuardian')::boolean,true),coalesce((p_payload->>'notificationConsent')::boolean,false),coalesce(nullif(trim(p_payload->>'preferredLanguage'),''),'english'));
    if coalesce((v_result->>'ok')::boolean,false) is not true then return v_result; end if;
    v_result := v_result || jsonb_build_object('request_id',v_request_id); insert into public.school_registry_request_outcomes values(v_request_id,v_actor,v_action,v_result,now()); return v_result;
  end if;

  if v_action='allocations.class.set' then
    if not (wts_internal.school_registry_has_capability(v_ent,'allocations.school.manage') or wts_internal.school_registry_has_capability(v_ent,'allocations.early_childhood.manage')) then return jsonb_build_object('ok',false,'code','REGISTRY_CAPABILITY_DENIED'); end if;
    v_target_class := nullif(trim(coalesce(p_payload->>'classKey','')),'');
    begin v_staff_id := nullif(trim(coalesce(p_payload->>'staffId','')),'')::uuid; exception when others then return jsonb_build_object('ok',false,'code','ALLOCATION_STAFF_ID_INVALID'); end;
    if v_target_class is null or v_staff_id is null then return jsonb_build_object('ok',false,'code','ALLOCATION_INPUT_REQUIRED'); end if;
    if lower(coalesce(p_payload->>'responsibility','class_teacher')) not in ('class_teacher','assistant_class_teacher') then return jsonb_build_object('ok',false,'code','CLASS_RESPONSIBILITY_INVALID'); end if;
    if length(trim(coalesce(p_payload->>'reason',''))) < 8 then return jsonb_build_object('ok',false,'code','ALLOCATION_REASON_REQUIRED'); end if;
    if not exists(select 1 from public.school_classes c where c.class_key=v_target_class and c.is_active and lower(c.class_key) not like 'archive-%') then return jsonb_build_object('ok',false,'code','ACTIVE_CLASS_NOT_FOUND'); end if;
    if wts_internal.school_registry_has_capability(v_ent,'allocations.early_childhood.manage') and not wts_internal.school_registry_has_capability(v_ent,'allocations.school.manage') and not exists(select 1 from public.school_classes c where c.class_key=v_target_class and c.stage_code='early_childhood') then return jsonb_build_object('ok',false,'code','TARGET_CLASS_OUT_OF_SCOPE'); end if;
    if not exists(select 1 from public.staff_attendance_profiles s where s.id=v_staff_id and s.registration_status='active' and s.employment_status='active') then return jsonb_build_object('ok',false,'code','ACTIVE_STAFF_REQUIRED'); end if;
    v_current := public.school_academic_current();
    v_gate := public.school_academic_term_write_gate(v_current->>'academic_session',v_current->>'term');
    if coalesce((v_gate->>'ok')::boolean,false) is not true then return v_gate; end if;
    if lower(coalesce(p_payload->>'responsibility','class_teacher'))='class_teacher' then
      for v_row in select id,staff_id,person_id from public.school_staff_class_allocations where academic_session=v_current->>'academic_session' and term_name=v_current->>'term' and class_key=v_target_class and responsibility='assistant_class_teacher' and allocation_status='active' and staff_id=v_staff_id for update loop
        update public.school_staff_class_allocations set allocation_status='ended',effective_until=now(),updated_at=now(),revocation_reason='Promoted from assistant to main class teacher' where id=v_row.id;
        perform public.school_registry_sync_allocation_scope(v_row.person_id,v_row.staff_id,'class',v_target_class,null,v_current->>'academic_session',v_current->>'term',false,v_actor,v_row.id,'Promoted from assistant to main class teacher');
      end loop;
      for v_row in select id,staff_id,person_id from public.school_staff_class_allocations where academic_session=v_current->>'academic_session' and term_name=v_current->>'term' and class_key=v_target_class and responsibility='class_teacher' and allocation_status='active' and staff_id<>v_staff_id for update loop
        update public.school_staff_class_allocations set allocation_status='ended',effective_until=now(),updated_at=now(),revocation_reason='Replaced by a new main teacher' where id=v_row.id;
        perform public.school_registry_sync_allocation_scope(v_row.person_id,v_row.staff_id,'class',v_target_class,null,v_current->>'academic_session',v_current->>'term',false,v_actor,v_row.id,'Replaced by a new main teacher');
        perform public.school_registry_sync_class_teacher_role(v_row.person_id,v_row.staff_id,false,v_actor,'Replaced by a new main teacher');
      end loop;
    elsif exists(select 1 from public.school_staff_class_allocations where academic_session=v_current->>'academic_session' and term_name=v_current->>'term' and class_key=v_target_class and responsibility='class_teacher' and allocation_status='active' and staff_id=v_staff_id) then
      return jsonb_build_object('ok',false,'code','STAFF_ALREADY_MAIN_TEACHER');
    end if;
    insert into public.school_staff_class_allocations(staff_id,person_id,academic_session,term_name,class_key,responsibility,allocation_status,assigned_by_person_id,reason)
    select v_staff_id,s.central_person_id,v_current->>'academic_session',v_current->>'term',v_target_class,case when lower(coalesce(p_payload->>'responsibility','class_teacher'))='assistant_class_teacher' then 'assistant_class_teacher' else 'class_teacher' end,'active',v_actor,coalesce(nullif(trim(p_payload->>'reason'),''),'Central Registry allocation') from public.staff_attendance_profiles s where s.id=v_staff_id
    on conflict (staff_id,academic_session,term_name,class_key,responsibility) where allocation_status='active' do update set updated_at=now(),reason=excluded.reason,assigned_by_person_id=excluded.assigned_by_person_id;
    select central_person_id into v_person_id from public.staff_attendance_profiles where id=v_staff_id;
    select a.id into v_allocation_id
    from public.school_staff_class_allocations a
    where a.staff_id=v_staff_id
      and a.academic_session=v_current->>'academic_session'
      and a.term_name=v_current->>'term'
      and a.class_key=v_target_class
      and a.responsibility=case when lower(coalesce(p_payload->>'responsibility','class_teacher'))='assistant_class_teacher' then 'assistant_class_teacher' else 'class_teacher' end
      and a.allocation_status='active'
    order by a.created_at desc
    limit 1;
    if v_allocation_id is null then
      return jsonb_build_object('ok',false,'code','ALLOCATION_SAVE_FAILED');
    end if;
    perform public.school_registry_sync_allocation_scope(
      v_person_id,v_staff_id,'class',v_target_class,null,
      v_current->>'academic_session',v_current->>'term',true,v_actor,v_allocation_id,
      coalesce(nullif(trim(p_payload->>'reason'),''),'Central Registry allocation')
    );
    if lower(coalesce(p_payload->>'responsibility','class_teacher'))='class_teacher' then
      perform public.school_registry_sync_class_teacher_role(
        v_person_id,v_staff_id,true,v_actor,
        coalesce(nullif(trim(p_payload->>'reason'),''),'Central Registry allocation')
      );
    end if;
    insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,request_id,details)
    values('person',v_actor::text,'staff.class_allocation_saved','school_staff_class_allocation',v_allocation_id::text,v_request_id,
      jsonb_build_object('staff_id',v_staff_id,'person_id',v_person_id,'class_key',v_target_class,'responsibility',lower(coalesce(p_payload->>'responsibility','class_teacher')),'academic_session',v_current->>'academic_session','term',v_current->>'term'));
    v_result := jsonb_build_object('ok',true,'code','CLASS_ALLOCATION_SAVED','allocationId',v_allocation_id,'request_id',v_request_id); insert into public.school_registry_request_outcomes values(v_request_id,v_actor,v_action,v_result,now()); return v_result;
  end if;

  if v_action='allocations.subject.set' then
    if not wts_internal.school_registry_has_capability(v_ent,'allocations.school.manage') then return jsonb_build_object('ok',false,'code','REGISTRY_CAPABILITY_DENIED'); end if;
    begin v_staff_id := nullif(trim(coalesce(p_payload->>'staffId','')),'')::uuid; exception when others then return jsonb_build_object('ok',false,'code','ALLOCATION_STAFF_ID_INVALID'); end;
    v_target_class := nullif(trim(coalesce(p_payload->>'classKey','')),'');
    if v_staff_id is null or v_target_class is null or jsonb_typeof(p_payload->'subjectIndexes') <> 'array' then return jsonb_build_object('ok',false,'code','SUBJECT_ALLOCATION_INPUT_REQUIRED'); end if;
    if length(trim(coalesce(p_payload->>'reason',''))) < 8 then return jsonb_build_object('ok',false,'code','ALLOCATION_REASON_REQUIRED'); end if;
    if not exists(select 1 from public.staff_attendance_profiles s where s.id=v_staff_id and s.registration_status='active' and s.employment_status='active') then return jsonb_build_object('ok',false,'code','ACTIVE_STAFF_REQUIRED'); end if;
    if not exists(select 1 from public.school_classes c where c.class_key=v_target_class and c.is_active and lower(c.class_key) not like 'archive-%') then return jsonb_build_object('ok',false,'code','ACTIVE_CLASS_NOT_FOUND'); end if;
    begin select coalesce(array_agg(distinct value::integer order by value::integer),array[]::integer[]) into v_subject_indexes from jsonb_array_elements_text(p_payload->'subjectIndexes') value; exception when others then return jsonb_build_object('ok',false,'code','SUBJECT_SELECTION_INVALID'); end;
    if cardinality(v_subject_indexes)=0 then return jsonb_build_object('ok',false,'code','SUBJECT_SELECTION_REQUIRED'); end if;
    if cardinality(v_subject_indexes)>100 then return jsonb_build_object('ok',false,'code','TOO_MANY_SUBJECTS_SELECTED'); end if;
    select central_person_id into v_person_id from public.staff_attendance_profiles where id=v_staff_id;
    v_current := public.school_academic_current();
    v_gate := public.school_academic_term_write_gate(v_current->>'academic_session',v_current->>'term');
    if coalesce((v_gate->>'ok')::boolean,false) is not true then return v_gate; end if;
    if exists (
      select 1 from unnest(v_subject_indexes) selected_index
      where not exists (
        select 1 from public.result_subject_catalog s
        where s.class_key=v_target_class and s.subject_index=selected_index and s.active
      )
    ) then return jsonb_build_object('ok',false,'code','ACTIVE_SUBJECT_NOT_FOUND'); end if;
    for v_row in
      select a.*
      from public.school_staff_subject_allocations a
      where a.staff_id=v_staff_id
        and a.academic_session=v_current->>'academic_session'
        and a.term_name=v_current->>'term'
        and a.class_key=v_target_class
        and a.allocation_status='active'
        and not (a.subject_index = any(v_subject_indexes))
      for update
    loop
      update public.school_staff_subject_allocations
      set allocation_status='revoked',effective_until=now(),revoked_by_person_id=v_actor,
          revoked_at=now(),revocation_reason=left(trim(coalesce(p_payload->>'reason','')),500),updated_at=now()
      where id=v_row.id;
      perform public.school_registry_sync_allocation_scope(
        v_row.person_id,v_row.staff_id,'subject',v_row.class_key,v_row.subject_index,
        v_row.academic_session,v_row.term_name,false,v_actor,v_row.id,
        coalesce(nullif(trim(p_payload->>'reason'),''),'Central Registry subject allocation')
      );
      v_count := v_count + 1;
    end loop;
    for v_subject in select distinct unnest(v_subject_indexes) loop
      insert into public.school_staff_subject_allocations(staff_id,person_id,academic_session,term_name,class_key,subject_index,allocation_status,assigned_by_person_id,reason)
      select v_staff_id,s.central_person_id,v_current->>'academic_session',v_current->>'term',v_target_class,v_subject,'active',v_actor,coalesce(nullif(trim(p_payload->>'reason'),''),'Central Registry subject allocation') from public.staff_attendance_profiles s where s.id=v_staff_id
      on conflict (staff_id,academic_session,term_name,class_key,subject_index) where allocation_status='active' do update set updated_at=now(),reason=excluded.reason,assigned_by_person_id=excluded.assigned_by_person_id;
      select a.id into v_allocation_id
      from public.school_staff_subject_allocations a
      where a.staff_id=v_staff_id and a.academic_session=v_current->>'academic_session'
        and a.term_name=v_current->>'term' and a.class_key=v_target_class
        and a.subject_index=v_subject and a.allocation_status='active'
      order by a.created_at desc
      limit 1;
      perform public.school_registry_sync_allocation_scope(
        v_person_id,v_staff_id,'subject',v_target_class,v_subject,v_current->>'academic_session',
        v_current->>'term',true,v_actor,v_allocation_id,
        coalesce(nullif(trim(p_payload->>'reason'),''),'Central Registry subject allocation')
      );
    end loop;
    insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,request_id,details)
    values('person',v_actor::text,'staff.subject_allocations_replaced','staff_attendance_profile',v_staff_id::text,v_request_id,
      jsonb_build_object('person_id',v_person_id,'class_key',v_target_class,'academic_session',v_current->>'academic_session','term',v_current->>'term','selected_subject_indexes',v_subject_indexes,'revoked_count',v_count));
    v_result := jsonb_build_object('ok',true,'code','SUBJECT_ALLOCATION_SAVED','revokedCount',v_count,'request_id',v_request_id); insert into public.school_registry_request_outcomes values(v_request_id,v_actor,v_action,v_result,now()); return v_result;
  end if;

  if v_action in ('allocations.class.end','allocations.subject.end') then
    if not (wts_internal.school_registry_has_capability(v_ent,'allocations.school.manage') or wts_internal.school_registry_has_capability(v_ent,'allocations.early_childhood.manage')) then return jsonb_build_object('ok',false,'code','REGISTRY_CAPABILITY_DENIED'); end if;
    begin v_allocation_id := (p_payload->>'allocationId')::uuid; exception when others then return jsonb_build_object('ok',false,'code','ALLOCATION_ID_INVALID'); end;
    if length(trim(coalesce(p_payload->>'reason',''))) < 8 then return jsonb_build_object('ok',false,'code','ALLOCATION_REASON_REQUIRED'); end if;
    v_current := public.school_academic_current();
    v_gate := public.school_academic_term_write_gate(v_current->>'academic_session',v_current->>'term');
    if coalesce((v_gate->>'ok')::boolean,false) is not true then return v_gate; end if;
    if v_action='allocations.class.end' then
      select a.* into v_row from public.school_staff_class_allocations a where a.id=v_allocation_id for update;
      if not found then return jsonb_build_object('ok',false,'code','CLASS_ALLOCATION_NOT_FOUND'); end if;
      if v_row.allocation_status <> 'active' then return jsonb_build_object('ok',false,'code','CLASS_ALLOCATION_NOT_FOUND'); end if;
      if v_row.academic_session <> v_current->>'academic_session' or v_row.term_name <> v_current->>'term' then return jsonb_build_object('ok',false,'code','ALLOCATION_CONTEXT_MISMATCH'); end if;
      if wts_internal.school_registry_has_capability(v_ent,'allocations.early_childhood.manage') and not wts_internal.school_registry_has_capability(v_ent,'allocations.school.manage') and not exists(select 1 from public.school_classes c where c.class_key=v_row.class_key and c.stage_code='early_childhood') then return jsonb_build_object('ok',false,'code','TARGET_CLASS_OUT_OF_SCOPE'); end if;
      update public.school_staff_class_allocations set allocation_status='ended',effective_until=now(),updated_at=now(),revoked_by_person_id=v_actor,revoked_at=now(),revocation_reason=left(trim(p_payload->>'reason'),500) where id=v_allocation_id;
      perform public.school_registry_sync_allocation_scope(v_row.person_id,v_row.staff_id,'class',v_row.class_key,null,v_row.academic_session,v_row.term_name,false,v_actor,v_allocation_id,left(trim(p_payload->>'reason'),500));
      if v_row.responsibility='class_teacher' then perform public.school_registry_sync_class_teacher_role(v_row.person_id,v_row.staff_id,false,v_actor,left(trim(p_payload->>'reason'),500)); end if;
      insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,request_id,details) values('person',v_actor::text,'staff.class_allocation_ended','school_staff_class_allocation',v_allocation_id::text,v_request_id,jsonb_build_object('class_key',v_row.class_key,'staff_id',v_row.staff_id,'reason',left(trim(p_payload->>'reason'),500)));
      v_result := jsonb_build_object('ok',true,'code','CLASS_ALLOCATION_ENDED','allocationId',v_allocation_id,'request_id',v_request_id);
    else
      select a.* into v_row from public.school_staff_subject_allocations a where a.id=v_allocation_id for update;
      if not found then return jsonb_build_object('ok',false,'code','SUBJECT_ALLOCATION_NOT_FOUND'); end if;
      if v_row.allocation_status <> 'active' then return jsonb_build_object('ok',false,'code','SUBJECT_ALLOCATION_NOT_FOUND'); end if;
      if v_row.academic_session <> v_current->>'academic_session' or v_row.term_name <> v_current->>'term' then return jsonb_build_object('ok',false,'code','ALLOCATION_CONTEXT_MISMATCH'); end if;
      if not wts_internal.school_registry_has_capability(v_ent,'allocations.school.manage') then return jsonb_build_object('ok',false,'code','REGISTRY_CAPABILITY_DENIED'); end if;
      update public.school_staff_subject_allocations set allocation_status='revoked',effective_until=now(),updated_at=now(),revoked_by_person_id=v_actor,revoked_at=now(),revocation_reason=left(trim(p_payload->>'reason'),500) where id=v_allocation_id;
      perform public.school_registry_sync_allocation_scope(v_row.person_id,v_row.staff_id,'subject',v_row.class_key,v_row.subject_index,v_row.academic_session,v_row.term_name,false,v_actor,v_allocation_id,left(trim(p_payload->>'reason'),500));
      insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,request_id,details) values('person',v_actor::text,'staff.subject_allocation_ended','school_staff_subject_allocation',v_allocation_id::text,v_request_id,jsonb_build_object('class_key',v_row.class_key,'subject_index',v_row.subject_index,'staff_id',v_row.staff_id,'reason',left(trim(p_payload->>'reason'),500)));
      v_result := jsonb_build_object('ok',true,'code','SUBJECT_ALLOCATION_ENDED','allocationId',v_allocation_id,'request_id',v_request_id);
    end if;
    insert into public.school_registry_request_outcomes values(v_request_id,v_actor,v_action,v_result,now()); return v_result;
  end if;

  if v_action='portal.operating_mode.set' then
    if not wts_internal.school_registry_has_capability(v_ent,'portal.operating_mode.manage') or not wts_internal.school_registry_is_technical_actor(v_actor) then return jsonb_build_object('ok',false,'code','PORTAL_OPERATING_MODE_MANAGE_DENIED'); end if;
    v_app := lower(trim(coalesce(p_payload->>'appCode','')));
    v_status := lower(trim(coalesce(p_payload->>'operatingMode','')));
    v_reason := nullif(trim(coalesce(p_payload->>'reason','')),'');
    if v_app<>'results' or v_status not in ('active','read_only') then return jsonb_build_object('ok',false,'code','PORTAL_OPERATING_MODE_INVALID'); end if;
    if v_reason is null or length(v_reason)<8 then return jsonb_build_object('ok',false,'code','PORTAL_OPERATING_MODE_REASON_REQUIRED'); end if;
    select to_jsonb(o) into v_item from public.school_module_operating_controls o where o.app_code=v_app for update;
    update public.school_module_operating_controls set operating_mode=v_status,reason=left(v_reason,500),updated_by_person_id=v_actor,updated_at=now(),metadata=metadata||jsonb_build_object('managed_from','registry_v2','request_id',v_request_id) where app_code=v_app;
    if not found then return jsonb_build_object('ok',false,'code','PORTAL_OPERATING_CONTROL_NOT_FOUND'); end if;
    insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,request_id,before_data,after_data,details)
    values('person',v_actor::text,'portal.operating_mode.updated','school_module_operating_controls',v_app,v_request_id,v_item,(select to_jsonb(o) from public.school_module_operating_controls o where o.app_code=v_app),jsonb_build_object('app_code',v_app,'operating_mode',v_status,'reason',left(v_reason,500)));
    v_result := jsonb_build_object('ok',true,'code','RESULTS_OPERATING_MODE_UPDATED','appCode',v_app,'operatingMode',v_status,'request_id',v_request_id);
    insert into public.school_registry_request_outcomes values(v_request_id,v_actor,v_action,v_result,now()); return v_result;
  end if;

  if v_action='portal.access.set' then
    if not wts_internal.school_registry_has_capability(v_ent,'portal_access.manage') then return jsonb_build_object('ok',false,'code','REGISTRY_CAPABILITY_DENIED'); end if;
    begin v_person_id := nullif(trim(coalesce(p_payload->>'personId','')),'')::uuid; exception when others then return jsonb_build_object('ok',false,'code','PERSON_ID_INVALID'); end;
    if v_person_id is null or not exists(select 1 from public.staff_attendance_profiles s where s.central_person_id=v_person_id and s.registration_status='active' and s.employment_status='active') then return jsonb_build_object('ok',false,'code','ACTIVE_STAFF_REQUIRED'); end if;
    v_app := lower(trim(coalesce(p_payload->>'appCode','')));
    v_status := lower(trim(coalesce(p_payload->>'accessRole','staff')));
    if v_app='' then return jsonb_build_object('ok',false,'code','PORTAL_APP_REQUIRED'); end if;
    if not exists(select 1 from public.school_portal_catalog c where c.app_code=v_app and c.is_active) then return jsonb_build_object('ok',false,'code','PORTAL_NOT_FOUND'); end if;
    if coalesce((p_payload->>'enabled')::boolean,false) and not wts_internal.school_portal_entry_allowed(v_person_id,v_app) then return jsonb_build_object('ok',false,'code','PORTAL_OPERATING_MODE_RESTRICTED'); end if;
    select coalesce(array_agg(distinct lower(trim(x.role_name))) filter (where nullif(trim(x.role_name),'') is not null),array[]::text[])
      into v_allowed_roles
    from (
      select unnest(coalesce(c.default_roles,array[]::text[])) role_name
      from public.school_portal_catalog c where c.app_code=v_app and c.is_active
      union all
      select p.default_access_role from public.school_portal_access_policy p where p.app_code=v_app and p.is_active
      union all
      select g.access_role from public.school_access_grants g where g.person_id=v_person_id and g.app_code=v_app
    ) x;
    if not (v_status = any(v_allowed_roles)) then return jsonb_build_object('ok',false,'code','PORTAL_ROLE_INVALID'); end if;
    if v_app='results' and v_status in ('admin','administrator','results_admin') and not wts_internal.school_registry_has_capability(v_ent,'portal.results.admin') then return jsonb_build_object('ok',false,'code','PROTECTED_PORTAL_ROLE_RESTRICTED'); end if;
    if v_app='attendance' and v_status in ('admin','administrator','attendance_admin') and not wts_internal.school_registry_has_capability(v_ent,'attendance.setup') then return jsonb_build_object('ok',false,'code','PROTECTED_PORTAL_ROLE_RESTRICTED'); end if;
    if v_app='central_registry' and v_status in ('admin','administrator','registry_admin') and not wts_internal.school_registry_is_protected_actor(v_actor) then return jsonb_build_object('ok',false,'code','PROTECTED_PORTAL_ROLE_RESTRICTED'); end if;
    if v_app='notifications' and not wts_internal.school_registry_is_protected_actor(v_person_id) and not exists(
      select 1 from public.school_portfolio_assignments a
      where a.holder_type='staff'
        and a.holder_person_id=v_person_id
        and a.assignment_status='active'
        and a.portfolio_code in ('developer','proprietor','director','principal','vice_principal','director_primary','headmistress','assistant_headmistress')
        and a.effective_from<=now() and (a.effective_until is null or a.effective_until>now())
    ) then return jsonb_build_object('ok',false,'code','PORTAL_POLICY_RESTRICTED'); end if;
    if not coalesce((p_payload->>'enabled')::boolean,false)
      and v_app='central_registry'
      and exists(select 1 from public.school_access_grants g where g.person_id=v_person_id and g.app_code='central_registry' and g.grant_status='active' and coalesce((g.metadata->>'primary_registry_admin')::boolean,false)) then
      return jsonb_build_object('ok',false,'code','PRIMARY_SUPER_ADMIN_ACCESS_CANNOT_BE_REVOKED_HERE');
    end if;
    select to_jsonb(g) into v_item from public.school_access_grants g where g.person_id=v_person_id and g.app_code=v_app;
    if coalesce((p_payload->>'enabled')::boolean,false) then
      v_permissions := case
        when v_app='results' and v_status in ('admin','administrator','results_admin') then array['result_entry.view','result_entry.create','result_entry.edit','result_entry.submit','result_review.review','result_approval.approve','report_cards.generate','result_publishing.publish']::text[]
        when v_app='results' then array['result_entry.view']::text[]
        when v_app='attendance' and v_status in ('admin','administrator','attendance_admin') then array['dashboard.read','staff.read','reports.read','credentials.manage','staff.manage','devices.manage','staff.rules.manage','settings.manage','corrections.create','corrections.review','manual_entries.create','manual_entries.review']::text[]
        when v_app='attendance' then array['dashboard.read']::text[]
        when v_app='notifications' and v_status in ('admin','administrator','notification_admin') then array['notifications.manage','settings.manage']::text[]
        when v_app='notifications' then array['notifications.view']::text[]
        when v_app='central_registry' and v_status in ('admin','administrator','registry_admin') then array['registry.read','registry.manage','admissions.manage','access.manage']::text[]
        when v_app='central_registry' then array['registry.read']::text[]
        when v_app='staff_self_service' then array['profile.self.read','profile.self.update']::text[]
        else array[]::text[]
      end;
      insert into public.school_access_grants(person_id,app_code,access_role,permissions,grant_status,valid_from,granted_by_person_id,reason,metadata)
      values(v_person_id,v_app,v_status,v_permissions,'active',now(),v_actor,'Registry v2 portal access assignment',jsonb_build_object('managed_from','registry_v2','request_id',v_request_id))
      on conflict(person_id,app_code) do update set access_role=excluded.access_role,permissions=case when public.school_access_grants.metadata->>'managed_from'='portal_policy' and public.school_access_grants.access_role=excluded.access_role then public.school_access_grants.permissions else excluded.permissions end,grant_status='active',valid_from=now(),valid_until=null,granted_by_person_id=v_actor,reason=excluded.reason,metadata=public.school_access_grants.metadata||excluded.metadata,revoked_by_person_id=null,revoked_at=null,revocation_reason=null,updated_at=now();
    else
      update public.school_access_grants set grant_status='revoked',revoked_by_person_id=v_actor,revoked_at=now(),revocation_reason='Explicit Registry v2 disable',updated_at=now() where person_id=v_person_id and app_code=v_app;
    end if;
    select g.id into v_transition_id from public.school_access_grants g where g.person_id=v_person_id and g.app_code=v_app;
    insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,request_id,before_data,after_data,details)
    values('person',v_actor::text,case when coalesce((p_payload->>'enabled')::boolean,false) then 'staff_access.module_granted' else 'staff_access.module_revoked' end,'school_access_grant',coalesce(v_transition_id::text,v_person_id::text),v_request_id,v_item,(select to_jsonb(g) from public.school_access_grants g where g.person_id=v_person_id and g.app_code=v_app),jsonb_build_object('person_id',v_person_id,'app_code',v_app,'access_role',v_status,'managed_from','registry_v2'));
    v_result := jsonb_build_object('ok',true,'code','PORTAL_ACCESS_UPDATED','request_id',v_request_id); insert into public.school_registry_request_outcomes values(v_request_id,v_actor,v_action,v_result,now()); return v_result;
  end if;

  if v_action='registration.under_review' then
    if not wts_internal.school_registry_has_capability(v_ent,'staff.school.read') then return jsonb_build_object('ok',false,'code','REGISTRY_CAPABILITY_DENIED'); end if;
    begin v_student := (p_payload->>'registrationId')::uuid; exception when others then return jsonb_build_object('ok',false,'code','REGISTRATION_ID_INVALID'); end;
    update public.school_staff_registrations set registration_status='under_review',reviewed_by_person_id=v_actor,reviewed_at=now(),updated_at=now() where id=v_student and registration_status in ('pending','under_review');
    if not found then return jsonb_build_object('ok',false,'code','STAFF_REGISTRATION_NOT_FOUND'); end if;
    insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,request_id)
    values('person',v_actor::text,'staff.registration_under_review','school_staff_registration',v_student::text,v_request_id);
    v_result := jsonb_build_object('ok',true,'code','REGISTRATION_UNDER_REVIEW','request_id',v_request_id); insert into public.school_registry_request_outcomes values(v_request_id,v_actor,v_action,v_result,now()); return v_result;
  end if;

  if v_action in ('registration.approve','registration.reject') then
    if not wts_internal.school_registry_has_capability(v_ent,'portfolio.manage') then return jsonb_build_object('ok',false,'code','REGISTRY_CAPABILITY_DENIED'); end if;
    if v_action='registration.approve' then
      begin v_student := (p_payload->>'registrationId')::uuid; exception when others then return jsonb_build_object('ok',false,'code','REGISTRATION_ID_INVALID'); end;
      v_result := wts_internal.school_registry_approve_registration_v2(v_student,v_actor,p_payload);
    else
      begin v_student := (p_payload->>'registrationId')::uuid; exception when others then return jsonb_build_object('ok',false,'code','REGISTRATION_ID_INVALID'); end;
      if length(trim(coalesce(p_payload->>'reason',''))) < 8 then return jsonb_build_object('ok',false,'code','REJECTION_REASON_REQUIRED'); end if;
      update public.school_staff_registrations set registration_status='rejected',rejection_reason=left(coalesce(p_payload->>'reason','Rejected through Registry v2'),500),reviewed_by_person_id=v_actor,reviewed_at=now(),updated_at=now() where id=v_student and registration_status in ('pending','under_review');
      if not found then return jsonb_build_object('ok',false,'code','STAFF_REGISTRATION_NOT_FOUND'); end if;
      insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,request_id,details)
      values('person',v_actor::text,'staff.registration_rejected','school_staff_registration',v_student::text,v_request_id,jsonb_build_object('reason',left(p_payload->>'reason',500)));
      v_result := jsonb_build_object('ok',true,'code','REGISTRATION_REJECTED');
    end if;
    insert into public.school_registry_request_outcomes values(v_request_id,v_actor,v_action,v_result || jsonb_build_object('request_id',v_request_id),now()); return v_result || jsonb_build_object('request_id',v_request_id);
  end if;

  if v_action='calendar.transition' then
    if not wts_internal.school_registry_has_capability(v_ent,'academic_calendar.manage') then return jsonb_build_object('ok',false,'code','REGISTRY_CAPABILITY_DENIED'); end if;
    if coalesce((p_payload->>'confirmed')::boolean,false) is not true then return jsonb_build_object('ok',false,'code','ACADEMIC_TRANSITION_CONFIRMATION_REQUIRED'); end if;
    if coalesce(nullif(trim(p_payload->>'reason'),''),'') = '' then return jsonb_build_object('ok',false,'code','ACADEMIC_TRANSITION_REASON_REQUIRED'); end if;
    v_result := wts_internal.school_registry_transition_readiness(p_payload->>'sourceSession');
    if coalesce((v_result->>'ok')::boolean,false) is not true then return v_result; end if;
    v_result := public.school_academic_transition_apply(p_payload->>'sourceSession',p_payload->>'sourceTerm',p_payload->>'targetSession',p_payload->>'targetTerm',v_actor,p_payload->>'reason');
    insert into public.school_registry_request_outcomes values(v_request_id,v_actor,v_action,v_result || jsonb_build_object('request_id',v_request_id),now()); return v_result || jsonb_build_object('request_id',v_request_id);
  end if;

  if v_action='portfolio.assignment.set' then
    if not wts_internal.school_registry_has_capability(v_ent,'portfolio.manage') then return jsonb_build_object('ok',false,'code','REGISTRY_CAPABILITY_DENIED'); end if;
    if lower(trim(coalesce(p_payload->>'portfolioCode',''))) in ('developer','proprietor') and not wts_internal.school_registry_is_protected_actor(v_actor) then return jsonb_build_object('ok',false,'code','PROTECTED_PORTFOLIO_RESTRICTED'); end if;
    if not exists(select 1 from public.school_portfolio_catalog c where c.portfolio_code=trim(coalesce(p_payload->>'portfolioCode','')) and c.is_active) then return jsonb_build_object('ok',false,'code','PORTFOLIO_NOT_FOUND'); end if;
    if exists(select 1 from public.school_portfolio_catalog c where c.portfolio_code=trim(coalesce(p_payload->>'portfolioCode','')) and coalesce(c.metadata->>'visibility','school')='technical_only') then return jsonb_build_object('ok',false,'code','TECHNICAL_PRIVILEGE_NOT_ASSIGNABLE_AS_PORTFOLIO'); end if;
    if trim(coalesce(p_payload->>'portfolioCode',''))='student_executive_council' then return jsonb_build_object('ok',false,'code','PREFECT_WORKFLOW_REQUIRED'); end if;
    v_status := lower(trim(coalesce(p_payload->>'holderType','staff')));
    if v_status not in ('staff','student') then return jsonb_build_object('ok',false,'code','PORTFOLIO_HOLDER_TYPE_INVALID'); end if;
    v_reason := nullif(trim(coalesce(p_payload->>'reason','')),'');
    if v_reason is null or length(v_reason) < 8 then return jsonb_build_object('ok',false,'code','PORTFOLIO_REASON_REQUIRED'); end if;
    if v_status='staff' then
      begin v_staff_id := nullif(trim(coalesce(p_payload->>'staffId','')),'')::uuid; exception when others then return jsonb_build_object('ok',false,'code','PORTFOLIO_STAFF_ID_INVALID'); end;
      if v_staff_id is null or not exists(select 1 from public.staff_attendance_profiles s where s.id=v_staff_id and s.registration_status='active' and s.employment_status='active') then return jsonb_build_object('ok',false,'code','ACTIVE_STAFF_REQUIRED'); end if;
    else
      begin v_student := nullif(trim(coalesce(p_payload->>'studentId','')),'')::uuid; exception when others then return jsonb_build_object('ok',false,'code','PORTFOLIO_STUDENT_ID_INVALID'); end;
      if v_student is null or not exists(select 1 from public.students s where s.id=v_student and not s.archived) then return jsonb_build_object('ok',false,'code','ACTIVE_STUDENT_REQUIRED'); end if;
    end if;
    if nullif(trim(coalesce(p_payload->>'classKey','')),'') is not null and not exists(select 1 from public.school_classes c where c.class_key=trim(p_payload->>'classKey') and c.is_active) then return jsonb_build_object('ok',false,'code','ACTIVE_CLASS_NOT_FOUND'); end if;
    insert into public.school_portfolio_assignments(portfolio_code,holder_type,staff_id,student_id,academic_session,scope_type,stage_code,class_key,assigned_by_person_id,reason,metadata)
    values(trim(p_payload->>'portfolioCode'),v_status,v_staff_id,v_student,nullif(trim(p_payload->>'academicSession'),''),lower(coalesce(nullif(trim(p_payload->>'scopeType'),''),'school')),nullif(trim(p_payload->>'stageCode'),''),nullif(trim(p_payload->>'classKey'),''),v_actor,v_reason,jsonb_build_object('request_id',v_request_id))
    returning id into v_transition_id;
    insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,request_id,details)
    values('person',v_actor::text,'portfolio.assignment_created','school_portfolio_assignment',v_transition_id::text,v_request_id,jsonb_build_object('portfolio_code',trim(p_payload->>'portfolioCode'),'holder_type',v_status,'staff_id',v_staff_id,'student_id',v_student,'scope_type',lower(coalesce(nullif(trim(p_payload->>'scopeType'),''),'school'))));
    v_result := jsonb_build_object('ok',true,'code','PORTFOLIO_ASSIGNMENT_SAVED','request_id',v_request_id); insert into public.school_registry_request_outcomes values(v_request_id,v_actor,v_action,v_result,now()); return v_result;
  end if;

  if v_action='portfolio.assignment.end' then
    if not wts_internal.school_registry_has_capability(v_ent,'portfolio.manage') then return jsonb_build_object('ok',false,'code','REGISTRY_CAPABILITY_DENIED'); end if;
    begin v_transition_id := (p_payload->>'assignmentId')::uuid; exception when others then return jsonb_build_object('ok',false,'code','PORTFOLIO_ASSIGNMENT_ID_INVALID'); end;
    v_reason := nullif(trim(coalesce(p_payload->>'reason','')),'');
    if v_reason is null or length(v_reason)<8 then return jsonb_build_object('ok',false,'code','PORTFOLIO_REASON_REQUIRED'); end if;
    select a.* into v_row from public.school_portfolio_assignments a where a.id=v_transition_id and a.assignment_status='active' for update;
    if not found then return jsonb_build_object('ok',false,'code','PORTFOLIO_ASSIGNMENT_NOT_FOUND'); end if;
    if v_row.portfolio_code in ('developer','proprietor') and not wts_internal.school_registry_is_protected_actor(v_actor) then return jsonb_build_object('ok',false,'code','PROTECTED_PORTFOLIO_RESTRICTED'); end if;
    update public.school_portfolio_assignments
    set assignment_status='ended',effective_until=now(),
        metadata=metadata||jsonb_build_object('ended_by_person_id',v_actor,'end_reason',v_reason)
          ||case when portfolio_code='student_executive_council' then jsonb_build_object('appointment_status','ended') else '{}'::jsonb end,
        updated_at=now()
    where id=v_transition_id and assignment_status='active';
    if not found then return jsonb_build_object('ok',false,'code','PORTFOLIO_ASSIGNMENT_NOT_FOUND'); end if;
    insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,request_id,before_data,after_data,details)
    values('person',v_actor::text,'portfolio.assignment_ended','school_portfolio_assignment',v_transition_id::text,v_request_id,to_jsonb(v_row),(select to_jsonb(a) from public.school_portfolio_assignments a where a.id=v_transition_id),jsonb_build_object('reason',v_reason));
    v_result := jsonb_build_object('ok',true,'code','PORTFOLIO_ASSIGNMENT_ENDED','request_id',v_request_id); insert into public.school_registry_request_outcomes values(v_request_id,v_actor,v_action,v_result,now()); return v_result;
  end if;

  if v_action='prefect.bootstrap' then
    if not wts_internal.school_registry_has_capability(v_ent,'student.prefect.manage') then return jsonb_build_object('ok',false,'code','REGISTRY_CAPABILITY_DENIED'); end if;
    v_result := public.school_registry_prefect_bootstrap(v_actor,coalesce(p_payload->'assignments','[]'::jsonb));
    if coalesce((v_result->>'ok')::boolean,false) is true then
      insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,request_id,details)
      values('person',v_actor::text,'prefect.bootstrap_completed','school_prefect_bootstrap','true',v_request_id,v_result);
    end if;
    insert into public.school_registry_request_outcomes values(v_request_id,v_actor,v_action,v_result || jsonb_build_object('request_id',v_request_id),now()); return v_result || jsonb_build_object('request_id',v_request_id);
  end if;

  if v_action='prefect.open' then
    if not wts_internal.school_registry_has_capability(v_ent,'student.prefect.manage') then return jsonb_build_object('ok',false,'code','REGISTRY_CAPABILITY_DENIED'); end if;
    if public.school_academic_current()->>'term' <> '3rd Term' then return jsonb_build_object('ok',false,'code','PREFECT_THIRD_TERM_REQUIRED'); end if;
    if nullif(trim(coalesce(p_payload->>'academicSession','')),'') is null then return jsonb_build_object('ok',false,'code','PREFECT_ACADEMIC_SESSION_REQUIRED'); end if;
    if nullif(trim(coalesce(p_payload->>'targetSession','')),'') is null then return jsonb_build_object('ok',false,'code','PREFECT_TARGET_SESSION_REQUIRED'); end if;
    if trim(p_payload->>'academicSession') <> public.school_academic_current()->>'academic_session' then return jsonb_build_object('ok',false,'code','PREFECT_ACADEMIC_CONTEXT_MISMATCH'); end if;
    if public.school_academic_next_session(trim(p_payload->>'academicSession')) <> trim(p_payload->>'targetSession') then return jsonb_build_object('ok',false,'code','PREFECT_TARGET_SESSION_INVALID'); end if;
    insert into public.school_prefect_cycles(academic_session,source_term,target_session,opened_by_person_id,reason)
    values(p_payload->>'academicSession','3rd Term',coalesce(p_payload->>'targetSession',public.school_academic_next_session(p_payload->>'academicSession')),v_actor,coalesce(nullif(trim(p_payload->>'reason'),''),'Annual prefect selection'))
    on conflict (academic_session,target_session) do update set cycle_status='open',reason=excluded.reason,opened_by_person_id=excluded.opened_by_person_id,opened_at=now()
    returning id into v_student;
    insert into public.school_prefect_candidates(cycle_id,student_id)
    select v_student,s.id from public.students s where not s.archived and s.class_key in ('ss2-science','ss2-arts','ss2-business')
    on conflict do nothing;
    insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,request_id,details)
    values('person',v_actor::text,'prefect.cycle_opened','school_prefect_cycle',v_student::text,v_request_id,jsonb_build_object('academic_session',p_payload->>'academicSession','target_session',p_payload->>'targetSession'));
    v_result := jsonb_build_object('ok',true,'code','PREFECT_CYCLE_OPENED','cycleId',v_student,'request_id',v_request_id); insert into public.school_registry_request_outcomes values(v_request_id,v_actor,v_action,v_result,now()); return v_result;
  end if;

  if v_action='prefect.select' then
    if not wts_internal.school_registry_has_capability(v_ent,'student.prefect.manage') then return jsonb_build_object('ok',false,'code','REGISTRY_CAPABILITY_DENIED'); end if;
    begin v_student := (p_payload->>'studentId')::uuid; exception when others then return jsonb_build_object('ok',false,'code','PREFECT_STUDENT_INVALID'); end;
    if not exists(select 1 from public.students s where s.id=v_student and not s.archived and s.class_key in ('ss2-science','ss2-arts','ss2-business')) then return jsonb_build_object('ok',false,'code','PREFECT_CANDIDATE_NOT_SS2'); end if;
    begin v_transition_id := (p_payload->>'cycleId')::uuid; exception when others then return jsonb_build_object('ok',false,'code','PREFECT_CYCLE_INVALID'); end;
    if v_transition_id is null then return jsonb_build_object('ok',false,'code','PREFECT_CYCLE_REQUIRED'); end if;
    if coalesce((p_payload->>'selected')::boolean,true) and (nullif(trim(coalesce(p_payload->>'officeName','')),'') is null or length(trim(p_payload->>'officeName'))>120) then return jsonb_build_object('ok',false,'code','PREFECT_OFFICE_REQUIRED'); end if;
    if not exists(select 1 from public.school_prefect_cycles where id=v_transition_id and cycle_status in ('open','submitted')) then return jsonb_build_object('ok',false,'code','PREFECT_CYCLE_NOT_SELECTABLE'); end if;
    update public.school_prefect_candidates set candidate_status=case when coalesce((p_payload->>'selected')::boolean,true) then 'selected' else 'rejected' end,office_name=nullif(trim(p_payload->>'officeName'),''),notes=left(coalesce(p_payload->>'notes',''),500),selected_by_person_id=v_actor,selected_at=now() where cycle_id=v_transition_id and student_id=v_student;
    if not found then return jsonb_build_object('ok',false,'code','PREFECT_CANDIDATE_NOT_FOUND'); end if;
    insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,request_id,details)
    values('person',v_actor::text,'prefect.candidate_selected','school_prefect_candidate',v_student::text,v_request_id,jsonb_build_object('cycle_id',v_transition_id,'selected',coalesce((p_payload->>'selected')::boolean,true),'office_name',nullif(trim(p_payload->>'officeName'),'')));
    v_result := jsonb_build_object('ok',true,'code','PREFECT_CANDIDATE_UPDATED','request_id',v_request_id); insert into public.school_registry_request_outcomes values(v_request_id,v_actor,v_action,v_result,now()); return v_result;
  end if;

  if v_action='prefect.approve' then
    if not wts_internal.school_registry_has_capability(v_ent,'student.prefect.manage') then return jsonb_build_object('ok',false,'code','REGISTRY_CAPABILITY_DENIED'); end if;
    begin v_transition_id := (p_payload->>'cycleId')::uuid; exception when others then return jsonb_build_object('ok',false,'code','PREFECT_CYCLE_INVALID'); end;
    if v_transition_id is null then return jsonb_build_object('ok',false,'code','PREFECT_CYCLE_REQUIRED'); end if;
    if not exists(select 1 from public.school_prefect_cycles where id=v_transition_id and cycle_status in ('open','submitted')) then return jsonb_build_object('ok',false,'code','PREFECT_CYCLE_NOT_APPROVABLE'); end if;
    if not exists(select 1 from public.school_prefect_candidates where cycle_id=v_transition_id and candidate_status='selected') then return jsonb_build_object('ok',false,'code','PREFECT_SELECTED_CANDIDATES_REQUIRED'); end if;
    if exists(select 1 from public.school_prefect_candidates where cycle_id=v_transition_id and candidate_status='selected' and nullif(trim(coalesce(office_name,'')),'') is null) then return jsonb_build_object('ok',false,'code','PREFECT_OFFICES_REQUIRED'); end if;
    update public.school_prefect_candidates set candidate_status='approved',approved_by_person_id=v_actor,approved_at=now() where cycle_id=v_transition_id and candidate_status='selected';
    update public.school_prefect_cycles set cycle_status='approved',approved_by_person_id=v_actor,approved_at=now() where id=v_transition_id;
    insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,request_id)
    values('person',v_actor::text,'prefect.cycle_approved','school_prefect_cycle',v_transition_id::text,v_request_id);
    v_result := jsonb_build_object('ok',true,'code','PREFECT_CYCLE_APPROVED','request_id',v_request_id); insert into public.school_registry_request_outcomes values(v_request_id,v_actor,v_action,v_result,now()); return v_result;
  end if;

  if v_action='prefect.activate' then
    if not wts_internal.school_registry_has_capability(v_ent,'student.prefect.manage') then return jsonb_build_object('ok',false,'code','REGISTRY_CAPABILITY_DENIED'); end if;
    begin v_transition_id := (p_payload->>'transitionRunId')::uuid; exception when others then return jsonb_build_object('ok',false,'code','TRANSITION_ID_INVALID'); end;
    v_result := public.school_registry_prefect_activate(v_transition_id);
    if coalesce((v_result->>'ok')::boolean,false) is true then
      insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,request_id,details)
      values('person',v_actor::text,'prefect.assignments_activated','school_academic_transition_run',v_transition_id::text,v_request_id,v_result);
    end if;
    insert into public.school_registry_request_outcomes values(v_request_id,v_actor,v_action,v_result || jsonb_build_object('request_id',v_request_id),now()); return v_result || jsonb_build_object('request_id',v_request_id);
  end if;

  return jsonb_build_object('ok',false,'code','REGISTRY_ACTION_UNKNOWN');
exception when unique_violation then
  return jsonb_build_object('ok',false,'code','REGISTRY_CONFLICT');
when invalid_text_representation then
  return jsonb_build_object('ok',false,'code','REGISTRY_REQUEST_INVALID');
when others then
  return jsonb_build_object('ok',false,'code',case when sqlstate='P0001' then regexp_replace(sqlerrm,'[^A-Za-z0-9]+','_','g') else 'REGISTRY_WRITE_FAILED' end);
end;
$function$;

revoke all on function public.school_registry_write_v2(uuid,text,text,jsonb) from public, authenticated;
grant execute on function public.school_registry_write_v2(uuid,text,text,jsonb) to anon;
