-- Registry v2 session, read and policy APIs.

create or replace function public.school_registry_session_context_v2(
  p_session_id uuid,
  p_session_secret text
)
returns jsonb
language sql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
  select wts_internal.school_registry_session_entitlements(p_session_id, p_session_secret)
$function$;

revoke all on function public.school_registry_session_context_v2(uuid,text) from public, authenticated;
grant execute on function public.school_registry_session_context_v2(uuid,text) to anon;

create or replace function wts_internal.school_registry_has_capability(p_entitlements jsonb, p_capability text)
returns boolean
language sql
immutable
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
  select exists (
    select 1 from jsonb_array_elements_text(coalesce(p_entitlements -> 'capabilities','[]'::jsonb)) c
    where c = p_capability or c = '*'
  )
$function$;

revoke all on function wts_internal.school_registry_has_capability(jsonb,text) from public, anon, authenticated;

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
  v_search text := left(trim(coalesce(p_payload ->> 'search','')), 120);
  v_class text := nullif(trim(coalesce(p_payload ->> 'classKey','')), '');
  v_status text := lower(trim(coalesce(p_payload ->> 'status','active')));
  v_student_id uuid;
  v_person_id uuid;
  v_current jsonb;
  v_stage jsonb;
  v_result jsonb;
begin
  v_auth := wts_internal.school_registry_session_entitlements(p_session_id, p_session_secret);
  if coalesce((v_auth ->> 'ok')::boolean,false) is not true then return v_auth; end if;
  v_ent := coalesce(v_auth -> 'entitlements','{}'::jsonb);
  v_person_id := nullif(v_auth -> 'actor' ->> 'personId','')::uuid;

  if v_action = 'dashboard' then
    if not (wts_internal.school_registry_has_capability(v_ent,'students.school.read')
      or wts_internal.school_registry_has_capability(v_ent,'students.stage.read')
      or wts_internal.school_registry_has_capability(v_ent,'students.class.read')) then
      return jsonb_build_object('ok',true,'mode','profile','cards','[]'::jsonb,'message','You are not currently assigned a student scope.','guardianReadiness',jsonb_build_object('activeStudents',0,'withPrimaryGuardian',0,'withPhone',0,'withWhatsApp',0,'withConsent',0,'invalidContacts',0));
    end if;
    with allowed as (
      select s.id,s.gender,s.class_key,s.archived,c.stage_code
      from public.students s left join public.school_classes c on c.class_key=s.class_key
      where (wts_internal.school_registry_has_capability(v_ent,'students.school.read')
        or (wts_internal.school_registry_has_capability(v_ent,'students.stage.read') and exists (select 1 from jsonb_array_elements_text(coalesce(v_ent->'stageScopes','[]'::jsonb)) x where x.value=c.stage_code))
        or (wts_internal.school_registry_has_capability(v_ent,'students.class.read') and s.class_key in (select value from jsonb_array_elements_text(coalesce(v_ent->'classScopes','[]'::jsonb)))))
    )
    select jsonb_build_object(
      'ok',true,'mode','students',
      'cards',jsonb_build_array(
        jsonb_build_object('key','active','label','Active students','value',count(*) filter (where not archived)),
        jsonb_build_object('key','archived','label','Archived students','value',count(*) filter (where archived)),
        jsonb_build_object('key','female','label','Female','value',count(*) filter (where not archived and lower(coalesce(gender,''))='female')),
        jsonb_build_object('key','male','label','Male','value',count(*) filter (where not archived and lower(coalesce(gender,''))='male')),
        jsonb_build_object('key','early_childhood','label','Early childhood','value',count(*) filter (where not archived and stage_code='early_childhood')),
        jsonb_build_object('key','primary','label','Primary','value',count(*) filter (where not archived and stage_code='primary')),
        jsonb_build_object('key','secondary','label','Secondary','value',count(*) filter (where not archived and stage_code='secondary'))
      ),
      'classCards',(select coalesce(jsonb_agg(jsonb_build_object('classKey',x.class_key,'label',x.display_name,'total',x.total,'female',x.female,'male',x.male) order by x.sort_order,x.display_name),'[]'::jsonb) from (select c.class_key,c.display_name,c.sort_order,count(a.id) filter (where not a.archived) total,count(a.id) filter (where not a.archived and lower(coalesce(a.gender,''))='female') female,count(a.id) filter (where not a.archived and lower(coalesce(a.gender,''))='male') male from public.school_classes c join allowed a on a.class_key=c.class_key where c.is_active group by c.class_key,c.display_name,c.sort_order) x),
      'guardianReadiness',jsonb_build_object(
        'activeStudents',(select count(*) from allowed where not archived),
        'withPrimaryGuardian',(select count(*) from allowed a where not a.archived and exists(select 1 from public.school_student_guardians g where g.student_id=a.id and g.status='active' and g.is_primary)),
        'withPhone',(select count(*) from allowed a join public.school_student_guardians g on g.student_id=a.id and g.status='active' join public.school_guardians gd on gd.id=g.guardian_id where not a.archived and nullif(trim(coalesce(gd.primary_phone,'')),'') is not null),
        'withWhatsApp',(select count(*) from allowed a join public.school_student_guardians g on g.student_id=a.id and g.status='active' join public.school_guardians gd on gd.id=g.guardian_id where not a.archived and nullif(trim(coalesce(gd.whatsapp_phone,'')),'') is not null),
        'withConsent',(select count(*) from allowed a join public.school_student_guardians g on g.student_id=a.id and g.status='active' where not a.archived and g.notification_consent),
        'invalidContacts',(select count(*) from allowed a join public.school_student_guardians g on g.student_id=a.id and g.status='active' join public.school_guardians gd on gd.id=g.guardian_id where not a.archived and (nullif(trim(coalesce(gd.primary_phone,'')),'') is null and nullif(trim(coalesce(gd.whatsapp_phone,'')),'') is null))
      )
    ) into v_result from allowed;
    return v_result;
  end if;

  if v_action in ('students','student') then
    if v_action = 'student' then
      begin v_student_id := (p_payload ->> 'studentId')::uuid; exception when others then return jsonb_build_object('ok',false,'code','INVALID_STUDENT_ID'); end;
    end if;
    if not (wts_internal.school_registry_has_capability(v_ent,'students.school.read') or wts_internal.school_registry_has_capability(v_ent,'students.stage.read') or wts_internal.school_registry_has_capability(v_ent,'students.class.read')) then
      return jsonb_build_object('ok',false,'code','REGISTRY_SCOPE_DENIED');
    end if;
    select coalesce(jsonb_agg(to_jsonb(x) order by x.name), '[]'::jsonb) into v_result
    from (
      select s.id,s.central_person_id,s.name,s.gender,s.admno,s.class_key,c.display_name class_label,c.stage_code,s.archived,s.lifecycle_status,s.admission_date,s.photo,
        (select count(*) from public.school_student_guardians g where g.student_id=s.id and g.status='active') guardian_count
      from public.students s left join public.school_classes c on c.class_key=s.class_key
      where (v_action='students' or s.id=v_student_id)
        and (v_action='student' or v_status='' or (v_status='active' and not s.archived) or (v_status='archived' and s.archived) or s.lifecycle_status=v_status)
        and (v_class is null or s.class_key=v_class)
        and (v_search='' or s.name ilike '%'||v_search||'%' or coalesce(s.admno,'') ilike '%'||v_search||'%')
        and (wts_internal.school_registry_has_capability(v_ent,'students.school.read')
          or (wts_internal.school_registry_has_capability(v_ent,'students.stage.read') and exists (select 1 from jsonb_array_elements_text(coalesce(v_ent->'stageScopes','[]'::jsonb)) x where x.value=c.stage_code))
          or (wts_internal.school_registry_has_capability(v_ent,'students.class.read') and s.class_key in (select value from jsonb_array_elements_text(coalesce(v_ent->'classScopes','[]'::jsonb)))))
      order by s.name limit case when v_action='student' then 1 else 200 end
    ) x;
    return jsonb_build_object('ok',true,'students',v_result);
  end if;

  if v_action='guardians' then
    begin v_student_id := (p_payload ->> 'studentId')::uuid; exception when others then return jsonb_build_object('ok',false,'code','INVALID_STUDENT_ID'); end;
    select s.class_key into v_class from public.students s where s.id=v_student_id;
    if v_class is null then return jsonb_build_object('ok',false,'code','STUDENT_NOT_FOUND'); end if;
    if not (wts_internal.school_registry_has_capability(v_ent,'students.school.read')
      or (wts_internal.school_registry_has_capability(v_ent,'students.stage.read') and exists(select 1 from public.school_classes c where c.class_key=v_class and c.stage_code in (select value from jsonb_array_elements_text(coalesce(v_ent->'stageScopes','[]'::jsonb)))))
      or (wts_internal.school_registry_has_capability(v_ent,'students.class.read') and v_class in (select value from jsonb_array_elements_text(coalesce(v_ent->'classScopes','[]'::jsonb))))) then
      return jsonb_build_object('ok',false,'code','REGISTRY_SCOPE_DENIED');
    end if;
    return jsonb_build_object('ok',true,'guardians',(select coalesce(jsonb_agg(jsonb_build_object(
      'relationshipId',sg.id,'guardianId',g.id,'fullName',g.full_name,'primaryPhone',g.primary_phone,
      'whatsappPhone',g.whatsapp_phone,'email',g.email,'relationship',sg.relationship,
      'isPrimary',sg.is_primary,'isLegalGuardian',sg.is_legal_guardian,
      'notificationConsent',sg.notification_consent,'preferredLanguage',sg.preferred_language,
      'status',sg.status
    ) order by sg.is_primary desc,g.full_name),'[]'::jsonb)
      from public.school_student_guardians sg join public.school_guardians g on g.id=sg.guardian_id
      where sg.student_id=v_student_id));
  end if;

  if v_action in ('staff','staff_self') then
    if v_action='staff_self' or not (wts_internal.school_registry_has_capability(v_ent,'staff.school.read') or wts_internal.school_registry_has_capability(v_ent,'staff.stage.read')) then
      select coalesce(jsonb_agg(to_jsonb(x)),'[]'::jsonb) into v_result from (select s.id staff_id,s.central_person_id,s.staff_number,s.full_name,s.email,s.phone,s.whatsapp_number,s.address,s.emergency_contact,case when lower(coalesce(s.designation,'')) ~ '(super[ _-]*administrator|system[ _-]*owner|developer)' then null else s.designation end designation,s.department,s.staff_category,s.employment_status,s.registration_status,s.photo,s.signature_path from public.staff_attendance_profiles s where s.central_person_id=v_person_id) x;
      return jsonb_build_object('ok',true,'staff',v_result,'selfOnly',true);
    end if;
    select coalesce(jsonb_agg(to_jsonb(x) order by x.full_name),'[]'::jsonb) into v_result
    from (select s.id staff_id,s.central_person_id,s.staff_number,s.full_name,s.email,s.phone,case when lower(coalesce(s.designation,'')) ~ '(super[ _-]*administrator|system[ _-]*owner|developer)' then null else s.designation end designation,s.department,s.staff_category,s.employment_status,s.registration_status,s.photo
      from public.staff_attendance_profiles s
      where s.registration_status='active' and s.employment_status='active'
      and (wts_internal.school_registry_has_capability(v_ent,'staff.school.read') or s.central_person_id=v_person_id or exists (select 1 from public.school_staff_class_allocations a join public.school_classes c on c.class_key=a.class_key where a.person_id=s.central_person_id and a.allocation_status='active' and c.stage_code in (select value from jsonb_array_elements_text(coalesce(v_ent->'stageScopes','[]'::jsonb)))) or exists (select 1 from public.school_portfolio_assignments pa where pa.holder_type='staff' and pa.staff_id=s.id and pa.assignment_status='active' and pa.scope_type='stage' and pa.stage_code in (select value from jsonb_array_elements_text(coalesce(v_ent->'stageScopes','[]'::jsonb)))))
      and (v_search='' or s.full_name ilike '%'||v_search||'%' or coalesce(s.staff_number,'') ilike '%'||v_search||'%' or coalesce(s.email,'') ilike '%'||v_search||'%')
      and (v_status='' or s.employment_status=v_status or s.registration_status=v_status) order by s.full_name limit 1000) x;
    return jsonb_build_object(
      'ok',true,'staff',v_result,'selfOnly',false,
      'self',(select to_jsonb(x) from (
        select s.id staff_id,s.central_person_id,s.staff_number,s.full_name,s.email,s.phone,
          s.whatsapp_number,s.address,s.emergency_contact,case when lower(coalesce(s.designation,'')) ~ '(super[ _-]*administrator|system[ _-]*owner|developer)' then null else s.designation end designation,s.department,
          s.staff_category,s.employment_status,s.registration_status,s.photo,s.signature_path
        from public.staff_attendance_profiles s where s.central_person_id=v_person_id
        order by s.created_at limit 1
      ) x)
    );
  end if;

  if v_action='registrations' then
    if not (wts_internal.school_registry_has_capability(v_ent,'staff.school.read') or wts_internal.school_registry_has_capability(v_ent,'portfolio.manage')) then return jsonb_build_object('ok',false,'code','REGISTRY_CAPABILITY_DENIED'); end if;
    return jsonb_build_object('ok',true,'registrations',(select coalesce(jsonb_agg(jsonb_build_object(
      'id',r.id,'full_name',r.full_name,'email',r.email,'phone',r.phone,
      'whatsapp_number',r.whatsapp_number,'address',r.address,
      'emergency_contact_supplied',r.emergency_contact is not null,
      'has_photo',r.photo_data is not null,'registration_status',r.registration_status,
      'submitted_at',r.submitted_at,'reviewed_at',r.reviewed_at,
      'rejection_reason',r.rejection_reason,'approved_staff_id',r.approved_staff_id
    ) order by r.created_at desc),'[]'::jsonb) from public.school_staff_registrations r where (nullif(trim(coalesce(p_payload->>'status','')),'') is null or r.registration_status=trim(p_payload->>'status'))));
  end if;

  if v_action='catalog' then
    if not wts_internal.school_registry_has_capability(v_ent,'allocations.read') then return jsonb_build_object('ok',false,'code','REGISTRY_CAPABILITY_DENIED'); end if;
    return jsonb_build_object(
      'ok',true,
      'classes',(select coalesce(jsonb_agg(to_jsonb(c) order by c.sort_order,c.display_name),'[]'::jsonb)
        from public.school_classes c
        where c.is_active and lower(c.class_key) not like 'archive-%'
          and (
            wts_internal.school_registry_has_capability(v_ent,'allocations.school.manage')
            or wts_internal.school_registry_has_capability(v_ent,'students.school.read')
            or (wts_internal.school_registry_has_capability(v_ent,'students.stage.read') and exists (
              select 1 from jsonb_array_elements_text(coalesce(v_ent->'stageScopes','[]'::jsonb)) x where x.value=c.stage_code
            ))
            or c.class_key in (select value from jsonb_array_elements_text(coalesce(v_ent->'classScopes','[]'::jsonb)))
            or exists (
              select 1 from public.school_staff_class_allocations ca
              where ca.person_id=v_person_id and ca.class_key=c.class_key and ca.allocation_status='active'
            )
            or exists (
              select 1 from public.school_staff_subject_allocations sa
              where sa.person_id=v_person_id and sa.class_key=c.class_key and sa.allocation_status='active'
            )
          )),
      'subjects',(select coalesce(jsonb_agg(to_jsonb(s) order by s.class_key,s.subject_index),'[]'::jsonb)
        from public.result_subject_catalog s
        where s.active
          and (
            wts_internal.school_registry_has_capability(v_ent,'allocations.school.manage')
            or wts_internal.school_registry_has_capability(v_ent,'students.school.read')
            or s.class_key in (select value from jsonb_array_elements_text(coalesce(v_ent->'classScopes','[]'::jsonb)))
            or exists (
              select 1 from jsonb_array_elements_text(coalesce(v_ent->'stageScopes','[]'::jsonb)) x
              join public.school_classes c on c.class_key=s.class_key and c.stage_code=x.value
            )
            or exists (
              select 1 from public.school_staff_subject_allocations sa
              where sa.person_id=v_person_id and sa.class_key=s.class_key and sa.subject_index=s.subject_index and sa.allocation_status='active'
            )
          )),
      'staff',(select coalesce(jsonb_agg(jsonb_build_object('id',s.id,'staff_id',s.id,'central_person_id',s.central_person_id,'staff_number',s.staff_number,'full_name',s.full_name,'designation',case when lower(coalesce(s.designation,'')) ~ '(super[ _-]*administrator|system[ _-]*owner|developer)' then null else s.designation end,'staff_category',s.staff_category) order by s.full_name),'[]'::jsonb) from public.staff_attendance_profiles s where s.registration_status='active' and s.employment_status='active' and (wts_internal.school_registry_has_capability(v_ent,'allocations.school.manage') or exists (select 1 from public.school_portfolio_assignments pa where pa.holder_type='staff' and pa.staff_id=s.id and pa.assignment_status='active' and pa.scope_type='stage' and pa.stage_code in (select value from jsonb_array_elements_text(coalesce(v_ent->'stageScopes','[]'::jsonb)))) or exists (select 1 from public.school_staff_class_allocations ca join public.school_classes cc on cc.class_key=ca.class_key where ca.person_id=s.central_person_id and ca.allocation_status='active' and cc.stage_code in (select value from jsonb_array_elements_text(coalesce(v_ent->'stageScopes','[]'::jsonb)))) or s.central_person_id=v_person_id)),
      'current',public.school_academic_current()
    );
  end if;

  if v_action='allocations' then
    if not wts_internal.school_registry_has_capability(v_ent,'allocations.read') then return jsonb_build_object('ok',false,'code','REGISTRY_CAPABILITY_DENIED'); end if;
    v_current := public.school_academic_current();
    return jsonb_build_object(
      'ok',true,
      'classAllocations',(select coalesce(jsonb_agg(jsonb_build_object('id',a.id,'staff_id',a.staff_id,'person_id',a.person_id,'academic_session',a.academic_session,'term_name',a.term_name,'class_key',a.class_key,'class_name',c.display_name,'responsibility',a.responsibility,'allocation_status',a.allocation_status,'effective_from',a.effective_from,'effective_until',a.effective_until,'staff_number',s.staff_number,'full_name',s.full_name,'reason',a.reason,'created_at',a.created_at) order by a.class_key,a.responsibility,a.created_at desc),'[]'::jsonb) from public.school_staff_class_allocations a join public.staff_attendance_profiles s on s.id=a.staff_id left join public.school_classes c on c.class_key=a.class_key where a.academic_session=v_current->>'academic_session' and a.term_name=v_current->>'term' and a.allocation_status='active' and (wts_internal.school_registry_has_capability(v_ent,'allocations.school.manage') or a.person_id=v_person_id or a.class_key in (select value from jsonb_array_elements_text(coalesce(v_ent->'classScopes','[]'::jsonb))) or exists (select 1 from jsonb_array_elements_text(coalesce(v_ent->'stageScopes','[]'::jsonb)) x where x.value=c.stage_code))),
      'subjectAllocations',(select coalesce(jsonb_agg(jsonb_build_object('id',a.id,'staff_id',a.staff_id,'person_id',a.person_id,'academic_session',a.academic_session,'term_name',a.term_name,'class_key',a.class_key,'class_name',c.display_name,'subject_index',a.subject_index,'subject_name',r.subject_name,'allocation_status',a.allocation_status,'effective_from',a.effective_from,'effective_until',a.effective_until,'staff_number',s.staff_number,'full_name',s.full_name,'reason',a.reason,'created_at',a.created_at) order by a.class_key,a.subject_index),'[]'::jsonb) from public.school_staff_subject_allocations a join public.staff_attendance_profiles s on s.id=a.staff_id left join public.school_classes c on c.class_key=a.class_key left join public.result_subject_catalog r on r.class_key=a.class_key and r.subject_index=a.subject_index where a.academic_session=v_current->>'academic_session' and a.term_name=v_current->>'term' and a.allocation_status='active' and (wts_internal.school_registry_has_capability(v_ent,'allocations.school.manage') or a.person_id=v_person_id or a.class_key in (select value from jsonb_array_elements_text(coalesce(v_ent->'classScopes','[]'::jsonb))) or exists (select 1 from jsonb_array_elements_text(coalesce(v_ent->'stageScopes','[]'::jsonb)) x where x.value=c.stage_code))),
      'classAllocationHistory',(select coalesce(jsonb_agg(jsonb_build_object('id',a.id,'staff_id',a.staff_id,'person_id',a.person_id,'academic_session',a.academic_session,'term_name',a.term_name,'class_key',a.class_key,'class_name',c.display_name,'responsibility',a.responsibility,'allocation_status',a.allocation_status,'effective_from',a.effective_from,'effective_until',a.effective_until,'staff_number',s.staff_number,'full_name',s.full_name,'reason',a.reason,'created_at',a.created_at) order by a.academic_session desc,a.term_name desc,a.created_at desc),'[]'::jsonb) from public.school_staff_class_allocations a join public.staff_attendance_profiles s on s.id=a.staff_id left join public.school_classes c on c.class_key=a.class_key where wts_internal.school_registry_has_capability(v_ent,'allocations.school.manage') or a.person_id=v_person_id or exists (select 1 from jsonb_array_elements_text(coalesce(v_ent->'stageScopes','[]'::jsonb)) x where x.value=c.stage_code)),
      'subjectAllocationHistory',(select coalesce(jsonb_agg(jsonb_build_object('id',a.id,'staff_id',a.staff_id,'person_id',a.person_id,'academic_session',a.academic_session,'term_name',a.term_name,'class_key',a.class_key,'class_name',c.display_name,'subject_index',a.subject_index,'subject_name',r.subject_name,'allocation_status',a.allocation_status,'effective_from',a.effective_from,'effective_until',a.effective_until,'staff_number',s.staff_number,'full_name',s.full_name,'reason',a.reason,'created_at',a.created_at) order by a.academic_session desc,a.term_name desc,a.created_at desc),'[]'::jsonb) from public.school_staff_subject_allocations a join public.staff_attendance_profiles s on s.id=a.staff_id left join public.school_classes c on c.class_key=a.class_key left join public.result_subject_catalog r on r.class_key=a.class_key and r.subject_index=a.subject_index where wts_internal.school_registry_has_capability(v_ent,'allocations.school.manage') or a.person_id=v_person_id or exists (select 1 from jsonb_array_elements_text(coalesce(v_ent->'stageScopes','[]'::jsonb)) x where x.value=c.stage_code)),
      'current',v_current
    );
  end if;

  if v_action='calendar' then
    if not wts_internal.school_registry_has_capability(v_ent,'academic_calendar.read') then return jsonb_build_object('ok',false,'code','REGISTRY_CAPABILITY_DENIED'); end if;
    return jsonb_build_object('ok',true,'current',public.school_academic_current(),'sessions',(select coalesce(jsonb_agg(to_jsonb(s) order by s.session_name desc),'[]'::jsonb) from public.school_academic_sessions s),'terms',(select coalesce(jsonb_agg(to_jsonb(t) order by t.academic_session desc,t.term_name),'[]'::jsonb) from public.school_academic_terms t),'transitions',(select coalesce(jsonb_agg(to_jsonb(r) order by r.created_at desc),'[]'::jsonb) from (select * from public.school_academic_transition_runs order by created_at desc limit 20) r),'canManage',wts_internal.school_registry_has_capability(v_ent,'academic_calendar.manage'),'configurationWarnings',wts_internal.school_registry_configuration_warnings());
  end if;

  if v_action='prefect' then
    if not wts_internal.school_registry_has_capability(v_ent,'student.prefect.manage') and not wts_internal.school_registry_has_capability(v_ent,'portfolio.self.read') then return jsonb_build_object('ok',false,'code','REGISTRY_CAPABILITY_DENIED'); end if;
    return jsonb_build_object('ok',true,'bootstrap',(select to_jsonb(b) from public.school_prefect_bootstrap b where b.id=true),'cycles',(select coalesce(jsonb_agg(to_jsonb(c) order by c.opened_at desc),'[]'::jsonb) from public.school_prefect_cycles c),'candidates',(select coalesce(jsonb_agg(to_jsonb(c)||jsonb_build_object('student_name',s.name,'student_number',s.admno,'class_key',s.class_key) order by c.created_at desc),'[]'::jsonb) from public.school_prefect_candidates c join public.school_prefect_cycles cy on cy.id=c.cycle_id join public.students s on s.id=c.student_id where wts_internal.school_registry_has_capability(v_ent,'student.prefect.manage') or exists(select 1 from public.school_portfolio_assignments a where a.student_id=c.student_id and a.holder_person_id=v_person_id and a.assignment_status='active')),'canManage',wts_internal.school_registry_has_capability(v_ent,'student.prefect.manage'),'canBootstrap',wts_internal.school_registry_is_protected_actor(v_person_id));
  end if;

  if v_action='portfolio' then
    if wts_internal.school_registry_has_capability(v_ent,'portfolio.manage') then
      return jsonb_build_object('ok',true,'catalog',(select coalesce(jsonb_agg(to_jsonb(c) order by c.sort_order),'[]'::jsonb) from public.school_portfolio_catalog c where c.is_active and coalesce(c.metadata->>'visibility','school')<>'technical_only' and c.portfolio_code<>'student_executive_council'),'assignments',(select coalesce(jsonb_agg(to_jsonb(a) order by a.created_at desc),'[]'::jsonb) from public.school_portfolio_assignments a join public.school_portfolio_catalog c on c.portfolio_code=a.portfolio_code where coalesce(c.metadata->>'visibility','school')<>'technical_only'));
    end if;
    return jsonb_build_object('ok',true,'catalog',(select coalesce(jsonb_agg(to_jsonb(c) order by c.sort_order),'[]'::jsonb) from public.school_portfolio_catalog c where c.is_active and coalesce(c.metadata->>'visibility','school')<>'technical_only' and c.portfolio_code<>'student_executive_council'),'assignments',(select coalesce(jsonb_agg(to_jsonb(a) order by a.created_at desc),'[]'::jsonb) from public.school_portfolio_assignments a join public.school_portfolio_catalog c on c.portfolio_code=a.portfolio_code where a.holder_person_id=v_person_id and coalesce(c.metadata->>'visibility','school')<>'technical_only'));
  end if;

  if v_action='portal_access' then
    if not wts_internal.school_registry_has_capability(v_ent,'portal_access.manage') then return jsonb_build_object('ok',false,'code','REGISTRY_CAPABILITY_DENIED'); end if;
    return jsonb_build_object(
      'ok',true,
      'catalog',(select coalesce(jsonb_agg(to_jsonb(c)||jsonb_build_object('operating_mode',coalesce(o.operating_mode,'disabled'),'operating_reason',o.reason) order by c.app_code),'[]'::jsonb) from public.school_portal_catalog c left join public.school_module_operating_controls o on o.app_code=c.app_code where c.is_active and (c.app_code in ('central_registry','results','staff_self_service') or (c.app_code='attendance' and wts_internal.school_registry_is_technical_actor(v_person_id)))),
      'staff',(select coalesce(jsonb_agg(jsonb_build_object('id',s.id,'central_person_id',s.central_person_id,'staff_number',s.staff_number,'full_name',s.full_name,'designation',case when lower(coalesce(s.designation,'')) ~ '(super[ _-]*administrator|system[ _-]*owner|developer)' then null else s.designation end,'technical_pilot_user',wts_internal.school_registry_is_technical_actor(s.central_person_id)) order by s.full_name),'[]'::jsonb) from public.staff_attendance_profiles s where s.registration_status='active' and s.employment_status='active' and (v_search='' or s.full_name ilike '%'||v_search||'%' or coalesce(s.staff_number,'') ilike '%'||v_search||'%' or coalesce(s.email,'') ilike '%'||v_search||'%' or s.central_person_id = nullif(p_payload->>'personId','')::uuid)),
      'grants',(select coalesce(jsonb_agg(to_jsonb(g) order by g.app_code),'[]'::jsonb) from public.school_access_grants g where g.person_id = nullif(p_payload->>'personId','')::uuid),
      'resultsOperatingControl',(select to_jsonb(o) from public.school_module_operating_controls o where o.app_code='results'),
      'canManageOperatingControls',wts_internal.school_registry_is_technical_actor(v_person_id) and wts_internal.school_registry_has_capability(v_ent,'portal.operating_mode.manage')
    );
  end if;

  return jsonb_build_object('ok',false,'code','REGISTRY_ACTION_UNKNOWN');
exception when invalid_text_representation then
  return jsonb_build_object('ok',false,'code','REGISTRY_REQUEST_INVALID');
end;
$function$;

revoke all on function public.school_registry_read_v2(uuid,text,text,jsonb) from public, authenticated;
grant execute on function public.school_registry_read_v2(uuid,text,text,jsonb) to anon;

create or replace function public.school_registry_login_v2(p_login text, p_password text)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_credential public.school_identity_credentials%rowtype;
  v_account public.school_identity_accounts%rowtype;
  v_person public.school_people%rowtype;
  v_staff public.staff_attendance_profiles%rowtype;
  v_secret text;
  v_session_id uuid;
begin
  if nullif(trim(coalesce(p_login,'')),'') is null or coalesce(p_password,'') = '' then return jsonb_build_object('ok',false,'code','LOGIN_AND_PASSWORD_REQUIRED'); end if;
  select c.* into v_credential
  from public.school_identity_credentials c
  join public.school_identity_accounts i on i.id=c.identity_account_id
  left join public.staff_attendance_profiles s on s.central_person_id=c.person_id
  where lower(c.login_name)=lower(trim(p_login)) or lower(coalesce(i.login_email,''))=lower(trim(p_login)) or lower(coalesce(s.email,''))=lower(trim(p_login))
  order by case when lower(c.login_name)=lower(trim(p_login)) then 0 else 1 end
  limit 1 for update of c;
  if not found then return jsonb_build_object('ok',false,'code','INVALID_LOGIN'); end if;
  select * into v_account from public.school_identity_accounts where id=v_credential.identity_account_id;
  select * into v_person from public.school_people where id=v_credential.person_id;
  select * into v_staff from public.staff_attendance_profiles where central_person_id=v_credential.person_id order by created_at limit 1;
  if v_credential.credential_status <> 'active' or v_account.account_status <> 'active' or v_person.person_status <> 'active' or v_staff.id is null or v_staff.registration_status <> 'active' or v_staff.employment_status <> 'active' then return jsonb_build_object('ok',false,'code','REGISTRY_IDENTITY_NOT_ACTIVE'); end if;
  if v_credential.locked_until is not null and v_credential.locked_until > now() then return jsonb_build_object('ok',false,'code','ACCOUNT_TEMPORARILY_LOCKED','locked_until',v_credential.locked_until); end if;
  if v_credential.password_hash is null or crypt(p_password,v_credential.password_hash) <> v_credential.password_hash then
    update public.school_identity_credentials set failed_attempts=failed_attempts+1,locked_until=case when failed_attempts+1>=5 then now()+interval '15 minutes' else locked_until end,updated_at=now() where id=v_credential.id;
    return jsonb_build_object('ok',false,'code','INVALID_LOGIN');
  end if;
  v_secret := encode(gen_random_bytes(32),'base64');
  insert into public.school_identity_sessions(person_id,identity_account_id,originating_app_code,target_app_code,secret_hash,created_at,expires_at,last_seen_at,metadata)
  values(v_person.id,v_account.id,'central_registry','central_registry',encode(digest(v_secret,'sha256'),'hex'),now(),now()+interval '8 hours',now(),jsonb_build_object('source','registry_v2_login')) returning id into v_session_id;
  update public.school_identity_credentials set failed_attempts=0,locked_until=null,last_login_at=now(),updated_at=now() where id=v_credential.id;
  update public.school_identity_accounts set last_login_at=now(),updated_at=now() where id=v_account.id;
  insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,details)
  values('staff_session',v_person.id::text,'identity.registry_v2.login','school_identity_sessions',v_session_id::text,jsonb_build_object('staff_id',v_staff.id));
  return jsonb_build_object('ok',true,'code','REGISTRY_SESSION_ISSUED','session_id',v_session_id,'session_secret',v_secret,'expires_at',now()+interval '8 hours','person_id',v_person.id,'identity_account_id',v_account.id,'must_change_password',v_credential.must_change_password);
end;
$function$;

revoke all on function public.school_registry_login_v2(text,text) from public, authenticated;
grant execute on function public.school_registry_login_v2(text,text) to anon;
