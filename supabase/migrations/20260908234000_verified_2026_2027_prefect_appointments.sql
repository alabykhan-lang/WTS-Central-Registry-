-- Verified official notice: Newly Appointed School Prefects, 2026/2027
-- Academic Session, dated 15 June 2026. Permanent numbers and canonical
-- Registry names are used for deterministic matching; spelling printed on
-- the notice is retained in metadata. Multiple offices are separate history
-- records. No student record or class placement is changed by this migration.

create temporary table verified_prefect_notice (
  notice_row integer not null,
  permanent_number text not null,
  official_name text not null,
  canonical_name text not null,
  office_name text not null,
  primary key (notice_row, permanent_number, office_name)
) on commit drop;

insert into verified_prefect_notice(notice_row,permanent_number,official_name,canonical_name,office_name) values
  (1,'WTS/STU/000554','Alabi Amirat','Alabi Ameerah','Ameerah'),
  (2,'WTS/STU/000210','Afeez Amirat','ABDUL AFEEZ AMEERAT','Assistant Ameerah'),
  (3,'WTS/STU/000647','Adigun Kamaldeen','Adigun Kamaldeen','Ameer'),
  (4,'WTS/STU/000205','Ibraheem Yusuf','IBRAHIM YUSUF','Assistant Ameer'),
  (5,'WTS/STU/000566','Usman Toheebat','Uthman Toheebat','Social Prefect Girl'),
  (6,'WTS/STU/000563','Adeyemi Hafsoh','Adeyemi Hafsoh','Assistant Social Prefect Girl'),
  (7,'WTS/STU/000650','Adigun Bazim','Adigun Basim','Social Prefect Boy'),
  (8,'WTS/STU/000651','Adigun Jamiu','Adigun Jamiu','Assistant Social Prefect Boy'),
  (9,'WTS/STU/000550','Oyeturo Victor','Oyetoro Victor','Health Prefect Boy'),
  (10,'WTS/STU/000655','Yunusa Sobur','Yunusa Sobur','Assistant Health Prefect Boy'),
  (11,'WTS/STU/000646','Adeyemi Khadiyah','Adeyemi Khadeejah','Health Prefect Girl'),
  (12,'WTS/STU/000557','Adebowale Muizat','Adebowale Muizat','Assistant Health Prefect Girl'),
  (13,'WTS/STU/000568','Ojedapo Atiyat','Ojedapo Aliyat','Laboratory Prefect Girl'),
  (14,'WTS/STU/000550','Oyeturo Victor','Oyetoro Victor','Laboratory Prefect Boy'),
  (15,'WTS/STU/000557','Adebowale Muizat','Adebowale Muizat','Games Prefect Girl'),
  (16,'WTS/STU/000653','Isiaq Uthman','Ishaq Uthman','Games Prefect Boy'),
  (17,'WTS/STU/000559','Bakare Fatihat','Bakare Fathiat','Laboratory Prefect Girl'),
  (17,'WTS/STU/000556','Adam Kashfat','Adam Kashfat','Laboratory Prefect Girl'),
  (17,'WTS/STU/000554','Alabi Amirat','Alabi Ameerah','Laboratory Prefect Girl'),
  (18,'WTS/STU/000553','Isiaq Fathullah','Isiak Fadilullah','Laboratory Prefect Boy'),
  (18,'WTS/STU/000648','Adigun Taiso','Adigun Taiwo','Laboratory Prefect Boy'),
  (18,'WTS/STU/000649','Adigun Kehinde','Adigun Kehinde','Laboratory Prefect Boy'),
  (18,'WTS/STU/000654','Shittu Mustapha','Shittu Mustapha','Laboratory Prefect Boy'),
  (19,'WTS/STU/000563','Adeyemi Hafsoh','Adeyemi Hafsoh','Punctuality Prefect Girl'),
  (19,'WTS/STU/000568','Ojedapo Atiyat','Ojedapo Aliyat','Punctuality Prefect Girl'),
  (19,'WTS/STU/000561','Bello Mutmainat','Bello Muthmaheenat','Punctuality Prefect Girl'),
  (19,'WTS/STU/000646','Adefemi Khadiyah','Adeyemi Khadeejah','Punctuality Prefect Girl'),
  (20,'WTS/STU/000655','Yunusa Sobur','Yunusa Sobur','Punctuality Prefect Boy'),
  (20,'WTS/STU/000654','Shittu Mustapha','Shittu Mustapha','Punctuality Prefect Boy'),
  (20,'WTS/STU/000647','Adigun Kamaldeen','Adigun Kamaldeen','Punctuality Prefect Boy'),
  (21,'WTS/STU/000657','Farinde Faheed','Farinde Faheed','Assistant Senior Prefect Boy'),
  (22,'WTS/STU/000561','Bello Mutmainat','Bello Muthmaheenat','Assistant Senior Prefect Girl'),
  (23,'WTS/STU/000656','Oyelami Muiz','Oyelami Muiz','Senior Prefect Boy'),
  (24,'WTS/STU/000564','Lateef Roheemat','Lateef Roheemat','Senior Prefect Girl'),
  (25,'WTS/STU/000196','Hassan Ibrahim','HASSAN IBRAHIM','Timekeeper');

do $migration$
declare
  v_actor uuid;
  v_bad text;
  v_student public.students%rowtype;
  v_notice record;
  v_existing record;
  v_assignment_id uuid;
  v_registered integer := 0;
  v_ended integer := 0;
begin
  if (select count(*) from verified_prefect_notice)<>35 or (select count(distinct permanent_number) from verified_prefect_notice)<>25 then
    raise exception using errcode='P0001',message='VERIFIED_PREFECT_NOTICE_COUNT_INVALID';
  end if;

  select p.id into v_actor
  from public.school_people p
  where p.person_status='active' and coalesce((wts_internal.institutional_authority(p.id)->>'active')::boolean,false)
    and lower(coalesce(wts_internal.institutional_authority(p.id)->>'classification','')) in ('system_owner','developer')
  order by case lower(wts_internal.institutional_authority(p.id)->>'classification') when 'system_owner' then 0 else 1 end,p.created_at
  limit 1;
  if v_actor is null then raise exception using errcode='P0001',message='VERIFIED_PREFECT_IMPORT_ACTOR_NOT_FOUND'; end if;

  select string_agg(v.permanent_number||' ('||v.official_name||')',', ' order by v.notice_row,v.permanent_number) into v_bad
  from verified_prefect_notice v
  left join public.students s on s.admno=v.permanent_number and lower(trim(s.name))=lower(trim(v.canonical_name))
  where s.id is null or coalesce(s.archived,false) or s.lifecycle_status<>'active'
    or s.central_person_id is null or s.class_key not like 'ss2-%' and s.class_key not like 'ss3-%';
  if v_bad is not null then raise exception using errcode='P0001',message='VERIFIED_PREFECT_STUDENT_MATCH_FAILED',detail=v_bad; end if;

  -- Close only conflicting current-session prefect records; retain them as history.
  for v_existing in
    select a.* from public.school_portfolio_assignments a
    where a.portfolio_code='student_executive_council' and a.academic_session='2026/2027' and a.assignment_status='active'
      and not exists (
        select 1 from verified_prefect_notice v join public.students s on s.admno=v.permanent_number
        where s.id=a.student_id and lower(trim(v.office_name))=lower(trim(coalesce(a.office_name,'')))
      )
    for update
  loop
    update public.school_portfolio_assignments set assignment_status='ended',effective_until=greatest(now(),effective_from+interval '1 second'),reason='Superseded by verified official prefect notice dated 15 June 2026',metadata=metadata||jsonb_build_object('appointment_status','ended','ended_by_source','verified_official_notice'),updated_at=now() where id=v_existing.id;
    insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,before_data,after_data,details)
    values('person',v_actor::text,'student.prefect_appointment.ended','school_portfolio_assignment',v_existing.id::text,to_jsonb(v_existing),(select to_jsonb(a) from public.school_portfolio_assignments a where a.id=v_existing.id),jsonb_build_object('academic_session','2026/2027','source','school_prefects_official_notice_2026-06-15'));
    v_ended:=v_ended+1;
  end loop;

  for v_notice in select * from verified_prefect_notice order by notice_row,permanent_number loop
    select * into strict v_student from public.students where admno=v_notice.permanent_number and lower(trim(name))=lower(trim(v_notice.canonical_name));
    select a.* into v_existing from public.school_portfolio_assignments a
    where a.portfolio_code='student_executive_council' and a.student_id=v_student.id and a.academic_session='2026/2027'
      and a.assignment_status='active' and lower(trim(coalesce(a.office_name,'')))=lower(trim(v_notice.office_name))
    order by a.created_at desc limit 1 for update;
    if found then
      v_assignment_id:=v_existing.id;
      update public.school_portfolio_assignments set holder_person_id=v_student.central_person_id,office_name=v_notice.office_name,reason='Verified official 2026/2027 school prefect appointment',metadata=metadata||jsonb_build_object('source','school_prefects_official_notice_2026-06-15','source_date','2026-06-15','notice_row',v_notice.notice_row,'official_name',v_notice.official_name,'canonical_registry_name',v_student.name,'class_at_import',v_student.class_key,'appointment_status','active'),updated_at=now() where id=v_assignment_id;
    else
      insert into public.school_portfolio_assignments(portfolio_code,holder_type,student_id,holder_person_id,academic_session,scope_type,office_name,assignment_status,effective_from,assigned_by_person_id,reason,metadata)
      values('student_executive_council','student',v_student.id,v_student.central_person_id,'2026/2027','self',v_notice.office_name,'active','2026-06-15 00:00:00+01',v_actor,'Verified official 2026/2027 school prefect appointment',jsonb_build_object('source','school_prefects_official_notice_2026-06-15','source_date','2026-06-15','notice_row',v_notice.notice_row,'official_name',v_notice.official_name,'canonical_registry_name',v_student.name,'class_at_import',v_student.class_key,'appointment_status','active'))
      returning id into v_assignment_id;
    end if;
    insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,after_data,details)
    values('person',v_actor::text,'student.prefect_appointment.verified','school_portfolio_assignment',v_assignment_id::text,(select to_jsonb(a) from public.school_portfolio_assignments a where a.id=v_assignment_id),jsonb_build_object('academic_session','2026/2027','source','school_prefects_official_notice_2026-06-15','notice_row',v_notice.notice_row,'permanent_number',v_notice.permanent_number));
    v_registered:=v_registered+1;
  end loop;

  insert into public.school_prefect_bootstrap(id,completed_at,completed_by_person_id,source,metadata)
  values(true,now(),v_actor,'school_prefects_official_notice_2026-06-15',jsonb_build_object('academic_session','2026/2027','source_date','2026-06-15','appointments',v_registered,'students',25,'superseded_records',v_ended))
  on conflict(id) do update set completed_at=excluded.completed_at,completed_by_person_id=excluded.completed_by_person_id,source=excluded.source,metadata=public.school_prefect_bootstrap.metadata||excluded.metadata;

  if v_registered<>35 then raise exception using errcode='P0001',message='VERIFIED_PREFECT_IMPORT_INCOMPLETE'; end if;
end
$migration$;
