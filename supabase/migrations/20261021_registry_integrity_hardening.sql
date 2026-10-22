-- 20261021_registry_integrity_hardening.sql
-- 1) daily_movement_logs was readable AND writable with the public key
--    (policy "Allow all for anon" with USING true/CHECK true, plus anon grants).
-- 2) the student trigger silently created/reactivated class rows with a
--    machine display_name and no stage, which produced the duplicated
--    'class' records and the 'no normalized stage' warnings.

begin;

drop policy if exists "Allow all for anon" on public.daily_movement_logs;
revoke all on table public.daily_movement_logs from public, anon, authenticated;
alter table public.daily_movement_logs enable row level security;

CREATE OR REPLACE FUNCTION public.school_registry_after_student()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
  v_session text:=public.school_registry_current_session();
  v_status text;
  v_key text;
begin
  v_status:=case when coalesce(new.archived,false) then 'archived' else 'active' end;

  insert into public.school_person_roles(person_id,role_type,source_table,source_id,role_status,ended_at,metadata)
  values(new.central_person_id,'student','students',new.id,v_status,case when v_status='archived' then now() else null end,jsonb_build_object('class_key',new.class_key))
  on conflict (source_table,source_id) do update
  set person_id=excluded.person_id,role_status=excluded.role_status,ended_at=excluded.ended_at,metadata=excluded.metadata,updated_at=now();

  if not exists (select 1 from public.school_classes c where c.class_key = new.class_key) then
    raise exception using errcode = 'P0001', message = 'CLASS_NOT_FOUND: ' || new.class_key;
  end if;

  if coalesce(new.archived,false)=false then
    update public.school_student_enrollments
    set enrollment_status=case
          when new.lifecycle_status='graduated' then 'graduated'
          when new.lifecycle_status='transferred' then 'transferred'
          when new.lifecycle_status='withdrawn' then 'withdrawn'
          else 'promoted' end,
        ended_on=current_date,
        updated_at=now()
    where student_id=new.id and enrollment_status='active'
      and (class_key<>new.class_key or academic_session<>v_session);

    insert into public.school_student_enrollments(person_id,student_id,academic_session,class_key,enrollment_status,started_on,source)
    select new.central_person_id,new.id,v_session,new.class_key,'active',coalesce(new.admission_date,current_date),coalesce(nullif(new.admission_source,''),'central_registry')
    where not exists (
      select 1 from public.school_student_enrollments
      where student_id=new.id and enrollment_status='active'
    );
  else
    update public.school_student_enrollments
    set enrollment_status=case
          when new.lifecycle_status='graduated' then 'graduated'
          when new.lifecycle_status='transferred' then 'transferred'
          when new.lifecycle_status='withdrawn' then 'withdrawn'
          else 'archived' end,
        ended_on=coalesce(new.archived_at::date,current_date),
        updated_at=now()
    where student_id=new.id and enrollment_status='active';
  end if;

  v_key:=format('student:%s:%s:%s',lower(tg_op),new.id,replace(clock_timestamp()::text,' ',':'));
  insert into public.school_registry_outbox(event_type,aggregate_type,aggregate_id,payload,target_apps,idempotency_key)
  values(
    case when tg_op='INSERT' then 'student.created'
         when coalesce(new.archived,false) and not coalesce(old.archived,false) then 'student.archived'
         when not coalesce(new.archived,false) and coalesce(old.archived,false) then 'student.restored'
         when new.class_key is distinct from old.class_key then 'student.class_changed'
         else 'student.updated' end,
    'student',new.id,
    jsonb_build_object('student_id',new.id,'person_id',new.central_person_id,'name',new.name,'class_key',new.class_key,'gender',new.gender,'archived',new.archived,'lifecycle_status',new.lifecycle_status),
    array['results','finance','attendance','notifications']::text[],v_key
  );
  return new;
end;
$function$

commit;
