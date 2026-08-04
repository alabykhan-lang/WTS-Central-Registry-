-- Phase 3 Central Registry record adapters.
-- These functions preserve the existing record workflows while replacing the
-- browser-supplied attendance-admin client code and secret.

create or replace function public.school_registry_admin_read_session_api(
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
  v_session jsonb;
  v_admin uuid;
  v_search text := trim(coalesce(p_payload ->> 'search', ''));
  v_class text := trim(coalesce(p_payload ->> 'classKey', ''));
  v_status text := trim(coalesce(p_payload ->> 'status', ''));
  v_person_id uuid;
  v_student_id uuid;
  v_result jsonb;
begin
  v_session := public.school_identity_session_validate(p_session_id, p_session_secret, 'central_registry');
  if coalesce((v_session ->> 'ok')::boolean, false) is not true then return v_session; end if;
  v_admin := wts_internal.central_management_actor(v_session);
  if v_admin is null then return jsonb_build_object('ok', false, 'code', 'MANAGEMENT_ACCESS_DENIED'); end if;

  if p_action = 'context' then
    return jsonb_build_object(
      'ok', true,
      'people', (select count(*) from public.school_people),
      'active_students', (select count(*) from public.students where archived = false),
      'archived_students', (select count(*) from public.students where archived = true),
      'active_staff', (select count(*) from public.staff_attendance_profiles where registration_status = 'active' and employment_status = 'active'),
      'archived_staff', (select count(*) from public.staff_attendance_profiles where registration_status = 'archived' or employment_status = 'exited'),
      'pending_admissions', (select count(*) from public.school_admission_applications where application_status in ('submitted', 'under_review', 'approved')),
      'pending_sync_events', (select count(*) from public.school_registry_outbox where event_status in ('pending', 'failed')),
      'classes', (select coalesce(jsonb_agg(to_jsonb(c) order by c.sort_order, c.display_name), '[]'::jsonb) from (select id, class_key, display_name, section, sort_order, is_active from public.school_classes where is_active = true) c),
      'applications', (select coalesce(jsonb_agg(to_jsonb(a) order by a.app_name), '[]'::jsonb) from (select app_code, app_name, description, supports_login, default_roles from public.school_portal_catalog where is_active = true) a),
      'access_summary', (select coalesce(jsonb_object_agg(app_code, total), '{}'::jsonb) from (select app_code, count(*) total from public.school_access_grants where grant_status = 'active' group by app_code) x)
    );
  end if;

  if p_action = 'students' then
    select jsonb_build_object('ok', true, 'students', coalesce(jsonb_agg(to_jsonb(s) order by s.name), '[]'::jsonb)) into v_result
    from (
      select st.id student_id, st.central_person_id person_id, st.name, st.gender, st.admno, st.class_key,
        st.archived, st.lifecycle_status, st.admission_date, st.admission_source, st.photo,
        (select count(*) from public.school_student_guardians g where g.student_id = st.id and g.status = 'active') guardian_count,
        (select count(*) from public.school_access_grants a where a.person_id = st.central_person_id and a.grant_status = 'active') access_count
      from public.students st
      where (v_class = '' or st.class_key = v_class)
        and (v_status = '' or (v_status = 'active' and st.archived = false) or (v_status = 'archived' and st.archived = true) or st.lifecycle_status = v_status)
        and (v_search = '' or st.name ilike '%' || v_search || '%' or coalesce(st.admno, '') ilike '%' || v_search || '%')
      order by st.name limit 1500
    ) s;
    return v_result;
  end if;

  if p_action = 'staff' then
    select jsonb_build_object('ok', true, 'staff', coalesce(jsonb_agg(to_jsonb(s) order by s.full_name), '[]'::jsonb)) into v_result
    from (
      select sp.id staff_id, sp.central_person_id person_id, sp.staff_number, sp.full_name, sp.email, sp.phone,
        sp.staff_category, sp.department, sp.designation, sp.employment_status, sp.attendance_required,
        sp.registration_source, sp.registration_status, sp.photo, sp.whatsapp_number, sp.whatsapp_opt_in_status,
        sp.whatsapp_opt_in_at, sp.whatsapp_opt_in_source, sp.whatsapp_verified_at, sp.preferred_language, sp.pilot_enabled,
        (select count(*) from public.school_access_grants a where a.person_id = sp.central_person_id and a.grant_status = 'active') access_count,
        exists(select 1 from public.school_identity_accounts i where i.person_id = sp.central_person_id and i.account_status = 'active') has_login
      from public.staff_attendance_profiles sp
      where (v_status = '' or sp.registration_status = v_status or sp.employment_status = v_status)
        and (v_search = '' or sp.full_name ilike '%' || v_search || '%' or coalesce(sp.staff_number, '') ilike '%' || v_search || '%' or coalesce(sp.email, '') ilike '%' || v_search || '%')
      order by sp.full_name limit 1000
    ) s;
    return v_result;
  end if;

  if p_action = 'access' then
    begin v_person_id := (p_payload ->> 'personId')::uuid;
    exception when others then return jsonb_build_object('ok', false, 'code', 'INVALID_PERSON_ID'); end;
    return jsonb_build_object(
      'ok', true,
      'person', (select jsonb_build_object('id', id, 'full_name', full_name, 'status', person_status) from public.school_people where id = v_person_id),
      'grants', (select coalesce(jsonb_agg(to_jsonb(g) order by g.app_name), '[]'::jsonb) from (
        select a.id, a.app_code, c.app_name, a.access_role, a.permissions, a.grant_status, a.valid_from, a.valid_until, a.reason
        from public.school_access_grants a join public.school_portal_catalog c on c.app_code = a.app_code where a.person_id = v_person_id
      ) g),
      'account', (select to_jsonb(i) from (select id, auth_user_id, legacy_user_profile_id, login_email, account_status, identity_source, last_login_at from public.school_identity_accounts where person_id = v_person_id limit 1) i)
    );
  end if;

  if p_action = 'admissions' then
    select jsonb_build_object('ok', true, 'applications', coalesce(jsonb_agg(to_jsonb(a) order by a.created_at desc), '[]'::jsonb)) into v_result
    from (
      select id, application_number, desired_session, desired_class_key, student_full_name, gender, date_of_birth,
        guardian_full_name, guardian_relationship, guardian_phone, guardian_whatsapp, guardian_email,
        notification_consent, preferred_language, application_status, rejection_reason, linked_student_id,
        submitted_at, reviewed_at, enrolled_at, created_at
      from public.school_admission_applications
      where (v_status = '' or application_status = v_status)
        and (v_search = '' or student_full_name ilike '%' || v_search || '%' or application_number ilike '%' || v_search || '%' or coalesce(guardian_full_name, '') ilike '%' || v_search || '%')
      order by created_at desc limit 1000
    ) a;
    return v_result;
  end if;

  if p_action = 'guardians' then
    begin v_student_id := (p_payload ->> 'studentId')::uuid;
    exception when others then return jsonb_build_object('ok', false, 'code', 'INVALID_STUDENT_ID'); end;
    return jsonb_build_object('ok', true, 'guardians', (
      select coalesce(jsonb_agg(to_jsonb(g) order by g.is_primary desc, g.full_name), '[]'::jsonb)
      from (
        select sg.id relationship_id, gd.id guardian_id, gd.full_name, gd.primary_phone, gd.whatsapp_phone, gd.email,
          sg.relationship, sg.is_primary, sg.is_legal_guardian, sg.notification_consent, sg.preferred_language, sg.status
        from public.school_student_guardians sg join public.school_guardians gd on gd.id = sg.guardian_id
        where sg.student_id = v_student_id
      ) g
    ));
  end if;

  if p_action = 'outbox' then
    select jsonb_build_object('ok', true, 'events', coalesce(jsonb_agg(to_jsonb(o) order by o.created_at desc), '[]'::jsonb)) into v_result
    from (
      select id, event_type, aggregate_type, aggregate_id, target_apps, event_status, attempts, available_at, processed_at, last_error, created_at
      from public.school_registry_outbox where (v_status = '' or event_status = v_status) order by created_at desc limit 1000
    ) o;
    return v_result;
  end if;

  return jsonb_build_object('ok', false, 'code', 'UNKNOWN_ACTION');
end;
$function$;

create or replace function public.school_registry_student_write_session_api(
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
  v_session jsonb;
  v_admin uuid;
  v_request uuid := gen_random_uuid();
  v_student uuid;
  v_before jsonb;
  v_after jsonb;
  v_name text;
  v_class text;
  v_admno text;
  v_status text;
  v_reason text;
begin
  v_session := public.school_identity_session_validate(p_session_id, p_session_secret, 'central_registry');
  if coalesce((v_session ->> 'ok')::boolean, false) is not true then return v_session; end if;
  v_admin := wts_internal.central_management_actor(v_session);
  if v_admin is null then return jsonb_build_object('ok', false, 'code', 'MANAGEMENT_ACCESS_DENIED'); end if;

  if p_action = 'create' then
    v_name := nullif(trim(p_payload ->> 'name'), '');
    v_class := nullif(trim(p_payload ->> 'classKey'), '');
    if v_name is null then return jsonb_build_object('ok', false, 'code', 'STUDENT_NAME_REQUIRED'); end if;
    if v_class is null then return jsonb_build_object('ok', false, 'code', 'CLASS_REQUIRED'); end if;
    insert into public.school_classes(class_key, display_name, section)
    values(v_class, v_class, case when lower(v_class) ~ '(creche|crèche|kg|nursery|primary|basic|pry)' then 'primary' else 'secondary' end)
    on conflict (class_key) do update set is_active = true, updated_at = now();
    insert into public.students(class_key, name, gender, house, age, photo, archived, lifecycle_status, admission_date, admission_source)
    values(v_class, v_name,
      case public.school_registry_gender(p_payload ->> 'gender') when 'male' then 'Male' when 'female' then 'Female' else 'Unknown' end,
      nullif(trim(p_payload ->> 'house'), ''), nullif(trim(p_payload ->> 'age'), ''), nullif(trim(p_payload ->> 'photo'), ''),
      false, 'active', coalesce(nullif(p_payload ->> 'admissionDate', '')::date, current_date), 'central_registry')
    returning id, admno into v_student, v_admno;
    select to_jsonb(s) into v_after from public.students s where id = v_student;
    insert into public.school_registry_audit(actor_id, action, entity_type, entity_id, request_id, after_data)
    values(v_admin::text, 'student.create', 'student', v_student::text, v_request, v_after);
    return jsonb_build_object('ok', true, 'code', 'STUDENT_CREATED', 'student_id', v_student, 'admission_number', v_admno, 'request_id', v_request);
  end if;

  begin v_student := (p_payload ->> 'studentId')::uuid;
  exception when others then return jsonb_build_object('ok', false, 'code', 'INVALID_STUDENT_ID'); end;
  select to_jsonb(s) into v_before from public.students s where id = v_student;
  if v_before is null then return jsonb_build_object('ok', false, 'code', 'STUDENT_NOT_FOUND'); end if;

  if p_action = 'update' then
    if coalesce((v_before ->> 'archived')::boolean, false) then return jsonb_build_object('ok', false, 'code', 'ARCHIVED_STUDENT_RESTORE_FIRST'); end if;
    update public.students set
      name = coalesce(nullif(trim(p_payload ->> 'name'), ''), name),
      class_key = coalesce(nullif(trim(p_payload ->> 'classKey'), ''), class_key),
      gender = case when nullif(trim(p_payload ->> 'gender'), '') is null then gender else case public.school_registry_gender(p_payload ->> 'gender') when 'male' then 'Male' when 'female' then 'Female' else 'Unknown' end end,
      house = case when p_payload ? 'house' then nullif(trim(p_payload ->> 'house'), '') else house end,
      age = case when p_payload ? 'age' then nullif(trim(p_payload ->> 'age'), '') else age end,
      photo = case when p_payload ? 'photo' then nullif(trim(p_payload ->> 'photo'), '') else photo end,
      updated_at = now()
    where id = v_student;
  elsif p_action = 'archive' then
    v_reason := nullif(trim(p_payload ->> 'reason'), '');
    v_status := coalesce(nullif(trim(p_payload ->> 'lifecycleStatus'), ''), 'archived');
    if v_reason is null then return jsonb_build_object('ok', false, 'code', 'ARCHIVE_REASON_REQUIRED'); end if;
    if v_status not in ('graduated', 'transferred', 'withdrawn', 'suspended', 'archived') then return jsonb_build_object('ok', false, 'code', 'INVALID_LIFECYCLE_STATUS'); end if;
    update public.students set previous_class_key = class_key, archived = true, archived_at = now(), archived_reason = v_reason, lifecycle_status = v_status,
      student_number_status = case when v_status = 'suspended' then student_number_status else 'revoked' end,
      student_number_revoked_at = case when v_status = 'suspended' then student_number_revoked_at else now() end,
      student_number_revoked_reason = case when v_status = 'suspended' then student_number_revoked_reason else v_reason end, updated_at = now()
    where id = v_student;
    update public.student_cards set status = 'suspended', disabled_at = now(), disabled_reason = 'Student archived: ' || v_reason, updated_at = now()
    where student_id = v_student and status = 'active';
  elsif p_action = 'restore' then
    update public.students set archived = false, archived_at = null, archived_reason = null, lifecycle_status = 'active',
      class_key = coalesce(nullif(trim(p_payload ->> 'classKey'), ''), class_key), student_number_status = 'active', student_number_revoked_at = null,
      student_number_revoked_reason = null, updated_at = now()
    where id = v_student;
  else
    return jsonb_build_object('ok', false, 'code', 'UNKNOWN_ACTION');
  end if;

  select to_jsonb(s) into v_after from public.students s where id = v_student;
  insert into public.school_registry_audit(actor_id, action, entity_type, entity_id, request_id, before_data, after_data, details)
  values(v_admin::text, 'student.' || p_action, 'student', v_student::text, v_request, v_before, v_after,
    jsonb_build_object('reason', p_payload ->> 'reason', 'lifecycle_status', p_payload ->> 'lifecycleStatus'));
  return jsonb_build_object('ok', true, 'code', 'STUDENT_' || upper(p_action), 'student_id', v_student, 'admission_number', v_after ->> 'admno', 'request_id', v_request);
exception
  when unique_violation then return jsonb_build_object('ok', false, 'code', 'DUPLICATE_STUDENT_RECORD');
  when invalid_text_representation then return jsonb_build_object('ok', false, 'code', 'INVALID_REQUEST_VALUE');
  when others then return jsonb_build_object('ok', false, 'code', 'STUDENT_WRITE_FAILED');
end;
$function$;

create or replace function public.school_registry_staff_write_session_api(
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
  v_session jsonb;
  v_admin uuid;
  v_request uuid := gen_random_uuid();
  v_staff uuid;
  v_before jsonb;
  v_after jsonb;
  v_name text;
  v_number text;
  v_reason text;
begin
  v_session := public.school_identity_session_validate(p_session_id, p_session_secret, 'central_registry');
  if coalesce((v_session ->> 'ok')::boolean, false) is not true then return v_session; end if;
  v_admin := wts_internal.central_management_actor(v_session);
  if v_admin is null then return jsonb_build_object('ok', false, 'code', 'MANAGEMENT_ACCESS_DENIED'); end if;

  if p_action = 'create' then
    v_name := nullif(trim(p_payload ->> 'fullName'), '');
    if v_name is null then return jsonb_build_object('ok', false, 'code', 'STAFF_NAME_REQUIRED'); end if;
    insert into public.staff_attendance_profiles(
      full_name, email, phone, address, staff_category, department, designation, photo, employment_status, attendance_required,
      metadata, registration_source, registration_status, activated_at, whatsapp_number, whatsapp_opt_in_status, whatsapp_opt_in_at,
      whatsapp_opt_in_source, whatsapp_verified_at, preferred_language, pilot_enabled
    ) values(
      v_name, nullif(lower(trim(p_payload ->> 'email')), ''), nullif(trim(p_payload ->> 'phone'), ''), nullif(trim(p_payload ->> 'address'), ''),
      coalesce(nullif(trim(p_payload ->> 'category'), ''), 'teaching'), nullif(trim(p_payload ->> 'department'), ''), nullif(trim(p_payload ->> 'designation'), ''), nullif(trim(p_payload ->> 'photo'), ''),
      'active', coalesce((p_payload ->> 'attendanceRequired')::boolean, true), jsonb_build_object('created_by_registry', 'secure_session'), 'admin_enrollment', 'active', now(),
      nullif(trim(p_payload ->> 'whatsappNumber'), ''), case when coalesce((p_payload ->> 'whatsappConsent')::boolean, false) then 'opted_in' else 'pending' end,
      case when coalesce((p_payload ->> 'whatsappConsent')::boolean, false) then now() end,
      case when coalesce((p_payload ->> 'whatsappConsent')::boolean, false) then coalesce(nullif(trim(p_payload ->> 'consentSource'), ''), 'central_registry') end,
      case when coalesce((p_payload ->> 'whatsappVerified')::boolean, false) then now() end,
      case lower(coalesce(p_payload ->> 'preferredLanguage', 'en')) when 'yo' then 'yo' when 'both' then 'both' else 'en' end,
      coalesce((p_payload ->> 'pilotEnabled')::boolean, false)
    ) returning id, staff_number into v_staff, v_number;
    select to_jsonb(s) into v_after from public.staff_attendance_profiles s where id = v_staff;
    insert into public.school_registry_audit(actor_id, action, entity_type, entity_id, request_id, after_data, details)
    values(v_admin::text, 'staff.create', 'staff', v_staff::text, v_request, v_after, jsonb_build_object('portal_access_granted', false));
    return jsonb_build_object('ok', true, 'code', 'STAFF_CREATED_NO_PORTAL_ACCESS', 'staff_id', v_staff, 'staff_number', v_number, 'request_id', v_request);
  end if;

  begin v_staff := (p_payload ->> 'staffId')::uuid;
  exception when others then return jsonb_build_object('ok', false, 'code', 'INVALID_STAFF_ID'); end;
  select to_jsonb(s) into v_before from public.staff_attendance_profiles s where id = v_staff;
  if v_before is null then return jsonb_build_object('ok', false, 'code', 'STAFF_NOT_FOUND'); end if;

  if p_action = 'update' then
    update public.staff_attendance_profiles set
      full_name = coalesce(nullif(trim(p_payload ->> 'fullName'), ''), full_name),
      email = case when p_payload ? 'email' then nullif(lower(trim(p_payload ->> 'email')), '') else email end,
      phone = case when p_payload ? 'phone' then nullif(trim(p_payload ->> 'phone'), '') else phone end,
      address = case when p_payload ? 'address' then nullif(trim(p_payload ->> 'address'), '') else address end,
      staff_category = coalesce(nullif(trim(p_payload ->> 'category'), ''), staff_category),
      department = case when p_payload ? 'department' then nullif(trim(p_payload ->> 'department'), '') else department end,
      designation = case when p_payload ? 'designation' then nullif(trim(p_payload ->> 'designation'), '') else designation end,
      photo = case when p_payload ? 'photo' then nullif(trim(p_payload ->> 'photo'), '') else photo end,
      attendance_required = coalesce((p_payload ->> 'attendanceRequired')::boolean, attendance_required),
      whatsapp_number = case when p_payload ? 'whatsappNumber' then nullif(trim(p_payload ->> 'whatsappNumber'), '') else whatsapp_number end,
      whatsapp_opt_in_status = case when p_payload ? 'whatsappConsent' and coalesce((p_payload ->> 'whatsappConsent')::boolean, false) then 'opted_in' when p_payload ? 'whatsappConsent' then 'pending' else whatsapp_opt_in_status end,
      whatsapp_opt_in_at = case when p_payload ? 'whatsappConsent' and coalesce((p_payload ->> 'whatsappConsent')::boolean, false) then coalesce(whatsapp_opt_in_at, now()) else whatsapp_opt_in_at end,
      whatsapp_opt_in_source = case when p_payload ? 'whatsappConsent' and coalesce((p_payload ->> 'whatsappConsent')::boolean, false) then coalesce(nullif(trim(p_payload ->> 'consentSource'), ''), 'central_registry') else whatsapp_opt_in_source end,
      whatsapp_verified_at = case when p_payload ? 'whatsappVerified' and coalesce((p_payload ->> 'whatsappVerified')::boolean, false) then coalesce(whatsapp_verified_at, now()) when p_payload ? 'whatsappVerified' then null else whatsapp_verified_at end,
      preferred_language = case when p_payload ? 'preferredLanguage' then case lower(p_payload ->> 'preferredLanguage') when 'yo' then 'yo' when 'both' then 'both' else 'en' end else preferred_language end,
      pilot_enabled = coalesce((p_payload ->> 'pilotEnabled')::boolean, pilot_enabled), updated_at = now()
    where id = v_staff;
  elsif p_action = 'suspend' then
    v_reason := coalesce(nullif(trim(p_payload ->> 'reason'), ''), 'Suspended through Central School Registry');
    update public.staff_attendance_profiles set employment_status = 'suspended', attendance_required = false, registration_status = 'suspended', updated_at = now() where id = v_staff;
    update public.staff_cards set status = 'suspended', disabled_at = now(), disabled_reason = v_reason, updated_at = now() where staff_id = v_staff and status = 'active';
    update public.school_access_grants set grant_status = 'suspended', reason = v_reason, updated_at = now() where person_id = (select central_person_id from public.staff_attendance_profiles where id = v_staff) and grant_status = 'active';
  elsif p_action = 'archive' then
    v_reason := coalesce(nullif(trim(p_payload ->> 'reason'), ''), 'Archived through Central School Registry');
    update public.staff_attendance_profiles set employment_status = 'exited', attendance_required = false, registration_status = 'archived', archived_at = now(), updated_at = now() where id = v_staff;
    update public.staff_cards set status = 'suspended', disabled_at = now(), disabled_reason = v_reason, updated_at = now() where staff_id = v_staff and status = 'active';
    update public.school_access_grants set grant_status = 'revoked', reason = v_reason, updated_at = now() where person_id = (select central_person_id from public.staff_attendance_profiles where id = v_staff) and grant_status in ('active', 'suspended');
    update public.school_identity_accounts set account_status = 'archived', updated_at = now() where person_id = (select central_person_id from public.staff_attendance_profiles where id = v_staff);
  elsif p_action = 'restore' then
    update public.staff_attendance_profiles set employment_status = 'active', registration_status = 'active', archived_at = null, attendance_required = coalesce((p_payload ->> 'attendanceRequired')::boolean, true), updated_at = now() where id = v_staff;
    update public.school_identity_accounts set account_status = case when auth_user_id is not null or legacy_user_profile_id is not null then 'active' else account_status end, updated_at = now() where person_id = (select central_person_id from public.staff_attendance_profiles where id = v_staff);
  else
    return jsonb_build_object('ok', false, 'code', 'UNKNOWN_ACTION');
  end if;

  select to_jsonb(s) into v_after from public.staff_attendance_profiles s where id = v_staff;
  insert into public.school_registry_audit(actor_id, action, entity_type, entity_id, request_id, before_data, after_data, details)
  values(v_admin::text, 'staff.' || p_action, 'staff', v_staff::text, v_request, v_before, v_after, jsonb_build_object('reason', p_payload ->> 'reason'));
  return jsonb_build_object('ok', true, 'code', 'STAFF_' || upper(p_action), 'staff_id', v_staff, 'staff_number', v_after ->> 'staff_number', 'request_id', v_request);
exception
  when unique_violation then return jsonb_build_object('ok', false, 'code', 'DUPLICATE_STAFF_RECORD');
  when invalid_text_representation then return jsonb_build_object('ok', false, 'code', 'INVALID_REQUEST_VALUE');
  when others then return jsonb_build_object('ok', false, 'code', 'STAFF_WRITE_FAILED');
end;
$function$;

create or replace function public.school_registry_guardian_write_session_api(
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
  v_session jsonb;
  v_admin uuid;
  v_request uuid := gen_random_uuid();
  v_student uuid;
  v_relationship uuid;
  v_guardian uuid;
  v_result jsonb;
  v_before jsonb;
  v_after jsonb;
begin
  v_session := public.school_identity_session_validate(p_session_id, p_session_secret, 'central_registry');
  if coalesce((v_session ->> 'ok')::boolean, false) is not true then return v_session; end if;
  v_admin := wts_internal.central_management_actor(v_session);
  if v_admin is null then return jsonb_build_object('ok', false, 'code', 'MANAGEMENT_ACCESS_DENIED'); end if;

  if p_action = 'upsert' then
    begin v_student := (p_payload ->> 'studentId')::uuid;
    exception when others then return jsonb_build_object('ok', false, 'code', 'INVALID_STUDENT_ID'); end;
    v_result := public.school_registry_upsert_guardian(
      v_student, p_payload ->> 'fullName', p_payload ->> 'relationship', p_payload ->> 'phone', p_payload ->> 'whatsapp', p_payload ->> 'email',
      coalesce((p_payload ->> 'isPrimary')::boolean, false), coalesce((p_payload ->> 'isLegalGuardian')::boolean, true),
      coalesce((p_payload ->> 'notificationConsent')::boolean, false), coalesce(p_payload ->> 'preferredLanguage', 'english')
    );
    if coalesce((v_result ->> 'ok')::boolean, false) = false then return v_result; end if;
    insert into public.school_registry_audit(actor_id, action, entity_type, entity_id, request_id, details)
    values(v_admin::text, 'guardian.upsert', 'student', v_student::text, v_request, v_result);
    return v_result || jsonb_build_object('request_id', v_request);
  end if;

  begin v_relationship := (p_payload ->> 'relationshipId')::uuid;
  exception when others then return jsonb_build_object('ok', false, 'code', 'INVALID_GUARDIAN_RELATIONSHIP_ID'); end;
  select to_jsonb(x), x.student_id, x.guardian_id into v_before, v_student, v_guardian from public.school_student_guardians x where x.id = v_relationship;
  if v_before is null then return jsonb_build_object('ok', false, 'code', 'GUARDIAN_RELATIONSHIP_NOT_FOUND'); end if;

  if p_action = 'archive' then
    update public.school_student_guardians set status = 'archived', notification_consent = false, is_primary = false, updated_at = now() where id = v_relationship;
    update public.attendance_guardian_contacts set status = 'inactive', receives_attendance_alerts = false, whatsapp_opt_in_status = 'revoked', updated_at = now()
    where student_id = v_student and status = 'active' and (phone in (select primary_phone from public.school_guardians where id = v_guardian) or whatsapp_number in (select whatsapp_phone from public.school_guardians where id = v_guardian) or lower(coalesce(email, '')) in (select lower(coalesce(email, '')) from public.school_guardians where id = v_guardian));
  elsif p_action = 'setConsent' then
    update public.school_student_guardians set notification_consent = coalesce((p_payload ->> 'notificationConsent')::boolean, false), preferred_language = case lower(coalesce(p_payload ->> 'preferredLanguage', 'english')) when 'yoruba' then 'yoruba' when 'both' then 'both' else 'english' end, updated_at = now() where id = v_relationship;
    update public.attendance_guardian_contacts set receives_attendance_alerts = coalesce((p_payload ->> 'notificationConsent')::boolean, false),
      whatsapp_opt_in_status = case when coalesce((p_payload ->> 'notificationConsent')::boolean, false) then 'opted_in' else 'revoked' end,
      whatsapp_opt_in_at = case when coalesce((p_payload ->> 'notificationConsent')::boolean, false) then coalesce(whatsapp_opt_in_at, now()) else whatsapp_opt_in_at end,
      whatsapp_opt_in_source = case when coalesce((p_payload ->> 'notificationConsent')::boolean, false) then 'central_registry' else whatsapp_opt_in_source end,
      preferred_language = case lower(coalesce(p_payload ->> 'preferredLanguage', 'english')) when 'yoruba' then 'yo' when 'both' then 'both' else 'en' end, updated_at = now()
    where student_id = v_student and status = 'active' and (phone in (select primary_phone from public.school_guardians where id = v_guardian) or whatsapp_number in (select whatsapp_phone from public.school_guardians where id = v_guardian) or lower(coalesce(email, '')) in (select lower(coalesce(email, '')) from public.school_guardians where id = v_guardian));
  else
    return jsonb_build_object('ok', false, 'code', 'UNKNOWN_ACTION');
  end if;

  select to_jsonb(x) into v_after from public.school_student_guardians x where x.id = v_relationship;
  insert into public.school_registry_audit(actor_id, action, entity_type, entity_id, request_id, before_data, after_data)
  values(v_admin::text, 'guardian.' || p_action, 'guardian_relationship', v_relationship::text, v_request, v_before, v_after);
  return jsonb_build_object('ok', true, 'code', 'GUARDIAN_' || upper(p_action), 'relationship_id', v_relationship, 'request_id', v_request);
exception
  when others then return jsonb_build_object('ok', false, 'code', 'GUARDIAN_WRITE_FAILED');
end;
$function$;

revoke all on function public.school_registry_admin_read_session_api(uuid, text, text, jsonb) from public, authenticated;
revoke all on function public.school_registry_student_write_session_api(uuid, text, text, jsonb) from public, authenticated;
revoke all on function public.school_registry_staff_write_session_api(uuid, text, text, jsonb) from public, authenticated;
revoke all on function public.school_registry_guardian_write_session_api(uuid, text, text, jsonb) from public, authenticated;
grant execute on function public.school_registry_admin_read_session_api(uuid, text, text, jsonb) to anon;
grant execute on function public.school_registry_student_write_session_api(uuid, text, text, jsonb) to anon;
grant execute on function public.school_registry_staff_write_session_api(uuid, text, text, jsonb) to anon;
grant execute on function public.school_registry_guardian_write_session_api(uuid, text, text, jsonb) to anon;
