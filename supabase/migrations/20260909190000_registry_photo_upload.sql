-- Audited image uploads for Registry staff self-profiles and scoped students.
create or replace function public.school_registry_photo_update_session_api(
  p_session_id uuid,
  p_session_secret text,
  p_target_type text,
  p_target_id uuid,
  p_photo_data text,
  p_request_id uuid default null
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog','extensions','public','wts_internal'
as $function$
declare
  v_auth jsonb;
  v_actor uuid;
  v_staff uuid;
  v_target text:=lower(trim(coalesce(p_target_type,'')));
  v_request uuid:=coalesce(p_request_id,gen_random_uuid());
  v_result jsonb;
begin
  v_auth:=public.school_registry_session_context_v2(p_session_id,p_session_secret);
  if coalesce((v_auth->>'ok')::boolean,false) is not true then return v_auth; end if;
  v_actor:=nullif(v_auth->'actor'->>'personId','')::uuid;
  v_staff:=nullif(v_auth->'actor'->>'staffId','')::uuid;
  if length(coalesce(p_photo_data,''))>440000 or p_photo_data !~ '^data:image/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$' then
    return jsonb_build_object('ok',false,'code','PHOTO_IMAGE_INVALID');
  end if;
  if v_target='staff' then
    if p_target_id is not null and p_target_id<>v_staff then return jsonb_build_object('ok',false,'code','REGISTRY_SCOPE_DENIED'); end if;
    if not wts_internal.school_registry_has_capability(coalesce(v_auth->'entitlements','{}'::jsonb),'profile.self.update') then return jsonb_build_object('ok',false,'code','REGISTRY_CAPABILITY_DENIED'); end if;
    update public.staff_attendance_profiles set photo=p_photo_data,updated_at=now()
    where id=v_staff and central_person_id=v_actor and registration_status='active' and employment_status='active';
    if not found then return jsonb_build_object('ok',false,'code','REGISTRY_IDENTITY_NOT_ACTIVE'); end if;
    insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,request_id,details)
    values('person',v_actor::text,'staff.photo_updated','staff_attendance_profile',v_staff::text,v_request,jsonb_build_object('source','registry_picture_upload'));
    return jsonb_build_object('ok',true,'code','STAFF_PHOTO_UPDATED','request_id',v_request);
  elsif v_target='student' and p_target_id is not null then
    v_result:=public.school_registry_write_v2(p_session_id,p_session_secret,'student.update',jsonb_build_object('studentId',p_target_id,'photo',p_photo_data,'requestId',v_request));
    return v_result;
  end if;
  return jsonb_build_object('ok',false,'code','PHOTO_TARGET_INVALID');
end;
$function$;

revoke all on function public.school_registry_photo_update_session_api(uuid,text,text,uuid,text,uuid) from public,authenticated;
grant execute on function public.school_registry_photo_update_session_api(uuid,text,text,uuid,text,uuid) to anon;
