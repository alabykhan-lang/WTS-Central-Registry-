-- Return only the minimum active staff recipient data to the server-side
-- email adapter. Browser roles cannot execute this function.
create or replace function public.school_registry_staff_notification_recipient_service(
  p_staff_id uuid
)
returns jsonb
language sql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
  select case
    when s.id is null or s.registration_status <> 'active' or s.employment_status <> 'active'
      then jsonb_build_object('ok', false, 'code', 'STAFF_NOT_ACTIVE')
    when nullif(trim(coalesce(s.email, '')), '') is null
      then jsonb_build_object('ok', false, 'code', 'STAFF_EMAIL_NOT_AVAILABLE')
    else jsonb_build_object('ok', true, 'email', lower(trim(s.email)), 'full_name', s.full_name, 'staff_number', s.staff_number)
  end
  from public.staff_attendance_profiles s
  where s.id = p_staff_id;
$function$;

revoke all on function public.school_registry_staff_notification_recipient_service(uuid)
  from public, anon, authenticated;
grant execute on function public.school_registry_staff_notification_recipient_service(uuid)
  to service_role;
