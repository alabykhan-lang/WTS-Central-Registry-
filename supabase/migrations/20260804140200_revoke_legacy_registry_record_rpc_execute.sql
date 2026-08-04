-- Apply only after the session-native record and staff routes are deployed.
-- These legacy functions accepted reusable attendance-admin client secrets.
revoke all on function public.school_registry_admin_read_api(text, text, text, jsonb) from public, anon, authenticated;
revoke all on function public.school_registry_student_write_api(text, text, text, jsonb) from public, anon, authenticated;
revoke all on function public.school_registry_staff_write_api(text, text, text, jsonb) from public, anon, authenticated;
revoke all on function public.school_registry_guardian_write_api(text, text, text, jsonb) from public, anon, authenticated;
revoke all on function public.school_staff_self_service_api(text, text, text, jsonb) from public, anon, authenticated;
