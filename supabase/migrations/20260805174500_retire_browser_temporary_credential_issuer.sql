-- Password creation and recovery are now self-service through verified email.
-- Keep the old database function for controlled rollback, but do not expose it
-- through an anonymous/session browser RPC.
revoke all on function public.school_identity_management_session_write_api(uuid, text, text, jsonb)
  from public, anon, authenticated;
grant execute on function public.school_identity_management_session_write_api(uuid, text, text, jsonb)
  to service_role;
