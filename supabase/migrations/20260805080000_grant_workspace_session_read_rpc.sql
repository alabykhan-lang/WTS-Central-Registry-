-- Final runtime fix: allow the WTS Workspace server to call the exact session-read RPC.
-- The endpoint still validates the session secret and target app inside the function.
revoke all on function public.school_staff_workspace_read_session_api(uuid, text)
  from public, authenticated;
grant execute on function public.school_staff_workspace_read_session_api(uuid, text)
  to anon;
