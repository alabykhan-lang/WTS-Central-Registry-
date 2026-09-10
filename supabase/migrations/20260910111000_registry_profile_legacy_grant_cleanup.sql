-- Keep the pre-wrapper profile implementation private.  The wrapper and the
-- explicit access-template RPC are the only public Registry profile entry
-- points; historical function grants are not an authorization path.
revoke all on function public.school_registry_profile_session_api_legacy(uuid, text, text, text, uuid, text, text, text, uuid, uuid)
  from public, anon, authenticated;

revoke all on function public.school_registry_read_v2_unrestricted(uuid, text, text, jsonb)
  from public, anon, authenticated;

revoke all on function wts_internal.school_registry_session_entitlements_legacy(uuid, text)
  from public, anon, authenticated;
