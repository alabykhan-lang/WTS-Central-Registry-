-- Retire the transitional Result emergency gate.
-- The normal WTS Staff Login and protected Result session remain unchanged.
-- This removes a legacy authority source rather than creating a replacement.

revoke all on function public.school_identity_result_emergency_access(uuid, text)
  from public, anon, authenticated;

drop function if exists public.school_identity_result_emergency_access(uuid, text);
