-- Server-side exchange adapters for the Phase 1 session foundation.
-- Raw session secrets are returned only to the same-origin server route, which
-- places them in an HttpOnly cookie; browser code does not receive them.
create or replace function public.school_identity_session_issue_api(
  p_client_code text,
  p_client_secret text,
  p_originating_app_code text,
  p_target_app_code text
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
begin
  return public.school_identity_session_issue(
    p_client_code,
    p_client_secret,
    p_originating_app_code,
    p_target_app_code
  );
end;
$function$;

revoke all on function public.school_identity_session_issue_api(text, text, text, text) from public, authenticated;
grant execute on function public.school_identity_session_issue_api(text, text, text, text) to anon;

create or replace function public.school_identity_session_context_api(
  p_session_id uuid,
  p_session_secret text,
  p_target_app_code text default null
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
begin
  return public.school_identity_session_validate(p_session_id, p_session_secret, p_target_app_code);
end;
$function$;

revoke all on function public.school_identity_session_context_api(uuid, text, text) from public, authenticated;
grant execute on function public.school_identity_session_context_api(uuid, text, text) to anon;