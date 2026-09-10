-- Registry v2: expose assignment-level access templates in staff profile reads.
-- The selected template is stored on each assignment (so entitlement history
-- remains immutable); profile reads must therefore join the assignment rather
-- than relying only on catalog metadata.

create or replace function public.school_registry_profile_session_api(
  p_session_id uuid,
  p_session_secret text,
  p_action text,
  p_target_type text default null,
  p_target_id uuid default null,
  p_department_code text default null,
  p_portfolio_name text default null,
  p_portfolio_description text default null,
  p_assignment_id uuid default null,
  p_request_id uuid default null
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_result jsonb;
begin
  v_result := public.school_registry_profile_session_api_legacy(
    p_session_id,p_session_secret,p_action,p_target_type,p_target_id,p_department_code,
    p_portfolio_name,p_portfolio_description,p_assignment_id,p_request_id
  );
  if lower(trim(coalesce(p_action,'')))='read'
     and lower(trim(coalesce(p_target_type,'')))='staff'
     and coalesce((v_result ->> 'ok')::boolean,false) then
    v_result := jsonb_set(v_result, '{portfolios}', (
      select coalesce(jsonb_agg(item || case when coalesce(nullif(a.metadata ->> 'access_template_code',''), nullif(c.metadata ->> 'access_template_code','')) is null then '{}'::jsonb else jsonb_build_object('access_template_code',coalesce(nullif(a.metadata ->> 'access_template_code',''), nullif(c.metadata ->> 'access_template_code',''))) end), '[]'::jsonb)
      from jsonb_array_elements(coalesce(v_result -> 'portfolios','[]'::jsonb)) item
      left join public.school_portfolio_assignments a on a.id=(item ->> 'assignment_id')::uuid
      left join public.school_portfolio_catalog c on c.portfolio_code=item ->> 'portfolio_code'
    ), true);
  end if;
  return v_result;
exception when others then
  return jsonb_build_object('ok',false,'code','PROFILE_OPERATION_FAILED');
end;
$function$;

revoke all on function public.school_registry_profile_session_api(uuid,text,text,text,uuid,text,text,text,uuid,uuid)
  from public, authenticated;
grant execute on function public.school_registry_profile_session_api(uuid,text,text,text,uuid,text,text,text,uuid,uuid)
  to anon;
