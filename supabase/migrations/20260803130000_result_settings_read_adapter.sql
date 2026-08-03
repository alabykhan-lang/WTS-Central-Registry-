-- Return Result configuration through a validated central session without
-- returning the legacy Gemini provider key to browser code.

create or replace function public.school_result_settings_read(
  p_session_id uuid,
  p_session_secret text
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_auth jsonb;
  v_config jsonb := '{}'::jsonb;
  v_settings jsonb := '{}'::jsonb;
begin
  v_auth := public.school_result_authorize(
    p_session_id,
    p_session_secret,
    'identity.context'
  );
  if coalesce((v_auth ->> 'ok')::boolean, false) is not true then
    return v_auth;
  end if;

  select value::jsonb - 'geminiKey' into v_config
  from public.settings
  where key = 'app_config';

  select coalesce(jsonb_object_agg(key, value), '{}'::jsonb) into v_settings
  from public.settings
  where key in ('session', 'term', 'school_name', 'school_addr', 'school_phone', 'school_email', 'card_theme', 'next_term_resumption');

  return jsonb_build_object(
    'ok', true,
    'code', 'RESULT_SETTINGS_READ',
    'settings', jsonb_build_object(
      'app_config', coalesce(v_config, '{}'::jsonb),
      'safe', v_settings
    )
  );
end;
$function$;

revoke all on function public.school_result_settings_read(uuid, text) from public;
grant execute on function public.school_result_settings_read(uuid, text) to anon, authenticated, service_role;
