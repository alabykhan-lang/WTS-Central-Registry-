-- Protect the legacy Result app_config write while retaining its existing shape.
-- The stored Gemini key is preserved server-side and is never replaced by a
-- browser-supplied value through this adapter.

create or replace function public.school_result_app_config_update(
  p_session_id uuid,
  p_session_secret text,
  p_config jsonb
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_auth jsonb;
  v_existing jsonb := '{}'::jsonb;
  v_config jsonb;
begin
  if jsonb_typeof(coalesce(p_config, '{}'::jsonb)) <> 'object' then
    return jsonb_build_object('ok', false, 'code', 'RESULT_CONFIG_PAYLOAD_INVALID');
  end if;

  v_auth := public.school_result_authorize(
    p_session_id,
    p_session_secret,
    'results.manage'
  );
  if coalesce((v_auth ->> 'ok')::boolean, false) is not true then
    return v_auth;
  end if;

  select value::jsonb into v_existing from public.settings where key = 'app_config';
  v_config := coalesce(p_config, '{}'::jsonb);
  if v_existing ? 'geminiKey' then
    v_config := jsonb_set(v_config, '{geminiKey}', v_existing -> 'geminiKey', true);
  else
    v_config := v_config - 'geminiKey';
  end if;

  insert into public.settings(key, value)
  values ('app_config', v_config::text)
  on conflict (key) do update set value = excluded.value;

  insert into public.school_registry_audit(
    actor_type, actor_id, action, entity_type, entity_id, details
  )
  values (
    'result_session',
    v_auth ->> 'person_id',
    'result.app_config.updated',
    'settings',
    'app_config',
    jsonb_build_object('source', 'school_result_app_config_update', 'gemini_key_preserved', v_existing ? 'geminiKey')
  );

  return jsonb_build_object('ok', true, 'code', 'RESULT_APP_CONFIG_UPDATED');
end;
$function$;

revoke all on function public.school_result_app_config_update(uuid, text, jsonb) from public;
grant execute on function public.school_result_app_config_update(uuid, text, jsonb) to anon, authenticated, service_role;
