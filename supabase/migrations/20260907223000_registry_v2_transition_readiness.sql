-- Transition readiness guard. SS2 Business must retain its department path.

create or replace function public.school_academic_default_promotion_target(p_class_key text)
returns text
language sql
immutable
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
  select case trim(coalesce(p_class_key,''))
    when 'creche' then 'kg1'
    when 'kg1' then 'kg2'
    when 'kg2' then 'nursery1'
    when 'nursery1' then 'nursery2'
    when 'nursery2' then 'primary1'
    when 'primary1' then 'primary2'
    when 'primary2' then 'primary3'
    when 'primary3' then 'primary4'
    when 'primary4' then 'primary5'
    when 'primary5' then 'jss1'
    when 'jss1' then 'jss2'
    when 'jss2' then 'jss3'
    when 'jss3' then 'ss1-general'
    when 'ss1-general' then 'ss2-science'
    when 'ss2-science' then 'ss3-science'
    when 'ss2-arts' then 'ss3-arts'
    when 'ss2-business' then 'ss3-business'
    when 'ss3-science' then ''
    when 'ss3-arts' then ''
    when 'ss3-business' then ''
    else ''
  end
$function$;

revoke all on function public.school_academic_default_promotion_target(text) from public, anon, authenticated;

create or replace function wts_internal.school_registry_transition_readiness(p_source_session text)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_config jsonb;
  v_target text;
  v_bad integer := 0;
begin
  v_config := wts_internal.school_registry_setting_json('app_config');
  if v_config is null then
    return jsonb_build_object(
      'ok',false,
      'code','APP_CONFIG_INVALID',
      'message','The official app configuration is missing or malformed; no transition destination may be guessed.'
    );
  end if;
  v_target := nullif(trim(v_config->'promotionCfg'->'ss2-business'->>'target'),'');
  select count(*) into v_bad from public.school_student_enrollments e where e.academic_session=trim(coalesce(p_source_session,'')) and e.enrollment_status='active' and e.class_key='ss2-business';
  return jsonb_build_object('ok',v_target='ss3-business','code',case when v_target='ss3-business' then 'TRANSITION_READY' else 'SS2_BUSINESS_PROMOTION_TARGET_REQUIRED' end,'configuredTarget',v_target,'activeBusinessStudents',v_bad,'requiredTarget','ss3-business');
end;
$function$;

revoke all on function wts_internal.school_registry_transition_readiness(text) from public, anon, authenticated;
