-- Safe configuration/readiness helpers used by Registry v2. These functions
-- never cast malformed operator-maintained JSON directly in a request path.

create or replace function wts_internal.school_registry_setting_json(p_key text)
returns jsonb
language plpgsql
stable
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_raw text;
begin
  select s.value into v_raw from public.settings s where s.key = p_key limit 1;
  if v_raw is null then return null; end if;
  begin
    return v_raw::jsonb;
  exception when others then
    return null;
  end;
end;
$function$;

revoke all on function wts_internal.school_registry_setting_json(text) from public, anon, authenticated;

-- The Business stream is approved school structure, not unresolved operator
-- data. Correct only this deterministic path and preserve every other config
-- key verbatim. Seed SS3 Business subjects from the verified SS2 structure
-- only when an SS3 entry does not already exist.
do $migration$
declare
  v_before jsonb;
  v_after jsonb;
  v_ss2_business jsonb;
begin
  v_before := wts_internal.school_registry_setting_json('app_config');
  if v_before is null then
    return;
  end if;

  v_after := jsonb_set(
    v_before,
    '{promotionCfg}',
    case when jsonb_typeof(v_before->'promotionCfg')='object' then v_before->'promotionCfg' else '{}'::jsonb end
      || jsonb_build_object(
        'ss2-business',
        case when jsonb_typeof(v_before->'promotionCfg'->'ss2-business')='object' then v_before->'promotionCfg'->'ss2-business' else '{}'::jsonb end
          || jsonb_build_object('target','ss3-business')
      ),
    true
  );

  v_ss2_business := v_after->'depts'->'ss2-business';
  if jsonb_typeof(v_after->'depts')='object'
     and v_after->'depts'->'ss3-business' is null
     and jsonb_typeof(v_ss2_business)='object' then
    v_after := jsonb_set(
      v_after,
      '{depts}',
      coalesce(v_after->'depts','{}'::jsonb)
        || jsonb_build_object(
          'ss3-business',
          jsonb_set(v_ss2_business,'{label}',to_jsonb('SS3 - Business'::text),true)
        ),
      true
    );
  end if;

  if v_after is distinct from v_before then
    update public.settings
    set value=v_after::text
    where key='app_config';
    insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,before_data,after_data,details)
    values('system','registry_v2_migration','configuration.ss2_business_normalized','setting','app_config',
      jsonb_build_object('promotionTarget',v_before->'promotionCfg'->'ss2-business'->>'target','hasSs3Business',v_before->'depts' ? 'ss3-business'),
      jsonb_build_object('promotionTarget',v_after->'promotionCfg'->'ss2-business'->>'target','hasSs3Business',v_after->'depts' ? 'ss3-business'),
      jsonb_build_object('preservedUnrelatedConfiguration',true));
  end if;
end
$migration$;

create or replace function wts_internal.school_registry_configuration_warnings()
returns jsonb
language plpgsql
stable
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_warnings jsonb := '[]'::jsonb;
  v_raw text;
  v_config jsonb;
  v_target text;
  v_current jsonb;
  v_missing_stage integer := 0;
  v_missing_main integer := 0;
  v_missing_subject integer := 0;
begin
  select s.value into v_raw from public.settings s where s.key = 'app_config' limit 1;
  if v_raw is null then
    v_warnings := v_warnings || jsonb_build_array(jsonb_build_object(
      'code','APP_CONFIG_MISSING',
      'message','The official app configuration is missing; verify promotion rules before a session transition.'
    ));
    v_config := '{}'::jsonb;
  else
    begin
      v_config := v_raw::jsonb;
    exception when others then
      v_config := '{}'::jsonb;
      v_warnings := v_warnings || jsonb_build_array(jsonb_build_object(
        'code','APP_CONFIG_INVALID',
        'message','The official app configuration is not valid JSON; no transition may guess promotion destinations.'
      ));
    end;
  end if;

  v_target := nullif(trim(v_config->'promotionCfg'->'ss2-business'->>'target'),'');
  if v_target is distinct from 'ss3-business' then
    v_warnings := v_warnings || jsonb_build_array(jsonb_build_object(
      'code','SS2_BUSINESS_PROMOTION_TARGET_REQUIRED',
      'message','SS2 Business must promote to SS3 Business before transition.',
      'configuredTarget',v_target,
      'requiredTarget','ss3-business'
    ));
  end if;

  select count(*) into v_missing_stage
  from public.school_classes c
  where c.is_active and lower(c.class_key) not like 'archive-%' and c.stage_code is null;
  if v_missing_stage > 0 then
    v_warnings := v_warnings || jsonb_build_array(jsonb_build_object(
      'code','CLASS_STAGE_CONFIGURATION_INCOMPLETE',
      'message','Some active classes have no normalized stage and are excluded from stage-scoped reads.',
      'count',v_missing_stage
    ));
  end if;

  v_current := public.school_academic_current();
  if nullif(v_current->>'academic_session','') is null or nullif(v_current->>'term','') is null then
    v_warnings := v_warnings || jsonb_build_array(jsonb_build_object(
      'code','ACADEMIC_CONTEXT_INCOMPLETE',
      'message','The official academic session or term is not configured.'
    ));
  else
    select count(*) into v_missing_main
    from public.school_classes c
    where c.is_active and lower(c.class_key) not like 'archive-%'
      and not exists (
        select 1 from public.school_staff_class_allocations a
        where a.class_key = c.class_key
          and a.academic_session = v_current->>'academic_session'
          and a.term_name = v_current->>'term'
          and a.responsibility = 'class_teacher'
          and a.allocation_status = 'active'
          and a.effective_from <= now()
          and (a.effective_until is null or a.effective_until > now())
      );
    if v_missing_main > 0 then
      v_warnings := v_warnings || jsonb_build_array(jsonb_build_object(
        'code','INCOMPLETE_MAIN_TEACHER_ALLOCATIONS',
        'message','Some active classes do not have an active main class teacher.',
        'count',v_missing_main
      ));
    end if;

    select count(*) into v_missing_subject
    from public.result_subject_catalog r
    join public.school_classes c on c.class_key = r.class_key and c.is_active
    where r.active and not exists (
      select 1 from public.school_staff_subject_allocations a
      where a.class_key = r.class_key
        and a.subject_index = r.subject_index
        and a.academic_session = v_current->>'academic_session'
        and a.term_name = v_current->>'term'
        and a.allocation_status = 'active'
        and a.effective_from <= now()
        and (a.effective_until is null or a.effective_until > now())
    );
    if v_missing_subject > 0 then
      v_warnings := v_warnings || jsonb_build_array(jsonb_build_object(
        'code','INCOMPLETE_SUBJECT_ALLOCATIONS',
        'message','Some active class subjects do not have an active subject staff allocation.',
        'count',v_missing_subject
      ));
    end if;
  end if;

  return v_warnings;
end;
$function$;

revoke all on function wts_internal.school_registry_configuration_warnings() from public, anon, authenticated;
