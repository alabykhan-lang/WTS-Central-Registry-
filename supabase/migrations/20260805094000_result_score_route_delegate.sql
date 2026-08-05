-- Route the retained generic Result API score action through the
-- authoritative transactional score writer. Other legacy API actions retain
-- their existing compatibility implementation; the legacy function is no
-- longer callable by browser roles.

begin;

alter function public.school_result_api(uuid, text, text, jsonb)
  rename to school_result_api_legacy;

create or replace function public.school_result_api(
  p_session_id uuid,
  p_session_secret text,
  p_action text,
  p_payload jsonb default '{}'::jsonb
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_action text := lower(trim(coalesce(p_action, '')));
  v_payload jsonb := coalesce(p_payload, '{}'::jsonb);
  v_student_id uuid;
  v_subject_index integer;
  v_ca1 numeric;
  v_ca2 numeric;
  v_ca3 numeric;
  v_exam numeric;
begin
  if v_action = 'scores.enter' then
    begin
      v_student_id := (v_payload ->> 'student_id')::uuid;
      v_subject_index := nullif(v_payload ->> 'subject_index', '')::integer;
      v_ca1 := nullif(v_payload ->> 'ca1', '')::numeric;
      v_ca2 := nullif(v_payload ->> 'ca2', '')::numeric;
      v_ca3 := nullif(v_payload ->> 'ca3', '')::numeric;
      v_exam := nullif(v_payload ->> 'exam', '')::numeric;
    exception when others then
      return jsonb_build_object('ok', false, 'code', 'RESULT_SCORE_PAYLOAD_INVALID');
    end;

    return public.school_result_score_update(
      p_session_id,
      p_session_secret,
      v_student_id,
      v_payload ->> 'class_key',
      v_subject_index,
      v_payload ->> 'term',
      v_payload ->> 'academic_session',
      v_ca1, v_ca2, v_ca3, v_exam
    );
  end if;

  return public.school_result_api_legacy(
    p_session_id, p_session_secret, p_action, v_payload
  );
end;
$function$;

revoke all on function public.school_result_api(uuid, text, text, jsonb)
  from public, authenticated;

grant execute on function public.school_result_api(uuid, text, text, jsonb)
  to anon, authenticated, service_role;

revoke all on function public.school_result_api_legacy(uuid, text, text, jsonb)
  from public, anon, authenticated;

grant execute on function public.school_result_api_legacy(uuid, text, text, jsonb)
  to service_role;

commit;
