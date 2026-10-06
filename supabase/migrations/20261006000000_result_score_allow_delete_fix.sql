CREATE OR REPLACE FUNCTION public.school_result_score_update(
  p_session_id uuid,
  p_session_secret text,
  p_student_id uuid,
  p_class_key text,
  p_subject_index integer,
  p_term text,
  p_academic_session text,
  p_ca1 numeric,
  p_ca2 numeric,
  p_ca3 numeric,
  p_exam numeric
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
AS $$
DECLARE
  v_person_id uuid;
  v_staff_id uuid;
  v_request_id uuid := gen_random_uuid();
  v_failure_code text;
  v_score_id uuid;
  v_before jsonb;
  v_after jsonb;
  v_action_type text;
BEGIN
  SELECT person_id, staff_id, failure_code
    INTO v_person_id, v_staff_id, v_failure_code
  FROM public.school_sso_session_validate(p_session_id, p_session_secret, 'result.score.write');

  IF v_failure_code IS NOT NULL THEN
    RETURN jsonb_build_object(
      'ok', false,
      'code', v_failure_code,
      'request_id', v_request_id
    );
  END IF;

  SELECT to_jsonb(s), s.id
    INTO v_before, v_score_id
  FROM public.scores s
  WHERE s.student_id = p_student_id
    AND s.class_key = trim(p_class_key)
    AND s.subject_index = p_subject_index
    AND s.academic_session = trim(p_academic_session)
    AND s.term = trim(p_term)
  FOR UPDATE;

  IF p_ca1 IS NULL AND p_ca2 IS NULL AND p_ca3 IS NULL AND p_exam IS NULL THEN
    DELETE FROM public.scores
    WHERE student_id = p_student_id
      AND class_key = trim(p_class_key)
      AND subject_index = p_subject_index
      AND academic_session = trim(p_academic_session)
      AND term = trim(p_term)
    RETURNING id INTO v_score_id;
    v_after := NULL;
  ELSE
    INSERT INTO public.scores(
      student_id, class_key, subject_index, academic_session, term, ca1, ca2, ca3, exam
    ) VALUES (
      p_student_id, trim(p_class_key), p_subject_index, trim(p_academic_session), trim(p_term),
      p_ca1, p_ca2, p_ca3, p_exam
    )
    ON CONFLICT (student_id, class_key, subject_index, academic_session, term) DO UPDATE
    SET class_key = EXCLUDED.class_key,
        ca1 = EXCLUDED.ca1,
        ca2 = EXCLUDED.ca2,
        ca3 = EXCLUDED.ca3,
        exam = EXCLUDED.exam
    RETURNING id INTO v_score_id;

    SELECT to_jsonb(s)
      INTO v_after
    FROM public.scores s
    WHERE s.id = v_score_id;
  END IF;

  v_action_type := CASE
    WHEN v_before IS NULL THEN 'score_entry'
    WHEN (v_before ->> 'ca1') IS DISTINCT FROM (v_after ->> 'ca1')
      OR (v_before ->> 'ca2') IS DISTINCT FROM (v_after ->> 'ca2')
      OR (v_before ->> 'ca3') IS DISTINCT FROM (v_after ->> 'ca3')
      OR (v_before ->> 'exam') IS DISTINCT FROM (v_after ->> 'exam')
      THEN 'score_correction'
    ELSE 'score_save_confirmed'
  END;

  INSERT INTO public.school_result_score_audit(
    request_id, actor_person_id, staff_id, student_id, class_key,
    subject_index, academic_session, term, component, old_value,
    new_value, old_record, new_record, action_type, source_application,
    success, failure_code
  )
  SELECT
    v_request_id, v_person_id, v_staff_id, p_student_id, trim(p_class_key),
    p_subject_index, trim(p_academic_session), trim(p_term), x.component,
    x.old_value, x.new_value, v_before, v_after, v_action_type,
    'result_portal', true, NULL
  FROM (
    VALUES
      ('ca1'::text, nullif(v_before ->> 'ca1', '')::numeric, nullif(v_after ->> 'ca1', '')::numeric),
      ('ca2'::text, nullif(v_before ->> 'ca2', '')::numeric, nullif(v_after ->> 'ca2', '')::numeric),
      ('ca3'::text, nullif(v_before ->> 'ca3', '')::numeric, nullif(v_after ->> 'ca3', '')::numeric),
      ('exam'::text, nullif(v_before ->> 'exam', '')::numeric, nullif(v_after ->> 'exam', '')::numeric)
  ) AS x(component, old_value, new_value);

  INSERT INTO public.school_registry_audit(
    actor_type, actor_id, action, entity_type, entity_id, request_id,
    before_data, after_data, details
  ) VALUES (
    'result_session', v_person_id::text,
    CASE WHEN v_action_type = 'score_entry'
      THEN 'result.score.entered'
      ELSE 'result.score.corrected'
    END,
    'scores', coalesce(v_score_id, (v_before->>'id')::uuid, p_student_id)::text, v_request_id, v_before, v_after,
    jsonb_build_object(
      'staff_id', v_staff_id,
      'person_id', v_person_id,
      'student_id', p_student_id,
      'class_key', trim(p_class_key),
      'subject_index', p_subject_index,
      'academic_session', trim(p_academic_session),
      'term', trim(p_term),
      'source_application', 'result_portal',
      'success', true
    )
  );

  RETURN jsonb_build_object(
    'ok', true,
    'code', 'RESULT_SCORE_SAVED',
    'request_id', v_request_id,
    'persisted', true,
    'student_id', p_student_id,
    'class_key', trim(p_class_key),
    'subject_index', p_subject_index,
    'term', trim(p_term),
    'academic_session', trim(p_academic_session),
    'score', jsonb_build_object(
      'id', coalesce(v_after ->> 'id', v_before ->> 'id'),
      'student_id', p_student_id,
      'class_key', trim(p_class_key),
      'subject_index', p_subject_index,
      'academic_session', trim(p_academic_session),
      'term', trim(p_term),
      'ca1', v_after -> 'ca1',
      'ca2', v_after -> 'ca2',
      'ca3', v_after -> 'ca3',
      'exam', v_after -> 'exam'
    )
  );
END;
$$;
