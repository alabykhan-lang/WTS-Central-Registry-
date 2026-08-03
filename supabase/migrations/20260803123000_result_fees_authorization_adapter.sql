-- Result fee writes are moved behind the same central session boundary.
-- This migration changes no existing rows and is reversible at the code layer.

create or replace function public.school_result_fees_update(
  p_session_id uuid,
  p_session_secret text,
  p_student_id uuid,
  p_class_key text,
  p_term text,
  p_academic_session text,
  p_total numeric default null,
  p_paid numeric default null,
  p_debt numeric default null
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_auth jsonb;
begin
  if nullif(trim(coalesce(p_class_key, '')), '') is null
     or nullif(trim(coalesce(p_term, '')), '') is null
     or nullif(trim(coalesce(p_academic_session, '')), '') is null then
    return jsonb_build_object('ok', false, 'code', 'RESULT_FEE_PAYLOAD_INVALID');
  end if;

  v_auth := public.school_result_authorize(
    p_session_id,
    p_session_secret,
    'results.manage',
    trim(p_class_key),
    null,
    trim(p_academic_session),
    trim(p_term)
  );
  if coalesce((v_auth ->> 'ok')::boolean, false) is not true then
    return v_auth;
  end if;

  if p_total is not null and p_total < 0
     or p_paid is not null and p_paid < 0
     or p_debt is not null and p_debt < 0 then
    return jsonb_build_object('ok', false, 'code', 'RESULT_FEE_VALUE_INVALID');
  end if;

  if not exists (
    select 1 from public.students s
    where s.id = p_student_id
      and s.class_key = trim(p_class_key)
      and coalesce(s.archived, false) = false
  ) then
    return jsonb_build_object('ok', false, 'code', 'RESULT_STUDENT_CLASS_MISMATCH');
  end if;

  insert into public.fees(student_id, class_key, term, total, paid, debt)
  values (p_student_id, trim(p_class_key), trim(p_term), p_total, p_paid, p_debt)
  on conflict (student_id, term) do update
  set class_key = excluded.class_key,
      total = excluded.total,
      paid = excluded.paid,
      debt = excluded.debt;

  insert into public.school_registry_audit(
    actor_type, actor_id, action, entity_type, entity_id, details
  )
  values (
    'result_session',
    v_auth ->> 'person_id',
    'result.fees.upserted',
    'fees',
    p_student_id::text,
    jsonb_build_object('class_key', trim(p_class_key), 'term', trim(p_term))
  );

  return jsonb_build_object(
    'ok', true,
    'code', 'RESULT_FEES_SAVED',
    'student_id', p_student_id,
    'class_key', trim(p_class_key),
    'term', trim(p_term)
  );
end;
$function$;

revoke all on function public.school_result_fees_update(uuid, text, uuid, text, text, text, numeric, numeric, numeric) from public;
grant execute on function public.school_result_fees_update(uuid, text, uuid, text, text, text, numeric, numeric, numeric) to anon, authenticated, service_role;
