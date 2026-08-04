-- Transitional Central Registry adapter for the existing management session.
-- The underlying credential routine remains the only password-generation path;
-- it hashes in the database, clears lock state, revokes sessions and audits the
-- initiating administrator. No password hash is returned.
create or replace function public.school_identity_management_write_api(
  p_client_code text,
  p_client_secret text,
  p_action text,
  p_payload jsonb default '{}'::jsonb
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_staff_id uuid;
  v_reason text := nullif(trim(coalesce(p_payload ->> 'reason', '')), '');
begin
  if lower(trim(coalesce(p_action, ''))) <> 'issuetemporarycredential' then
    return jsonb_build_object('ok', false, 'code', 'UNKNOWN_ACTION');
  end if;
  begin
    v_staff_id := (p_payload ->> 'staffId')::uuid;
  exception when others then
    return jsonb_build_object('ok', false, 'code', 'INVALID_STAFF_ID');
  end;
  if v_staff_id is null then
    return jsonb_build_object('ok', false, 'code', 'INVALID_STAFF_ID');
  end if;
  if v_reason is null or length(v_reason) < 8 then
    return jsonb_build_object('ok', false, 'code', 'RESET_REASON_REQUIRED');
  end if;
  return public.school_identity_issue_temporary_password(
    p_client_code,
    p_client_secret,
    v_staff_id,
    left(v_reason, 500)
  );
end;
$function$;

revoke all on function public.school_identity_management_write_api(text, text, text, jsonb) from public, authenticated;
grant execute on function public.school_identity_management_write_api(text, text, text, jsonb) to anon;