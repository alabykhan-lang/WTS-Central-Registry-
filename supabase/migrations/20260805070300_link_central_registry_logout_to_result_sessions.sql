create or replace function public.school_identity_session_revoke(
  p_session_id uuid,
  p_session_secret text,
  p_reason text default 'SESSION_LOGOUT'
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, extensions, public
as $function$
declare
  v_session public.school_identity_sessions%rowtype;
  v_reason text := left(coalesce(nullif(trim(p_reason), ''), 'SESSION_LOGOUT'), 160);
  v_linked_count integer := 0;
  v_linked public.school_identity_sessions%rowtype;
begin
  select s.* into v_session
  from public.school_identity_sessions s
  where s.id = p_session_id and s.revoked_at is null
  for update;
  if not found or coalesce(p_session_secret, '') = ''
     or encode(digest(p_session_secret, 'sha256'), 'hex') <> v_session.secret_hash then
    return jsonb_build_object('ok', false, 'code', 'RESULT_SESSION_NOT_ACTIVE');
  end if;

  update public.school_identity_sessions
  set revoked_at = now(), revocation_reason = v_reason, last_seen_at = now()
  where id = v_session.id;

  insert into public.school_registry_audit (
    actor_type, actor_id, action, entity_type, entity_id, details
  )
  values (
    'staff_session', v_session.person_id::text, 'identity.session.revoked',
    'school_identity_sessions', v_session.id::text,
    jsonb_build_object('reason', v_reason)
  );

  if v_session.target_app_code in ('staff_self_service', 'central_registry') then
    for v_linked in
      select s.*
      from public.school_identity_sessions s
      where s.target_app_code = 'results'
        and s.revoked_at is null
        and s.person_id = v_session.person_id
        and s.identity_account_id = v_session.identity_account_id
        and (
          v_session.target_app_code = 'central_registry'
          or s.metadata ->> 'source_workspace_session_id' = v_session.id::text
        )
      for update
    loop
      update public.school_identity_sessions
      set revoked_at = now(),
          revocation_reason = 'LINKED_WTS_SESSION_REVOKED',
          last_seen_at = now()
      where id = v_linked.id;

      insert into public.school_registry_audit (
        actor_type, actor_id, action, entity_type, entity_id, details
      )
      values (
        'staff_session', v_session.person_id::text,
        'identity.result_session.linked_revoked',
        'school_identity_sessions', v_linked.id::text,
        jsonb_build_object(
          'source_session_id', v_session.id,
          'source_app_code', v_session.target_app_code,
          'reason', v_reason
        )
      );
      v_linked_count := v_linked_count + 1;
    end loop;
  end if;

  return jsonb_build_object(
    'ok', true,
    'code', 'IDENTITY_SESSION_REVOKED',
    'linked_result_sessions_revoked', v_linked_count
  );
end;
$function$;

revoke execute on function public.school_identity_session_revoke(uuid, text, text) from public;
grant execute on function public.school_identity_session_revoke(uuid, text, text) to anon, authenticated;
