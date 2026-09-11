-- PostgreSQL's ARE regex engine rejects bounded repetitions above 255.
-- The shared SSO exchange function previously used {16,512} for state and
-- nonce, so every otherwise-valid exchange failed before the authorization
-- code could be consumed. Keep the 16..512 length contract, but validate the
-- allowed alphabet separately with an unbounded character-class expression.

do $migration$
declare
  v_definition text;
  v_original text;
begin
  select pg_get_functiondef(p.oid)
    into v_definition
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public'
    and p.proname = 'school_sso_authorization_code_exchange'
    and pg_get_function_identity_arguments(p.oid) = 'p_code text, p_client_id text, p_redirect_uri text, p_code_verifier text, p_state text, p_nonce text';

  if v_definition is null then
    raise exception 'school_sso_authorization_code_exchange function is missing';
  end if;

  v_original := v_definition;
  v_definition := replace(
    v_definition,
    'coalesce(trim(p_state), '''') !~ ''^[A-Za-z0-9._~-]{16,512}$''',
    '(length(trim(coalesce(p_state, ''''))) not between 16 and 512 or trim(coalesce(p_state, '''')) !~ ''^[A-Za-z0-9._~-]+$'')'
  );
  v_definition := replace(
    v_definition,
    'coalesce(trim(p_nonce), '''') !~ ''^[A-Za-z0-9._~-]{16,512}$''',
    '(length(trim(coalesce(p_nonce, ''''))) not between 16 and 512 or trim(coalesce(p_nonce, '''')) !~ ''^[A-Za-z0-9._~-]+$'')'
  );

  if v_definition = v_original then
    raise exception 'SSO state/nonce validation pattern was not found';
  end if;

  execute v_definition;
end
$migration$;
