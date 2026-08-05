-- Recovery tokens are accessed only through the three security-definer
-- functions. Do not expose direct table DML to a browser or service client.
revoke all on table public.school_identity_recovery_tokens from public, anon, authenticated, service_role;
