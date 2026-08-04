# Result RLS Rollout

## Policy

The Result Portal no longer needs browser table privileges for the nine legacy
Result tables listed below. The protected Result RPCs run as security-definer
functions owned by `postgres`, validate the WTS session and Result grant, and
apply class, subject, academic-session and term scope before returning data.

The Phase 3 policies are deny-by-default for `anon` and `authenticated`. RLS is
enabled per table. `FORCE ROW LEVEL SECURITY` is intentionally not used because
the protected adapters must read and write the tables as their controlled API
boundary. No raw session secret is returned by these adapters.

## Table Status

| Table | Reads | Writes | Protected replacement | RLS migration | Rollback prepared |
| --- | --- | --- | --- | --- | --- |
| `user_profiles` | `admin.users.read` | `admin.role.update` | `school_result_api` | `20260804131000` | Enabled, HTTP 401 direct REST |
| `invite_codes` | `admin.invite.read` | `admin.invite.rotate` | `school_result_api` | `20260804131100` | Enabled, HTTP 401 direct REST |
| `settings` | settings adapter | settings adapter | `school_result_settings_read`, `school_result_app_config_update` | `20260804131200` | Enabled, HTTP 401 direct REST |
| `published_subjects` | protected Result read | publish/unpublish adapter | `school_result_read_api`, `school_result_api` | `20260804131300` | Enabled, HTTP 401 direct REST |
| `scores` | protected Result read | `scores.enter` adapter | `school_result_read_api`, `school_result_api` | `20260804131400` | Enabled, HTTP 401 direct REST |
| `remarks` | protected Result read | `school_result_remarks_update` | protected Result adapters | `20260804131500` | Enabled, HTTP 401 direct REST |
| `traits` | protected Result read | `school_result_traits_update` | protected Result adapters | `20260804131600` | Enabled, HTTP 401 direct REST |
| `fees` | protected Result read | `school_result_fees_update` | protected Result adapters | `20260804131700` | Enabled, HTTP 401 direct REST |
| `students` | protected Result read | `students.upsert`, `students.archive` | `school_result_read_api`, `school_result_api` | `20260804131800` | Enabled, HTTP 401 direct REST |

The `classes` and `subjects` catalog tables were already behind the Central
Registry scope adapter and are not changed by this rollout. Report cards,
broadsheets, analytics, progress and exports consume protected Result reads and
server authorization before generating output.

## Verification Gate

Before each table migration, confirm the matching protected adapter exists and
the deployed Result client no longer uses the Supabase Data API for that table.
After each migration, verify RLS state, policy state, denied direct REST access,
protected endpoint authentication, and unchanged row counts. If a protected
workflow fails, stop at that table and use the rollback reference rather than
opening all Result tables again.

Rollback SQL is recorded in `supabase/rollback/RESULT-RLS-ROLLBACK.sql`.

The post-rollout counts matched the pre-rollout baseline: students 798,
scores 14303, traits 17520, remarks 757, fees 757, published subjects 300,
Result profiles 25, invite codes 1, active Result grants 25 and active Result
scopes 0. No academic or identity record was changed by the rollout.

## Central Registry Record Boundary

The management shell now sends record reads and writes to same-origin
`/api/registry-records`. That route reads the `wts_registry_session` HttpOnly
cookie and calls the session-native Central Registry adapters:

- `school_registry_admin_read_session_api`
- `school_registry_student_write_session_api`
- `school_registry_staff_write_session_api`
- `school_registry_guardian_write_session_api`

The `/staff` self-service page uses its separate `wts_staff_session` HttpOnly
cookie and `school_staff_self_service_session_api`. Neither page stores a
reusable attendance-admin client secret in browser storage. After deployment,
migration `20260804140200_revoke_legacy_registry_record_rpc_execute.sql` was
applied; the old record and self-service RPC privileges are now revoked for
`anon` and `authenticated`, and direct calls return HTTP 401.
