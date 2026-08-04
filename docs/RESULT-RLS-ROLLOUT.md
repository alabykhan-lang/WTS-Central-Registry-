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
| `user_profiles` | `admin.users.read` | `admin.role.update` | `school_result_api` | `20260804131000` | Yes |
| `invite_codes` | `admin.invite.read` | `admin.invite.rotate` | `school_result_api` | `20260804131100` | Yes |
| `settings` | settings adapter | settings adapter | `school_result_settings_read`, `school_result_app_config_update` | `20260804131200` | Yes |
| `published_subjects` | protected Result read | publish/unpublish adapter | `school_result_read_api`, `school_result_api` | `20260804131300` | Yes |
| `scores` | protected Result read | `scores.enter` adapter | `school_result_read_api`, `school_result_api` | `20260804131400` | Yes |
| `remarks` | protected Result read | `school_result_remarks_update` | protected Result adapters | `20260804131500` | Yes |
| `traits` | protected Result read | `school_result_traits_update` | protected Result adapters | `20260804131600` | Yes |
| `fees` | protected Result read | `school_result_fees_update` | protected Result adapters | `20260804131700` | Yes |
| `students` | protected Result read | `students.upsert`, `students.archive` | `school_result_read_api`, `school_result_api` | `20260804131800` | Yes |

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
