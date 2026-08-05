# WTS Staff Identity and Access Model

## Status

The Central Registry remains the authority for real staff identity, credentials, employment and module grants. The unified WTS Workspace consumes this authority; it does not create a parallel Staff or Management identity.

No staff record, person ID, password hash, Result Portal account, student record, score or report-card data is recreated by the recovery integration.

## Identity chain and current credential system

The real identity path is:

`school_people` → `staff_attendance_profiles` → `school_identity_accounts` → `school_identity_credentials`

The current staff sign-in functions are:

- `school_identity_portal_login`
- `school_identity_change_password`
- `school_identity_portal_logout`
- `school_identity_current_staff_session`

The WTS School Platform calls `school_identity_portal_login` with `p_app_code = staff_self_service`. It verifies person status, active employment, account status, credential state, lock state and an active grant before issuing an opaque transition session. Native Supabase Auth is not yet the shared staff population.

The Central Registry credential is the shared WTS staff credential used by the connected portal login adapters. Existing identity rows are reused; no second person, account or credential is created during activation.

## Confirmed existing account recovery state

The confirmed existing staff identity for the owner’s recovery procedure remains the same account and person record. Its grants are preserved. At verification time, the identity account and credential were active, compulsory password change was set, failed attempts were recorded and the previous temporary lock had expired. No password hash was exposed or changed directly.

## Grant model

`school_access_grants` is the enforceable module boundary. Effective access requires:

1. active staff identity and employment;
2. active identity account and credential;
3. active, currently valid module grant;
4. exact action permission; and
5. active class/subject scope where a specialist system requires it.

Role labels and role-permission templates are descriptive. Assigning a role does not create an effective module grant.

The unified workspace filters its module directory from active grants. Management authority is represented by permissions such as `access.manage`; there is no separate management workspace.

## One-time activation and password reset

Migration `20260805173000_staff_activation_recovery_profile_completion` adds `school_identity_recovery_tokens` and three guarded functions:

- `school_identity_recovery_issue_service`, service-role only, accepts a Staff Number/email for activation or a verified email for reset;
- `school_identity_recovery_consume`, anonymous execution with a one-time bearer token and new password;
- `school_identity_recovery_mark_delivery`, service-role only, records email delivery state.

Only a SHA-256 token digest is stored. The raw token is returned to the server-side mail adapter only, expires after 30 minutes, is single-use, invalidates earlier requests, and is never written to logs, audit metadata or browser storage. Completion reuses the existing identity account and credential row, clears compulsory-change/lock state, revokes old opaque sessions and records a safe audit event.

The browser temporary-credential issuer is retired. Management approves employment and receives activation status; it does not choose, view or manually set a staff password. Production email delivery requires the server-only `SUPABASE_SERVICE_ROLE_KEY`, `RESEND_API_KEY` and `WTS_EMAIL_FROM` environment variables.

## One-time bootstrap procedure

The bootstrap path targets only the confirmed existing account and refuses any other staff number/email pair. It does not create a second administrator or alter grants.

The previous bootstrap recovery route remains outside this repository for controlled emergency use. It is not part of the normal staff journey. Normal existing-staff activation and forgotten-password recovery use the public `/activate.html` page and the verified registered email.

## Session invalidation and audit

Password reset, password activation and account/grant suspension suspend the existing opaque attendance-admin client sessions for the affected person and replace the stored secret hash with a new random value. Logout also suspends the session. Subsequent workspace reads must fail with an inactive-session result.

Audit entries retain the actor, action, target, reason, request ID and safe state transition. They intentionally omit passwords and password hashes.

## Result transition

The Result Portal remains operational with central WTS login as its normal public choice. Central Registry grants determine whether the Results module is shown in WTS Workspace. The old compatibility handler is retained only behind the audited, grant-checked `/api/result-emergency` route while the remaining Result security work is paused.

## Remaining security risks

- The legacy Result Portal directly accesses core tables while RLS is disabled; this requires a dedicated compatibility migration.
- The current opaque transition session is not the final shared httpOnly authentication architecture.
- Production email-provider environment configuration must be completed before activation/reset emails can be delivered.
- Off-boarding and delegated approval policy still require management confirmation.
