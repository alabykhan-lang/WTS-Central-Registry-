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

The Central Registry credential is independent of the legacy Result Portal password. Existing Result credentials are not copied, reset or assumed to match.

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

## Protected password reset

Migration `20260801160000_secure_identity_recovery_and_unified_workspace` adds:

- `wts_internal.issue_temporary_credential`, a non-exposed implementation function;
- `school_identity_issue_temporary_password`, callable only by the server-side service-role route after the live admin session is checked;
- `school_identity_bootstrap_reset`, restricted to the one confirmed existing bootstrap target;
- `school_identity_bootstrap_reset_with_actor`, the service-only bootstrap wrapper used by the private operator recovery route;
- a revised password-change function that clears the compulsory state and records bootstrap completion without storing a password.

The reset operates on the existing account and credential rows. It issues a temporary credential once, sets `must_change_password`, clears failed attempts and expired locks, preserves grants and person IDs, invalidates opaque sessions for the target identity, and records actor, timestamp, reason, request ID and safe before/after status in `school_registry_audit`.

Neither password hashes nor plain-text temporary passwords are stored in audit metadata, repository files, browser storage or application logs. The old public execution privilege on `school_identity_admin_write_api` is revoked so its password-generating reset path cannot be called by anonymous or ordinary authenticated browser clients.

## One-time bootstrap procedure

The bootstrap path targets only the confirmed existing account and refuses any other staff number/email pair. It does not create a second administrator or alter grants.

The authorised owner must set the server-only Supabase service key and a newly generated one-time bootstrap secret in the WTS School Platform production environment. From a private device, the owner opens the unlinked `/portal/recovery` route, supplies that secret and an operational reason, receives the temporary credential once through the private response, signs in, completes the forced password change and immediately removes the bootstrap secret from the deployment environment. Account metadata records issuance/completion and prevents a second issuance.

The temporary credential is never included in source control, Vercel logs, public documentation or audit metadata.

## Session invalidation and audit

Password reset, password activation and account/grant suspension suspend the existing opaque attendance-admin client sessions for the affected person and replace the stored secret hash with a new random value. Logout also suspends the session. Subsequent workspace reads must fail with an inactive-session result.

Audit entries retain the actor, action, target, reason, request ID and safe state transition. They intentionally omit passwords and password hashes.

## Result transition

The Result Portal remains operational with central WTS login as its normal public choice. Central Registry grants determine whether the Results module is shown in WTS Workspace. The old compatibility handler is retained only behind the audited, grant-checked `/api/result-emergency` route while the remaining Result security work is paused.

## Remaining security risks

- The legacy Result Portal directly accesses core tables while RLS is disabled; this requires a dedicated compatibility migration.
- The current opaque transition session is not the final shared httpOnly authentication architecture.
- Bootstrap environment configuration must be completed by the authorised owner and removed after recovery.
- Off-boarding and delegated approval policy still require management confirmation.
