# WTS Identity and Access Integration Rollback Plan

## Scope

The unified workspace and recovery correction is additive. It changes no student, guardian, staff-person, grant, score or report-card record by default. The new migration adds guarded functions, internal recovery logic and permission-filtered workspace reads.

## Safe rollback order

1. Stop linking users to the affected WTS Workspace deployment if a user-facing issue appears.
2. Keep the pre-existing Central Registry login and separately protected Result Portal available.
3. Remove the bootstrap environment secret immediately if bootstrap recovery was initiated and recovery is not continuing. Do not publish or retain any temporary credential in source control or logs.
4. Revoke execute from `school_identity_issue_temporary_password`, `school_identity_bootstrap_reset` and `school_identity_bootstrap_reset_with_actor` for the service role if the recovery API must be stopped.
5. Disable the platform identity/access API routes or deploy the prior platform build if the server route is at fault. Preserve audit events.
6. If necessary, restore the previous `school_staff_workspace_read_api` implementation only after checking that the new module visibility response is no longer consumed by the deployed platform.
7. Do not drop `school_identity_accounts`, `school_identity_credentials`, staff profiles, grants or audit history.
8. Any database object removal must be a separately reviewed migration in reverse dependency order. Never use an ad-hoc destructive reset against the production database.

## Recovery guarantees

- The confirmed existing identity and person ID are preserved.
- Existing grants and Result Portal credentials are not recreated or replaced by rollback.
- Reset audit records are retained.
- Reset sessions are invalidated by the recovery functions; rollback does not silently reactivate them.
- Password hashes are not exported or restored through repository files.
- Existing Result data and report-card generation remain untouched.

## Bootstrap-specific recovery

The bootstrap function refuses a second issuance after its metadata is marked. If the owner receives a temporary credential but cannot complete recovery, the owner should remove the bootstrap environment secret, preserve the audit event and obtain an explicitly approved next step. No second super-admin account should be created, and no direct hash manipulation should be used.

## Result Portal boundary

The legacy Result Portal’s RLS-disabled direct browser access is not changed by this rollback plan. Its hardening release must have its own staged migration and rollback because enabling RLS before protected compatibility APIs are ready could interrupt live result operations.
