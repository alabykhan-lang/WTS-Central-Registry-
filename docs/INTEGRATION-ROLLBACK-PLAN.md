# WTS Identity and Access Integration Rollback Plan

## Scope of this release

The identity/access migration is additive. It adds access-control metadata, guarded management APIs and public-directory approval fields. It does not delete or update result scores, students, guardians, existing staff profiles, existing account links or password hashes.

## Safe rollback order

1. Disable the new WTS School Platform sign-in/workspace links if a user-facing issue appears.
2. Keep the pre-existing Central Registry login and legacy Result Portal operational.
3. Revoke execute from the three new guarded RPCs if an API-level issue is found:
   - `school_staff_workspace_read_api`
   - `school_access_management_read_api`
   - `school_access_management_write_api`
4. Preserve all `school_registry_audit` events; do not delete historical audit data.
5. If required, disable use of new role/scope records in the Central Registry UI while retaining the records for investigation.
6. Only after a confirmed dependency review, drop new indexes, functions and tables in reverse dependency order. Do not remove the public-directory fields or revocation columns until the deployed application no longer references them.

## Recovery guarantees

- Existing `school_access_grants` are retained.
- Existing Central Registry primary-administrator protection remains.
- Existing staff credentials are not reset.
- Existing Result Portal tables and report-card generation are untouched.
- Result data can be verified before and after rollback with counts only; do not alter scores for testing.

## Known non-rollback item

The legacy Result Portal has RLS disabled on its core direct-access tables. This release intentionally does not turn RLS on, because doing so before replacing its direct browser calls would interrupt live result operations. Its dedicated hardening migration must be tested separately with a staged rollback plan.
