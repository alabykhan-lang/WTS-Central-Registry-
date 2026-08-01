# WTS Staff Identity and Access Model

## Status

Implemented as an additive Central Registry access layer. No staff record, password hash, Result Portal account, student record, score, or report-card data was migrated or replaced.

## Confirmed identity chain

The current staff identity path is:

`school_people` → `staff_attendance_profiles` → `school_identity_accounts` → `school_identity_credentials`.

The Result Portal’s existing legacy profile is linked through `school_identity_accounts.legacy_user_profile_id` and `staff_attendance_profiles.user_profile_id`.

At implementation time, every active Central Registry staff profile had all four links. Native Supabase Auth is **not** yet the shared identity source: `auth.users` contained no users. The currently working staff authentication method is the guarded Central Registry credential flow:

- `school_identity_portal_login`
- `school_identity_change_password`
- `school_identity_portal_logout`

It verifies active person status, active employment, identity-account status, credential status, password hash, lockout status and an active portal grant. It does not expose a service-role key.

## Existing authoritative fields

| Concern | Actual current source |
| --- | --- |
| Staff ID | `staff_attendance_profiles.id` and `staff_number` |
| Person identity | `school_people.id` |
| Employment status | `staff_attendance_profiles.employment_status` and `registration_status` |
| Official position | `staff_attendance_profiles.designation` |
| Staff category | `staff_attendance_profiles.staff_category` |
| Identity account | `school_identity_accounts` |
| Credential lifecycle | `school_identity_credentials` |
| Current portal grant | `school_access_grants` |
| Official person-role history | `school_person_roles` |
| Existing audit history | `school_registry_audit` |

## Access-control extension

The 20260801010000 migration adds non-identity access records only:

- `school_system_role_catalog`: assignable responsibility labels.
- `school_permission_catalog`: module/action permission codes.
- `school_system_role_permissions`: non-effective guidance templates.
- `school_staff_role_assignments`: one or more explicit system roles per person.
- `school_staff_access_scopes`: class and subject boundaries per person and module.

The subject scope reuses the existing `result_subject_catalog(class_key, subject_index)`. No subject list was invented or duplicated.

`school_access_grants` remains the enforceable module grant and now records revocation actor, time and reason. A role assignment does not automatically create a module grant. Management must grant the module and selected actions separately.

All new tables have RLS enabled and no direct browser-table policy. Browser calls use only guarded RPCs that authenticate the Central Registry session and make server-side permission decisions:

- `school_staff_workspace_read_api`
- `school_access_management_read_api`
- `school_access_management_write_api`

## Management workflow

1. Search active staff in Central Registry → Portal Access.
2. Open the staff access profile.
3. Review employment, identity-account state, current module grants, roles, scopes and audit events.
4. Optionally assign a responsibility role. This alone grants no action.
5. Grant or revoke a module; select individual permitted actions and effective/expiry dates.
6. Assign or revoke real Result Portal classes and subjects from the existing catalog.
7. Suspend or restore the Central identity account without changing its password.
8. Review the recorded audit history.

Every change records actor, timestamp, reason, before/after data and request identifier in `school_registry_audit`.

## Super-admin protection and recovery

The confirmed existing Central Registry primary administrator is preserved through the existing primary-registry grant metadata. The new management API rejects ordinary suspension or revocation of that primary authority.

Emergency recovery procedure:

1. Use the existing primary administrator’s Central Registry identity.
2. Restore a suspended account or role/module grant in Portal Access.
3. If the primary account itself is unavailable, use the Supabase project owner through a controlled database change, record the reason in `school_registry_audit`, and rotate/verify the affected credential outside source control.
4. Do not reset or disclose passwords in source code, browser URLs, documentation or audit notes.

## Public directory preparation

`staff_attendance_profiles` now has explicit public-directory approval fields:

- `public_visibility_approved`
- `public_display_name`
- `public_display_role`
- `public_display_order`
- approval actor and timestamp

An active employment record is never public by default. The current public website directory remains unchanged until a later approved synchronisation uses these fields and an approved photograph.
