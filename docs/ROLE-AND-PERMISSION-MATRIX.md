# WTS Role and Permission Matrix

## Governing rule

Management titles and system roles are descriptive. They do not automatically create access. The effective decision is:

`active identity + active employment + active account + current module grant + exact action + scope`

The unified destination is `/workspace`. “Staff” and “management” are not competing workspaces; management authority is represented by the grants below.

## Module matrix

| Module | Effective visibility | Current integration state |
| --- | --- | --- |
| My Profile | `staff_self_service` plus profile permission | Operational identity link |
| Central Registry | `central_registry` or Registry permission | Under continued development in unified flow |
| Results | active `results` grant | Existing Result Portal operational; second login remains |
| Attendance | attendance grant/action | In development |
| Notifications | notification grant/action | In development |
| Reports | reporting permission | In development |
| Public Website Management | website-content permission | In development |
| System Administration | `access.manage` or explicit system-administration permission | Protected identity/access controls |

The WTS Workspace only renders modules from the current active-grant response. Specialist APIs and direct protected actions must repeat these checks server-side.

## Responsibility labels

| System role | Typical responsibility | Automatic access |
| --- | --- | --- |
| Teacher | Approved teaching work | No |
| Class Teacher | Approved class responsibility | No |
| Principal | Approved oversight | No |
| Vice Principal | Delegated oversight | No |
| Proprietor | Approved executive oversight | No |
| Registry Administrator | Registry, admissions and staff identity | No |
| Results Administrator | Results processing and release controls | No |
| Attendance Administrator | Attendance operations | No |
| Communications Administrator | Approved school communications | No |
| Super Administrator | Elevated platform administration | No |

## Permission catalogue

| Module | Actions |
| --- | --- |
| Staff Profile | `profile.view`, `profile.update` |
| Central Registry | `registry.read`, `registry.manage`, `admissions.manage` |
| Result Entry | `result_entry.view`, `result_entry.create`, `result_entry.edit`, `result_entry.submit` |
| Result Review | `result_review.review` |
| Result Approval | `result_approval.approve` |
| Report Cards | `report_cards.generate` |
| Result Publishing | `result_publishing.publish` |
| Attendance | `attendance.view`, `attendance.create`, `attendance.edit`, `attendance.review`, `attendance.export` |
| Notifications | `notifications.view`, `notifications.create`, `notifications.edit`, `notifications.approve`, `notifications.publish` |
| Reports | `reports.view`, `reports.export` |
| Public Website Content | `public_website_content.view`, `public_website_content.create`, `public_website_content.edit`, `public_website_content.publish` |
| System Administration | `access.manage`, `system_administration.view`, `system_administration.administer`, `staff_management.administer` |

## Identity recovery permission

Password reset is not a generic role privilege. The guarded server route requires:

1. an active Central Registry opaque session;
2. the current person’s effective `access.manage` permission;
3. an existing active target staff identity;
4. a reason of sufficient detail; and
5. the database reset function’s audit and session-invalidation controls.

The temporary credential is returned once to the authorised management session, is compulsory-change only, and is never written to logs or audit metadata. The old anonymous identity-admin write path is not an allowed fallback.

## Result scope matrix

| Capability | Required grant and scope |
| --- | --- |
| View assigned classes/subjects | active Results grant and matching scope |
| Enter/edit score | exact Result Entry action plus matching class and subject scope |
| Submit work | `result_entry.submit` plus authorised scope |
| Review | `result_review.review` plus approved review scope |
| Approve | `result_approval.approve` |
| Generate cards | `report_cards.generate` |
| Publish | `result_publishing.publish` |

The legacy Result Portal has not yet adopted this server-side matrix. These permissions are the contract for its hardening release and are not presented as proof that the legacy direct-table browser client is secure.

## Current data policy

No new users, roles, action grants, class scopes or subject scopes were seeded for this correction. Existing real grants remain the source of workspace visibility.
