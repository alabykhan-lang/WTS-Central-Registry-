# WTS Role and Permission Matrix

## Rule of operation

Job title and system role are descriptive. They do not by themselves create access. A staff member must have:

1. an active staff identity and employment record;
2. an active identity account and credential;
3. an active module grant;
4. the exact permitted action; and
5. for Result Management, an active class/subject scope where applicable.

| System role | Typical responsibility | Automatic access? |
| --- | --- | --- |
| Teacher | Teaching work | No |
| Class Teacher | Class-level responsibility | No |
| Principal | Approved academic/operational oversight | No |
| Vice Principal | Delegated oversight | No |
| Proprietor | Approved executive oversight | No |
| Registry Administrator | Registry, admissions and staff identity work | No |
| Results Administrator | Results processing and release controls | No |
| Attendance Administrator | Attendance operations | No |
| Communications Administrator | Approved school communications | No |
| Super Administrator | Elevated platform administration | No |

## Permission catalogue

| Module | Supported actions |
| --- | --- |
| Staff Profile | view, edit |
| Classes and Subjects | view |
| Result Entry | view, create, edit, submit |
| Result Review | view, review |
| Result Approval | view, approve |
| Report Card Generation | view, generate, export |
| Result Publishing | view, publish |
| Central Registry | view, administer |
| Student Records | view, create, edit, export |
| Staff Management | view, create, edit, administer |
| Attendance | view, create, edit, review, export |
| Notifications | view, create, edit, approve, publish |
| Reports | view, export |
| Public Website Content | view, create, edit, publish |
| System Administration | view, administer |

The action names map to `school_permission_catalog.permission_code`; the management interface sends only catalogued codes to the protected write API.

## Result scope matrix

| User capability | Required grant |
| --- | --- |
| View assigned classes/subjects | active `results` module grant and scope |
| Enter or edit a score | `result_entry.view` plus `result_entry.create`/`result_entry.edit` and matching active class + subject scope |
| Submit work | `result_entry.submit` and authorised scope |
| Review work | `result_review.review` and approved review scope when the Result API is hardened |
| Approve results | `result_approval.approve` |
| Generate report cards | `report_cards.generate` |
| Publish results | `result_publishing.publish` |

The legacy Result Portal has not yet adopted these server-side checks. These grants already constrain the WTS Workspace and are the contract for its hardening release; they do not falsely claim to secure the legacy direct-table client.

## Current real assignments

No new role, action, class or subject assignments were seeded in this phase. Existing active Result Portal grants were preserved as-is. Management must make each new assignment through Central Registry with a reason and, where relevant, dates.
