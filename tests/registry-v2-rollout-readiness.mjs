import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';

const root = new URL('../', import.meta.url);
const read = (path) => readFile(new URL(path, root), 'utf8');
const contract = JSON.parse(await read('docs/CENTRAL-REGISTRY-ARCHITECTURE-CONTRACT.json'));
const foundation = await read('supabase/migrations/20260907210000_central_registry_architecture_foundation.sql');
const policy = await read('supabase/migrations/20260907220000_registry_v2_policy_and_invariants.sql');
const config = await read('supabase/migrations/20260907220500_registry_v2_safe_configuration.sql');
const reads = await read('supabase/migrations/20260907221000_registry_v2_scoped_api.sql');
const approval = await read('supabase/migrations/20260907221500_registry_v2_registration_approval.sql');
const writes = await read('supabase/migrations/20260907222000_registry_v2_scoped_writes.sql');
const prefect = await read('supabase/migrations/20260907222500_registry_v2_prefect_workflow.sql');
const identity = await read('supabase/migrations/20260908153000_registry_v2_identity_consolidation.sql');
const pilot = await read('supabase/migrations/20260908170000_portal_pilot_and_result_hold.sql');
const business = await read('supabase/migrations/20260910085618_registry_business_and_departments.sql');
const profiles = await read('supabase/migrations/20260910085719_registry_profile_tools.sql');
const pages = await read('registry/pages.js');
const html = await read('index.html');

assert.equal(contract.acceptanceCriteria.length, 20);
assert.equal(contract.portfolios.developer.presentation, 'technical_only');
assert.equal(contract.technicalPrivilegePresentation.schoolFacingPortfolio, false);
assert.equal(contract.allocationModel.mainClassTeacherPerSessionTermClass, 1);
assert.equal(contract.allocationModel.assistantClassTeachersPerSessionTermClass, 'multiple');
assert.equal(contract.currentPrefectBootstrap.verifiedStudents, 25);
assert.equal(contract.currentPrefectBootstrap.verifiedAppointments, 35);
assert.equal(contract.currentPrefectBootstrap.multipleOfficesPerStudent, true);
assert.equal(contract.currentPrefectBootstrap.fabricatedAppointmentsAllowed, false);
assert.equal(contract.portalPolicies.attendance.entry, 'technical_account_only');
assert.equal(contract.portalPolicies.notifications.operatingMode, 'disabled');
assert.equal(contract.portalPolicies.results.operatingMode, 'read_only');

assert.match(foundation, /when 'ss2-business' then 330/);
assert.match(foundation, /when 'ss3-business' then 420/);
assert.match(foundation, /values \('ss3-business', 'SS 3 Business'/);
assert.match(foundation, /where r\.class_key = 'ss2-business'[\s\S]*on conflict \(class_key, subject_index\) do nothing/);
assert.match(config, /v_before->'promotionCfg'->'ss2-business'/);
assert.match(config, /jsonb_build_object\('target','ss3-business'\)/);
assert.match(config, /preservedUnrelatedConfiguration/);

assert.match(writes, /responsibility','class_teacher'\)\) not in \('class_teacher','assistant_class_teacher'\)/);
assert.match(writes, /STAFF_ALREADY_MAIN_TEACHER/);
assert.match(writes, /Promoted from assistant to main class teacher/);
assert.match(reads, /classAllocationHistory/);
assert.match(reads, /subjectAllocationHistory/);
assert.match(html, /multiple additional assistant teachers\/users/);

const validationMarker = prefect.indexOf('Validate the complete verified document');
const mutationMarker = prefect.indexOf('insert into public.school_portfolio_assignments');
assert.ok(validationMarker >= 0 && validationMarker < mutationMarker, 'prefect bootstrap must validate before mutation');
assert.match(prefect, /class_key like 'ss3-%'/);
assert.match(prefect, /office_name/);
assert.match(prefect, /academic_session/);
assert.match(prefect, /appointment_status','active/);
assert.match(prefect, /appointment_status','ended/);
assert.doesNotMatch(pages, /Register only appointments confirmed by the school document/);

assert.match(business, /ss2-business' then 'ss3-business/);
assert.match(business, /student\.business_stream_corrected/);
assert.match(business, /department_code/);
assert.doesNotMatch(business, /delete\s+from\s+public\.students/i);
assert.match(profiles, /school_registry_profile_session_api/);
assert.match(profiles, /DEPARTMENT_INVALID/);
assert.match(profiles, /PROFILE_PORTFOLIO_CREATED/);
assert.match(profiles, /profile_only/);
assert.match(profiles, /PORTFOLIO_SENIOR_SECONDARY_ONLY/);
assert.doesNotMatch(profiles, /delete\s+from\s+public\.(students|school_people|staff_attendance_profiles)/i);

assert.match(foundation, /coalesce\(pc\.metadata->>'visibility','school'\) <> 'technical_only'/);
assert.match(foundation, /'technicalPrivileges'/);
assert.match(policy, /a\.portfolio_code = 'proprietor'/);
assert.doesNotMatch(policy, /a\.portfolio_code in \('developer','proprietor'\)/);
assert.match(reads, /coalesce\(c\.metadata->>'visibility','school'\)<>'technical_only'/);
assert.match(reads, /where s\.registration_status='active' and s\.employment_status='active'/);
assert.match(writes, /TECHNICAL_PRIVILEGE_NOT_ASSIGNABLE_AS_PORTFOLIO/);
assert.match(approval, /STAFF_DESIGNATION_TECHNICAL_PRIVILEGE_FORBIDDEN/);

assert.match(identity, /school_identity_consolidations/);
assert.match(identity, /credential_status='active' and c\.last_login_at is not null/);
assert.match(identity, /REDUNDANT_IDENTITY_HAS_ACTIVE_ALLOCATIONS/);
assert.match(identity, /account_status='archived'/);
assert.match(identity, /registration_status='archived',employment_status='exited'/);
assert.match(identity, /set pw_hash=null/);
assert.match(identity, /identity\.duplicate_consolidated/);
assert.match(identity, /identity\.technical_privilege_presentation_separated/);
assert.doesNotMatch(identity, /delete\s+from/i);
assert.match(pilot, /RESULT_SYSTEM_READ_ONLY/);
assert.match(pilot, /school_registry_is_protected_actor\(v_person_id\)/);
assert.match(pilot, /not wts_internal\.school_registry_is_technical_actor\(g\.person_id\)/);
assert.doesNotMatch(pilot, /delete\s+from/i);

const names = (await readdir(new URL('supabase/migrations/', root))).filter((name) => name.endsWith('.sql')).sort();
assert.deepEqual(contract.migrationLedger.pendingOrder, [...contract.migrationLedger.pendingOrder].sort());
assert.equal(new Set(contract.migrationLedger.pendingOrder).size, contract.migrationLedger.pendingOrder.length);
assert.equal(contract.migrationLedger.productionApplied, true);
assert.equal(contract.migrationLedger.productionAppliedVersions.registry_business_and_departments, '20260910085618');
assert.equal(contract.migrationLedger.productionAppliedVersions.registry_profile_tools, '20260910085719');
for (const migration of contract.migrationLedger.pendingOrder) {
  assert.ok(names.includes(migration), `missing pending migration: ${migration}`);
  assert.ok(migration.slice(0, 14) > contract.migrationLedger.verifiedProductionHead, `pending migration is not after production head: ${migration}`);
}
const foundationIndex = names.indexOf('20260907210000_central_registry_architecture_foundation.sql');
const identityIndex = names.indexOf('20260908153000_registry_v2_identity_consolidation.sql');
assert.ok(foundationIndex >= 0 && identityIndex > foundationIndex, 'identity correction must run after the v2 foundation');

console.log('Registry v2 rollout-readiness contract passed');
