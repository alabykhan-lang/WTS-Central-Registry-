import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';

const root = new URL('../', import.meta.url);
const read = (path) => readFile(new URL(path, root), 'utf8');
const contract = JSON.parse(await read('docs/CENTRAL-REGISTRY-ARCHITECTURE-CONTRACT.json'));
const html = await read('index.html');
const app = await read('registry/app.js');
const pages = await read('registry/pages.js');
const session = await read('api/registry-session.js');
const api = await read('api/registry-v2.js');
const signature = await read('api/registry-signature.js');
const migrationNames = (await readdir(new URL('supabase/migrations/', root))).sort();
const migrationSources = await Promise.all(migrationNames.map((name) => read(`supabase/migrations/${name}`)));
const allSql = migrationSources.join('\n');
const v2Sql = migrationSources.filter((_, index) => migrationNames[index].startsWith('20260907')).join('\n');

const primaryRoutes = [...html.matchAll(/<button class="nav(?: active)?" data-route="([^"]+)"/g)].map((match) => match[1]);
assert.deepEqual(primaryRoutes, contract.primaryNavigation);
assert.equal(contract.acceptanceCriteria.length, 20);

const evidence = new Map([
  ['all_active_staff_entry', /\('central_registry','all_active_staff','staff',true\)/.test(v2Sql) && /REGISTRY_ACCESS_NOT_GRANTED/.test(v2Sql)],
  ['seven_item_actor_specific_navigation', primaryRoutes.length === contract.primaryNavigation.length && /configureNav\(\)/.test(app)],
  ['subject_only_no_student_data', /\('subject_teacher','allocations\.read'\)/.test(v2Sql) && !/\('subject_teacher','students\./.test(v2Sql)],
  ['class_teacher_allocated_class_only', /students\.class\.read/.test(v2Sql) && /classScopes/.test(v2Sql) && /s\.class_key in/.test(v2Sql)],
  ['early_childhood_leadership_scope', /\('headmistress','early_childhood'\)/.test(v2Sql) && /allocations\.early_childhood\.manage/.test(v2Sql)],
  ['director_primary_scope', /\('director_primary','early_childhood'\),\('director_primary','primary'\)/.test(v2Sql)],
  ['schoolwide_management_scope', /\('director','students\.school\.read'\)/.test(v2Sql) && /\('principal','staff\.school\.read'\)/.test(v2Sql)],
  ['protected_controls', /school_registry_is_protected_actor/.test(v2Sql) && /is_protected boolean/.test(v2Sql)],
  ['results_staff_default_and_admin_gate', /\('results','all_active_staff','staff',true\)/.test(v2Sql) && /portal\.results\.admin/.test(v2Sql)],
  ['attendance_developer_only_pilot', /\('attendance','configured_only','attendance_admin',false\)/.test(v2Sql) && /school_registry_is_technical_actor/.test(allSql) && /ATTENDANCE_PILOT_RESTRICTED/.test(allSql)],
  ['notifications_disabled', /\('notifications','configured_only','staff',false\)/.test(v2Sql) && /\('notifications','disabled'/.test(v2Sql) && /NOTIFICATIONS_DISABLED/.test(allSql)],
  ['self_profile_and_signature', /profile\.self\.update/.test(v2Sql) && /profile\.signature\.update/.test(v2Sql) && /validImageBuffer/.test(signature)],
  ['normalized_classes_and_ss3_business', /stage_code/.test(v2Sql) && /'ss3-business'/.test(allSql) && /jsonb_build_object\('target','ss3-business'\)/.test(allSql)],
  ['one_main_multiple_assistants', /school_class_allocations_one_main_teacher_idx/.test(allSql) && /assistant_class_teacher/.test(v2Sql) && /STAFF_ALREADY_MAIN_TEACHER/.test(v2Sql)],
  ['class_subject_staff_allocation_order', html.indexOf('id="subjectClass"') < html.indexOf('id="subjectChoices"') && html.indexOf('id="subjectChoices"') < html.indexOf('id="subjectStaff"')],
  ['historical_portfolios', /assignment_status text not null default 'active'/.test(v2Sql) && /effective_until/.test(v2Sql) && /portfolio\.assignment_ended/.test(v2Sql)],
  ['annual_prefect_workflow', /school_prefect_cycles/.test(v2Sql) && /PREFECT_CYCLE_APPROVED/.test(v2Sql) && /TRANSITION_NOT_APPLIED/.test(v2Sql)],
  ['preserve_798_students', contract.preservation.studentRows === 798 && !/delete\s+from\s+public\.students/i.test(v2Sql) && !/drop\s+table\s+(?:if\s+exists\s+)?public\.students/i.test(v2Sql)],
  ['backend_scope_enforcement', /school_registry_session_entitlements/.test(v2Sql) && /REGISTRY_SCOPE_DENIED/.test(v2Sql) && /TARGET_CLASS_OUT_OF_SCOPE/.test(v2Sql)],
  ['database_api_browser_security_regression_tests', /HttpOnly; Secure; SameSite=Lax/.test(session) && /ORIGIN_NOT_ALLOWED/.test(api) && /IDEMPOTENCY_KEY_REUSED/.test(v2Sql)],
]);

for (const criterion of contract.acceptanceCriteria) {
  assert.equal(evidence.get(criterion), true, `Acceptance criterion lacks implementation evidence: ${criterion}`);
}

assert.match(v2Sql, /default_roles/);
assert.match(v2Sql, /v_status = any\(v_allowed_roles\)/);
assert.match(allSql, /target_app_code in \('notifications','finance'\)/);
assert.match(v2Sql, /https:\/\/wts-notification-system\.vercel\.app\//);
assert.match(v2Sql, /ACADEMIC_TRANSITION_CONFIRMATION_REQUIRED/);
assert.match(v2Sql, /staff-signatures\/'\|\|v_actor::text/);
assert.match(app, /confirmed:\$\('#transitionConfirm'\)\.checked/);
assert.doesNotMatch(signature, /WTS_SUPABASE_PUBLISHABLE_KEY|SUPABASE_PUBLISHABLE_KEY|SUPABASE_ANON_KEY/);
assert.match(pages, /data\.self \|\|/);
assert.doesNotMatch(v2Sql, /'staff',\(select coalesce\(jsonb_agg\(to_jsonb\(s\)/);
assert.match(v2Sql, /technicalPrivileges/);
assert.match(v2Sql, /visibility','technical_only/);
assert.doesNotMatch(v2Sql, /a\.portfolio_code in \('developer','proprietor'\)/);
assert.match(v2Sql, /classAllocationHistory/);
assert.match(v2Sql, /subjectAllocationHistory/);

console.log('Registry v2 senior architectural review: all 20 acceptance criteria have implementation evidence');
