import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const root=new URL('../',import.meta.url);
const read=(path)=>readFile(new URL(path,root),'utf8');
const [foundation,policy,sso,reads,writes,enforcement,staffPortal,pages,app,html]=await Promise.all([
  read('supabase/migrations/20260907210000_central_registry_architecture_foundation.sql'),
  read('supabase/migrations/20260907220000_registry_v2_policy_and_invariants.sql'),
  read('supabase/migrations/20260907221600_registry_v2_sso.sql'),
  read('supabase/migrations/20260907221000_registry_v2_scoped_api.sql'),
  read('supabase/migrations/20260907222000_registry_v2_scoped_writes.sql'),
  read('supabase/migrations/20260908170000_portal_pilot_and_result_hold.sql'),
  read('staff-portal.js'),read('registry/pages.js'),read('registry/app.js'),read('index.html')
]);

assert.match(foundation,/\('results','read_only'/);
assert.match(foundation,/\('attendance','pilot'/);
assert.match(foundation,/\('notifications','disabled'/);
assert.match(foundation,/\('finance','disabled'/);
assert.match(foundation,/\('attendance','configured_only','attendance_admin',false\)/);
assert.doesNotMatch(foundation,/\('proprietor','attendance\.(?:setup|qr_generation)'\)/);
assert.match(policy,/classification',''\)\) in \('developer','system_owner'\)/);
assert.match(policy,/if v_mode='pilot' then return wts_internal\.school_registry_is_technical_actor/);
assert.match(sso,/school_portal_entry_allowed\(v_person_id, v_target\)/);
assert.match(sso,/school_portal_entry_allowed\(v_code\.person_id, v_client\.target_app_code\)/);
assert.match(enforcement,/RESULT_SYSTEM_READ_ONLY/);
assert.match(enforcement,/v_hold_exempt := wts_internal\.school_registry_is_protected_actor/);
assert.match(enforcement,/x\.permission in \('result_entry\.view','results\.view_assigned'\)/);
assert.match(enforcement,/school_attendance_registry_roster_read_api/);
assert.match(enforcement,/e\.class_key like 'ss2-%'/);
assert.match(enforcement,/'pilot_scope','SS2'/);
assert.match(enforcement,/join public\.school_access_grants g[\s\S]*g\.grant_status='active'/);
assert.match(enforcement,/target_app_code in \('notifications','finance'\)/);
assert.match(enforcement,/school_access_grants[\s\S]*on conflict\(person_id,app_code\) do update/);
assert.doesNotMatch(enforcement,/delete\s+from/i);
assert.match(reads,/'canManageOperatingControls',wts_internal\.school_registry_is_technical_actor/);
assert.match(reads,/c\.app_code='attendance' and wts_internal\.school_registry_is_technical_actor\(v_person_id\)/);
assert.match(writes,/v_action='portal\.operating_mode\.set'/);
assert.match(writes,/portal\.operating_mode\.updated/);
assert.match(writes,/school_portal_entry_allowed\(v_person_id,v_app\)/);
assert.match(staffPortal,/portal\.entry_allowed !== false/);
assert.match(enforcement,/client_id='notifications'/);
assert.doesNotMatch(html,/id="resultsOperatingForm"|data-route="portalAccess"|data-page="portalAccess"/);
assert.doesNotMatch(pages,/Resume result recording|loadPortalAccess/);
assert.doesNotMatch(app,/portal\.operating_mode\.set|loadPortalAccess/);

console.log('Portal pilot and Results hold policy contract passed');
