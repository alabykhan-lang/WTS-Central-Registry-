import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const root=new URL('../',import.meta.url);
const read=(path)=>readFile(new URL(path,root),'utf8');
const [html,pages,app,css,photoApi,photoSql,managementSql]=await Promise.all([
  read('index.html'),read('registry/pages.js'),read('registry/app.js'),read('registry-v2.css'),read('api/registry-photo.js'),read('supabase/migrations/20260909190000_registry_photo_upload.sql'),read('supabase/migrations/20260910110000_registry_principal_management_and_access_templates.sql')
]);

assert.doesNotMatch(html,/GUARDIAN READINESS|guardianReadiness/);
assert.match(html,/Select a class to begin/);
assert.match(pages,/if\s*\(!classKey\)\s*return/);
assert.doesNotMatch(html,/All permitted classes/);
assert.match(html,/id="selfPhotoFile"[^>]+type="file"/);
assert.match(app,/dialogPhotoFile[\s\S]*preparePhoto/);
assert.match(photoApi,/validImage/);
assert.match(photoSql,/staff\.photo_updated/);
assert.doesNotMatch(html,/Photo path/);
assert.doesNotMatch(html,/id="allocationReason"|id="subjectReason"/);
assert.match(html,/id="responsibilityClass"/);
assert.match(pages,/stage_code\s*===\s*['"]secondary['"]/);
assert.match(pages,/responsibility-table/);
assert.match(pages,/Assistant\$\{assistants\.length/);
assert.match(pages,/data-print-section="class"/);
assert.match(pages,/data-print-section="subjects"/);
assert.doesNotMatch(html,/data-route="portalAccess"|data-page="portalAccess"|data-route="portfolio"|data-page="portfolio"/);
assert.doesNotMatch(html,/data-route="registrations"|data-page="registrations"|id="signOutButton"/);
assert.match(html,/sidebarSignOutButton/);
assert.match(html,/Way to Success Standard Schools<\/strong>/);
assert.match(html,/sidebarBackdrop/);
assert.match(html,/id="profileDialog"/);
assert.match(app,/profileRequest/);
assert.match(app,/profileCustomPortfolioForm/);
assert.match(app,/profileDepartmentForm/);
assert.match(app,/profileCustomPortfolioTemplate/);
assert.match(app,/portfolio\.access_template/);
assert.match(app,/allocations\.school\.manage/);
assert.match(app,/academic_calendar\.manage/);
assert.match(pages,/staffDirectoryCard/);
assert.match(managementSql,/school_registry_profile_access_template_session_api/);
assert.match(managementSql,/access_template_code/);
assert.match(css,/\.responsibility-table/);
assert.match(css,/\.registry-sidebar\{position:sticky/);
assert.match(css,/\.nav-open \.registry-sidebar/);
assert.match(css,/\.sidebar-backdrop/);

console.log('Registry UI corrections contract passed');
