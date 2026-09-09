import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const root=new URL('../',import.meta.url);
const read=(path)=>readFile(new URL(path,root),'utf8');
const [html,pages,app,css,photoApi,photoSql]=await Promise.all([
  read('index.html'),read('registry/pages.js'),read('registry/app.js'),read('registry-v2.css'),read('api/registry-photo.js'),read('supabase/migrations/20260909190000_registry_photo_upload.sql')
]);

assert.doesNotMatch(html,/GUARDIAN READINESS|guardianReadiness/);
assert.match(html,/Select a class to begin/);
assert.match(pages,/if\(!classKey\)return/);
assert.doesNotMatch(html,/All permitted classes/);
assert.match(html,/id="selfPhotoFile"[^>]+type="file"/);
assert.match(app,/dialogPhotoFile[\s\S]*preparePhoto/);
assert.match(photoApi,/validImage/);
assert.match(photoSql,/staff\.photo_updated/);
assert.doesNotMatch(html,/Photo path/);
assert.doesNotMatch(html,/id="allocationReason"|id="subjectReason"/);
assert.match(html,/id="responsibilityClass"/);
assert.match(pages,/stage_code==='secondary'/);
assert.match(pages,/Assistant\$\{assistants\.length>1/);
assert.match(pages,/data-print-section="class"/);
assert.match(pages,/data-print-section="subjects"/);
assert.match(html,/data-portfolio-tab="staff"/);
assert.match(html,/data-portfolio-tab="student"/);
assert.match(pages,/\.holder_type===portfolioTab/);
assert.match(html,/View current occupants/);
assert.match(css,/\.registry-sidebar\{position:sticky/);
assert.match(css,/\.nav-open \.registry-sidebar/);

console.log('Registry UI corrections contract passed');
