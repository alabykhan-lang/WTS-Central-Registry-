import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const root = new URL('../', import.meta.url);
const read = (path) => readFile(new URL(path, root), 'utf8');
const [html, app, pages, client, endpoint, business, profileSql] = await Promise.all([
  read('index.html'),
  read('registry/app.js'),
  read('registry/pages.js'),
  read('registry/api-client.js'),
  read('api/registry-profile.js'),
  read('supabase/migrations/20260910100000_registry_business_and_departments.sql'),
  read('supabase/migrations/20260910101000_registry_profile_tools.sql'),
]);

assert.deepEqual(
  [...html.matchAll(/data-route="([^"]+)"/g)].map((match) => match[1]),
  ['dashboard', 'students', 'staff', 'registrations', 'allocations', 'calendar'],
);
assert.doesNotMatch(html, /data-page="portalAccess"|data-page="portfolio"|data-route="portalAccess"|data-route="portfolio"/);
assert.doesNotMatch(app, /loadPortalAccess|loadPortfolio|selectedPersonId/);
assert.doesNotMatch(pages, /loadPortalAccess|loadPortfolio|data-portfolio-tab|portfolioRows/);
assert.match(html, /id="profileDialog"/);
assert.match(app, /profileDepartmentForm/);
assert.match(app, /profileCustomPortfolioForm/);
assert.match(app, /if\(dialog&&!dialog\.open\)dialog\.showModal\(\)/);
assert.match(app, /\^ss\[123\]\(\?:-\(arts\|science\|business\|general\)\)\?\$/);
assert.match(client, /registry-profile/);
assert.match(endpoint, /school_registry_profile_session_api/);
assert.match(client, /credentials: 'same-origin'/);
assert.match(business, /department_code/);
assert.match(business, /ss2-business' then 'ss3-business/);
assert.match(business, /student\.business_stream_corrected/);
assert.match(business, /v_after_decision := null/);
assert.match(profileSql, /department\.update/);
assert.match(profileSql, /portfolio\.create/);
assert.match(profileSql, /portfolio\.end/);
assert.match(profileSql, /coalesce\(c\.metadata ->> 'custom', 'false'\) = 'true'/);
assert.match(profileSql, /portfolio\.manage/);
assert.match(profileSql, /PORTFOLIO_SENIOR_SECONDARY_ONLY/);
assert.match(profileSql, /\^ss\[23\]\(-\(arts\|science\|business\|general\)\)\?\$/);
assert.doesNotMatch(profileSql, /delete\s+from\s+public\.(students|school_people|staff_attendance_profiles)/i);
assert.match(pages, /responsibility-table/);
assert.match(pages, /Subject teachers/);

console.log('Registry profile workspace contract passed');
