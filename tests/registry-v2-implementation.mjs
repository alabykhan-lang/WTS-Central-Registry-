import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';

const root = new URL('../', import.meta.url);
const files = {
  html: await readFile(new URL('index.html', root), 'utf8'),
  session: await readFile(new URL('api/registry-session.js', root), 'utf8'),
  api: await readFile(new URL('api/registry-v2.js', root), 'utf8'),
  signature: await readFile(new URL('api/registry-signature.js', root), 'utf8'),
};
const migrations = (await readdir(new URL('supabase/migrations/', root))).filter((name) => name.startsWith('20260907')).sort();
const sql = await Promise.all(migrations.map((name) => readFile(new URL(`supabase/migrations/${name}`, root), 'utf8')));
const allSql = sql.join('\n');

assert.deepEqual([...files.html.matchAll(/data-route="([^"]+)"/g)].map((m) => m[1]).filter((value, index, array) => array.indexOf(value) === index), ['dashboard','students','staff','registrations','allocations','portalAccess','calendar','portfolio']);
assert.match(files.html, /Staff [Rr]egistrations/);
assert.doesNotMatch(files.html, /<button[^>]+data-route="registrations"[^>]+class="nav"/);
assert.match(files.session, /school_registry_login_v2/);
assert.match(files.api, /school_registry_read_v2/);
assert.match(files.api, /school_registry_write_v2/);
assert.match(files.signature, /staff-signatures/);
for (const table of ['school_portfolio_catalog','school_portfolio_assignments','school_registry_capability_catalog','school_portal_access_policy','school_registry_request_outcomes']) {
  assert.match(allSql, new RegExp(`create table if not exists public\\.${table}`));
  assert.match(allSql, new RegExp(`alter table public\\.${table} enable row level security`));
}
assert.match(allSql, /ss3-business/);
assert.match(allSql, /ss2-business' then 'ss3-business/);
assert.match(allSql, /school_registry_materialize_module_grants/);
assert.match(allSql, /school_registry_prefect_bootstrap/);
assert.match(allSql, /school_registry_transition_readiness/);
assert.doesNotMatch(allSql, /delete\s+from\s+public\.students/i);
assert.doesNotMatch(allSql, /drop\s+table\s+public\.(students|school_people|staff_attendance_profiles)/i);
console.log('Registry v2 implementation contract passed');
