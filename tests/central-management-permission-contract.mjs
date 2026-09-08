import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const session = await readFile(new URL('../api/registry-session.js', import.meta.url), 'utf8');
const v2 = await readFile(new URL('../api/registry-v2.js', import.meta.url), 'utf8');
const html = await readFile(new URL('../index.html', import.meta.url), 'utf8');

assert.match(session, /school_registry_login_v2/);
assert.match(session, /school_registry_session_context_v2/);
assert.doesNotMatch(session, /hasCentralManagementPermission/);
assert.match(v2, /school_registry_read_v2/);
assert.match(v2, /school_registry_write_v2/);
assert.doesNotMatch(html, /data-route="registration"[^>]*class="nav"/);
assert.match(html, /data-route="registrations"/);

console.log('Central Registry all-active-staff entitlement contract passed');
