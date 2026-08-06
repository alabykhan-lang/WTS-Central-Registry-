import assert from "node:assert/strict";
import fs from "node:fs";

const migration = fs.readFileSync(new URL("../supabase/migrations/20260806010000_staff_management_recovery_codes.sql", import.meta.url), "utf8");
const api = fs.readFileSync(new URL("../api/account-recovery.js", import.meta.url), "utf8");
const managementApi = fs.readFileSync(new URL("../api/registry-management.js", import.meta.url), "utf8");
const page = fs.readFileSync(new URL("../activate.html", import.meta.url), "utf8");
const admin = fs.readFileSync(new URL("../identity-admin.js", import.meta.url), "utf8");

assert.match(migration, /create table if not exists public\.school_identity_management_codes/);
assert.match(migration, /enable row level security/);
assert.match(migration, /revoke all on table public\.school_identity_management_codes/);
assert.match(migration, /digest\(upper\(regexp_replace\(v_raw_code/);
assert.match(migration, /school_identity_admin_write_session_api/);
assert.match(migration, /wts_internal\.central_management_actor/);
assert.match(migration, /school_identity_management_code_consume/);
assert.match(migration, /attempt_count = least\(attempt_count \+ 1, 5\)/);
assert.match(migration, /wts_internal\.revoke_identity_sessions/);
assert.doesNotMatch(migration, /temporary_password/);
assert.doesNotMatch(migration, /recovery_code.*audit/i);

assert.match(api, /complete_code/);
assert.match(api, /school_identity_management_code_consume/);
assert.match(managementApi, /identityWrite: 'school_identity_admin_write_session_api'/);
assert.match(page, /One-time management code/);
assert.match(page, /Email is not required/);
assert.match(admin, /Issue activation code/);
assert.match(admin, /Issue password-recovery code/);
assert.match(admin, /recovery_code/);

console.log("Management recovery-code contract passed");
