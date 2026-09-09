import assert from "node:assert/strict";
import fs from "node:fs";

const migration = fs.readFileSync(new URL("../supabase/migrations/20260806010000_staff_management_recovery_codes.sql", import.meta.url), "utf8");
const api = fs.readFileSync(new URL("../api/account-recovery.js", import.meta.url), "utf8");
const managementApi = fs.readFileSync(new URL("../api/registry-management.js", import.meta.url), "utf8");
const page = fs.readFileSync(new URL("../activate.html", import.meta.url), "utf8");
const admin = fs.readFileSync(new URL("../identity-admin.js", import.meta.url), "utf8");
const directAccess = fs.readFileSync(new URL("../supabase/migrations/20260909060000_direct_staff_password_access.sql", import.meta.url), "utf8");

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

assert.match(api, /school_identity_password_reset_by_staff_record/);
assert.doesNotMatch(api, /complete_code|school_identity_management_code_consume/);
assert.match(managementApi, /REGISTRY_LEGACY_ROUTE_RETIRED/);
assert.match(managementApi, /\/api\/registry-v2/);
assert.doesNotMatch(page, /activation key|management code/i);
assert.doesNotMatch(admin, /Issue activation code/);
assert.doesNotMatch(admin, /Issue password-recovery code/);
assert.match(admin, /Direct password access enabled/);
assert.doesNotMatch(admin, /identityCodeReason|Reason for issuing this code/);
assert.doesNotMatch(admin, /purpose, reason/);
assert.match(directAccess, /school_identity_management_code_consume/);
assert.match(directAccess, /revoke execute on function %s from public, anon, authenticated/);

console.log("Management recovery-code contract passed");
