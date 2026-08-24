import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const migration = await readFile(
  new URL(
    "../supabase/migrations/20260824004719_shared_teacher_recovery_code.sql",
    import.meta.url,
  ),
  "utf8",
);
const api = await readFile(
  new URL("../api/account-recovery.js", import.meta.url),
  "utf8",
);
const page = await readFile(new URL("../activate.html", import.meta.url), "utf8");
const client = await readFile(
  new URL("../account-recovery.js", import.meta.url),
  "utf8",
);

assert.match(migration, /school_identity_shared_teacher_code_consume/);
assert.match(migration, /v_shared_code_hash constant text := '[a-f0-9]{64}'/);
assert.doesNotMatch(migration, /WTS-[A-F0-9]{16}/);
assert.match(migration, /staff_category.*\('teaching', 'teacher'\)/s);
assert.match(migration, /designation.*like '%teacher%'/s);
assert.match(migration, /lower\(coalesce\(s\.staff_number/);
assert.match(migration, /crypt\(p_new_password, gen_salt\('bf', 12\)\)/);
assert.match(migration, /revoke_identity_sessions/);
assert.match(migration, /shared_teacher_password_reset_completed/);
assert.match(migration, /raw_code_stored', false/);
assert.match(migration, /grant execute.*to anon/s);

assert.match(api, /consumeSharedTeacherCode/);
assert.match(api, /school_identity_shared_teacher_code_consume/);
assert.match(api, /consumeManagementCode/);
assert.match(page, /Shared teacher access code/);
assert.match(client, /SHARED_TEACHER_CODE_INVALID/);
assert.match(client, /shared WTS teacher access code/);

console.log("Shared teacher recovery-code contract passed");
