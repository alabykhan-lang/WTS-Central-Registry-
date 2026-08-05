import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const session = await readFile(new URL("../api/registry-session.js", import.meta.url), "utf8");
const login = await readFile(new URL("../identity-login.js", import.meta.url), "utf8");

for (const permission of [
  "central_registry.administer",
  "staff_management.administer",
  "system_administration.administer",
]) {
  assert.match(session, new RegExp(permission.replace(".", "\\.")));
}
assert.match(session, /MANAGEMENT_ACCESS_DENIED/);
assert.match(session, /CENTRAL_MANAGEMENT_PERMISSION_REQUIRED/);
assert.match(session, /send\(res, 403/);
assert.match(session, /school_identity_session_revoke/);
assert.match(login, /Central Registry management permission has not been granted/);

console.log("Central management permission gate contract passed");

