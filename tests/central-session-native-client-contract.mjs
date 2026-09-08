import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const records = await readFile(new URL("../api/registry-records.js", import.meta.url), "utf8");
const management = await readFile(new URL("../api/registry-management.js", import.meta.url), "utf8");
const session = await readFile(new URL("../api/registry-session.js", import.meta.url), "utf8");
assert.match(records, /statusCode\s*=\s*410/);
assert.match(management, /statusCode\s*=\s*410/);
assert.match(session, /HttpOnly/);
assert.match(session, /publicSessionResult/);
assert.doesNotMatch(session, /send\(res, 200, \{ \.\.\.result, context \}/);

for (const path of ["core.js", "bootstrap.js", "identity-login.js", "records.js", "staff-portal.js"]) {
  const source = await readFile(new URL(`../${path}`, import.meta.url), "utf8");
  assert.equal(/p_client_secret|p_client_code/.test(source), false, `${path} contains a browser client credential payload`);
}

const identityLogin = await readFile(new URL("../identity-login.js", import.meta.url), "utf8");
assert.match(identityLogin, /code_challenge/);
assert.match(identityLogin, /SSO_CALLBACK_INVALID/);

console.log("Central session-native client contract passed");
