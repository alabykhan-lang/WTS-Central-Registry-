import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const source = await readFile(new URL("../api/registry-session.js", import.meta.url), "utf8");
assert.match(source, /REGISTRY_SESSION_REQUIRED/);
assert.match(source, /ORIGIN_NOT_ALLOWED/);
assert.match(source, /publicSessionResult/);
assert.match(source, /SSO_CLIENT_ID\s*=\s*'central_registry'/);
assert.doesNotMatch(source, /return send\(res, 200, \{\.\.\.result, context \}/);

console.log("Central Registry session contract passed");
