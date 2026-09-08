import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const source = await readFile(new URL("../api/registry-management.js", import.meta.url), "utf8");
assert.match(source, /statusCode\s*=\s*410/);
assert.match(source, /REGISTRY_LEGACY_ROUTE_RETIRED/);
assert.match(source, /replacement/);

console.log("Central secure management adapter contract passed");
