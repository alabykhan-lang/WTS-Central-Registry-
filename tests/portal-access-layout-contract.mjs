import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const page = await readFile(new URL("../index.html", import.meta.url), "utf8");
const app = await readFile(new URL("../registry/app.js", import.meta.url), "utf8");

assert.doesNotMatch(page, /data-route="portalAccess"|data-page="portalAccess"|id="accessDetail"|id="accessSearch"|id="accessStaffList"/);
assert.doesNotMatch(app, /loadPortalAccess|portal_access/);
assert.doesNotMatch(page, /data-route="portfolio"|data-page="portfolio"/);
assert.match(page, /id="profileDialog"/);

console.log("Registry removed-surface contract passed");
