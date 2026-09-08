import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const page = await readFile(new URL("../index.html", import.meta.url), "utf8");
const styles = await readFile(
  new URL("../registry-v2.css", import.meta.url),
  "utf8",
);

assert.match(page, /id="accessDetail"/);
assert.match(page, /class="access-layout"/);
assert.match(page, /id="accessSearch"/);
assert.match(page, /id="accessStaffList"/);
assert.match(page, /data-route="portalAccess"/);
assert.match(styles, /\.portal-grid\s*\{/);
assert.match(styles, /\.access-layout\s*\{/);

console.log("Portal access layout contract passed");
