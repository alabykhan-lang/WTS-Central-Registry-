import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const page = await readFile(new URL("../index.html", import.meta.url), "utf8");
const styles = await readFile(
  new URL("../portal-access-polish.css", import.meta.url),
  "utf8",
);

assert.match(page, /id="portalCards" class="access-detail-stack"/);
assert.match(page, /href="\/portal-access-polish\.css"/);
assert.match(styles, /\.access-detail-stack\s*\{/);
assert.match(styles, /grid-template-columns: minmax\(0, 1fr\)/);
assert.match(styles, /repeat\(auto-fit, minmax\(min\(100%, 330px\), 1fr\)\)/);
assert.match(styles, /overflow-x: hidden/);

console.log("Portal access layout contract passed");
