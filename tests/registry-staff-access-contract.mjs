import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const source = await readFile(new URL("../staff-portal.js", import.meta.url), "utf8");

assert.match(source, /grant_status === "active"/);
assert.match(source, /app_code !== "staff_self_service"/);
assert.match(source, /staff-access-empty/);
assert.equal(source.includes("Not granted"), false, "Staff view still contains an unassigned-module state");

console.log("Central Registry staff access visibility contract passed");
