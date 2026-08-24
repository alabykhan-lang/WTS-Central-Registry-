import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const records = await readFile(new URL("../records.js", import.meta.url), "utf8");
const index = await readFile(new URL("../index.html", import.meta.url), "utf8");
const bootstrap = await readFile(new URL("../bootstrap.js", import.meta.url), "utf8");

const studentForm = records.slice(
  records.indexOf("function studentForm"),
  records.indexOf("function guardianForm"),
);

assert.match(studentForm, /\["male", "Male"\]/);
assert.match(studentForm, /\["female", "Female"\]/);
assert.doesNotMatch(studentForm, /\["unknown", "Unknown"\]/);
assert.doesNotMatch(studentForm, /Message language|notificationConsent/);
assert.match(studentForm, /photoField\(s\.photo \|\| "", true\)/);
assert.match(records, /navigator\.mediaDevices\.getUserMedia/);
assert.match(index, /<button type="button" class="ghost" id="cancelRecord">Cancel<\/button>/);
assert.match(bootstrap, /cancelRecord.*formDialog.*close\('cancel'\)/);

console.log("Student admission UI contract passed");
