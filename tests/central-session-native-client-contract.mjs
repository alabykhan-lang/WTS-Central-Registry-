import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const baseUrl = process.env.REGISTRY_URL || "https://wts-central-registry.vercel.app";

async function request(path, options = {}) {
  const response = await fetch(`${baseUrl}${path}`, options);
  const text = await response.text();
  let payload = {};
  try { payload = text ? JSON.parse(text) : {}; } catch {}
  return { response, payload };
}

const record = await request("/api/registry-records", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ operation: "adminRead", action: "context", payload: {} }),
});
assert.equal(record.response.status, 401);
assert.equal(record.payload.code, "REGISTRY_SESSION_REQUIRED");

const staffSession = await request("/api/staff-session");
assert.equal(staffSession.response.status, 401);
assert.equal(staffSession.payload.code, "STAFF_SESSION_REQUIRED");

const staffPortal = await request("/api/staff-portal", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ action: "profile", payload: {} }),
});
assert.equal(staffPortal.response.status, 401);
assert.equal(staffPortal.payload.code, "STAFF_SESSION_REQUIRED");

for (const path of ["core.js", "bootstrap.js", "identity-login.js", "records.js", "staff-portal.js"]) {
  const source = await readFile(new URL(`../${path}`, import.meta.url), "utf8");
  assert.equal(/sessionStorage|localStorage/.test(source), false, `${path} stores browser session state`);
  assert.equal(/p_client_secret|p_client_code/.test(source), path === "identity-login.js" || path === "staff-portal.js", `${path} contains an unexpected client credential payload`);
}

console.log("Central session-native client contract passed");