import assert from "node:assert/strict";

const baseUrl = process.env.REGISTRY_PORTAL_URL || "https://wts-central-registry.vercel.app";

async function request(headers = {}, body = {}) {
  const response = await fetch(`${baseUrl}/api/registry-management`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  let payload = {};
  try { payload = text ? JSON.parse(text) : {}; } catch {}
  return { response, payload };
}

const missingSession = await request({}, { operation: "identityRead", action: "staffAccounts", payload: {} });
assert.equal(missingSession.response.status, 401);
assert.equal(missingSession.payload.code, "REGISTRY_SESSION_REQUIRED");

const rejectedOrigin = await request({ Origin: "https://evil.example" }, { operation: "identityRead", action: "staffAccounts", payload: {} });
assert.equal(rejectedOrigin.response.status, 403);
assert.equal(rejectedOrigin.payload.code, "ORIGIN_NOT_ALLOWED");

console.log("Central secure management adapter contract passed");
