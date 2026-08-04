import assert from "node:assert/strict";

const baseUrl = process.env.REGISTRY_URL || "https://wts-central-registry.vercel.app";

async function request(path, options = {}) {
  const response = await fetch(`${baseUrl}${path}`, options);
  const text = await response.text();
  let payload = {};
  try { payload = text ? JSON.parse(text) : {}; } catch {}
  return { response, payload };
}

const missing = await request("/api/registry-session");
assert.equal(missing.response.status, 401);
assert.equal(missing.payload.code, "REGISTRY_SESSION_REQUIRED");

const invalid = await request("/api/registry-session", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ action: "login", login: "contract-test-invalid-login@example.invalid", password: "contract-test-invalid-password" }),
});
assert.equal(invalid.response.status, 401);
assert.equal(Object.hasOwn(invalid.payload, "session_secret"), false);

const evil = await request("/api/registry-session", {
  method: "POST",
  headers: { "Content-Type": "application/json", Origin: "https://evil.example" },
  body: JSON.stringify({ action: "login", login: "contract-test-invalid-login@example.invalid", password: "contract-test-invalid-password" }),
});
assert.equal(evil.response.status, 403);
assert.equal(evil.payload.code, "ORIGIN_NOT_ALLOWED");

console.log("Central Registry session contract passed");
