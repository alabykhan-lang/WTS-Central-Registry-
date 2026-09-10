import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const contract = JSON.parse(await readFile(new URL("docs/CENTRAL-REGISTRY-ARCHITECTURE-CONTRACT.json", root), "utf8"));
const html = await readFile(new URL("index.html", root), "utf8");
const foundation = await readFile(new URL("supabase/migrations/20260907210000_central_registry_architecture_foundation.sql", root), "utf8").catch(() => "");

assert.deepEqual(contract.primaryNavigation, ["dashboard", "students", "staff", "allocations", "calendar"]);
assert.ok(!contract.primaryNavigation.includes("registrations"));
assert.ok(contract.removedRegistrySurfaces.includes("portalAccess"));
assert.ok(contract.removedRegistrySurfaces.includes("portfolio"));
assert.doesNotMatch(html, /data-route="portalAccess"|data-page="portalAccess"|data-route="portfolio"|data-page="portfolio"/);
assert.match(html, /id="profileDialog"/);
assert.doesNotMatch(html, /data-view="registration"/);
assert.match(html, /Registrations/);
assert.ok(contract.acceptanceCriteria.length === 20);
assert.ok(contract.preservation.studentRows === 798);
if (foundation) {
  assert.doesNotMatch(foundation, /delete\s+from\s+public\.students/i);
  assert.doesNotMatch(foundation, /drop\s+table\s+public\.(students|school_people|staff_attendance_profiles)/i);
  for (const table of ["school_portfolio_catalog", "school_portfolio_assignments", "school_registry_capability_catalog", "school_portal_access_policy"]) {
    assert.match(foundation, new RegExp(`alter table public\\.${table} enable row level security`, "i"));
  }
}
console.log("Central Registry target architecture contract passed");
