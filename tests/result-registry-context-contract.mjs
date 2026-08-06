import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const source = await readFile(new URL("../supabase/migrations/20260806100000_result_registry_context_and_history.sql", import.meta.url), "utf8");
const configSource = await readFile(new URL("../supabase/migrations/20260806110000_result_app_config_context_authority.sql", import.meta.url), "utf8");

assert.match(source, /school_academic_current\(\)/, "Results migration does not read the Registry academic context");
assert.match(source, /academic_history/, "Results migration does not expose academic history");
assert.match(source, /RESULT_ACADEMIC_CONTEXT_READ_ONLY/, "Results migration does not lock historical contexts");
assert.match(source, /school_academic_term_write_gate/, "Results migration does not respect closed-term locking");
assert.match(source, /school_result_scope_context_matches/, "Results migration does not preserve scoped historical access");
assert.match(source, /geminiKey/, "Results settings migration does not strip the private AI key");
assert.match(configSource, /school_academic_current\(\)/, "Result app-config writes do not read the Registry context");
assert.match(configSource, /academic_context_source.*central_registry/, "Result app-config writes do not record Registry context authority");

console.log("Result Registry academic-context contract passed");
