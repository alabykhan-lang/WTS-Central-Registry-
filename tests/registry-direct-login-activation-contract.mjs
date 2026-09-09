import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const root=new URL('../',import.meta.url);
const session=await readFile(new URL('api/registry-session.js',root),'utf8');
const registry=await readFile(new URL('api/registry-v2.js',root),'utf8');
const loginSql=await readFile(new URL('supabase/migrations/20260907221000_registry_v2_scoped_api.sql',root),'utf8');
const accessSql=await readFile(new URL('supabase/migrations/20260909060000_direct_staff_password_access.sql',root),'utf8');
const loginPage=await readFile(new URL('index.html',root),'utf8');
const recoveryPage=await readFile(new URL('activate.html',root),'utf8');
const registrationPage=await readFile(new URL('register.html',root),'utf8');
const recoveryApi=await readFile(new URL('api/account-recovery.js',root),'utf8');
const registrationApi=await readFile(new URL('api/staff-registration.js',root),'utf8');

for(const source of [session,registry]) {
  assert.match(source,/process\.env\.SUPABASE_ANON_KEY[\s\S]*eyJhbGciOiJIUzI1Ni/);
  assert.doesNotMatch(source,/['\"]role['\"]\s*:\s*['\"]service_role['\"]/i);
}
assert.match(loginSql,/school_registry_login_v2/);
assert.match(loginSql,/crypt\(p_password,v_credential\.password_hash\)/);
assert.match(loginSql,/lower\(c\.login_name\)=lower\(trim\(p_login\)\)/);
assert.match(accessSql,/initial_password_hash/);
assert.match(accessSql,/school_staff_registration_password_finalize/);
assert.match(accessSql,/school_identity_password_reset_by_staff_record/);
assert.match(accessSql,/registered_contact_matched/);
assert.match(accessSql,/revoke execute on function %s from public, anon, authenticated/);
assert.match(loginPage,/Already activated\? Sign in directly/);
assert.doesNotMatch(loginPage,/activation key/i);
assert.doesNotMatch(recoveryPage,/activation key|confirmation email|teacher access code/i);
assert.match(recoveryPage,/Registered email or phone/);
assert.match(registrationPage,/name="password"/);
assert.match(registrationPage,/No activation key or email confirmation is required/);
assert.match(recoveryApi,/school_identity_password_reset_by_staff_record/);
assert.doesNotMatch(recoveryApi,/issueAndSendRecoveryEmail|consumeSharedTeacherCode|consumeManagementCode/);
assert.doesNotMatch(registrationApi,/sendRegistrationReceivedEmail/);

console.log('Registry direct-login and no-activation access contract passed');
