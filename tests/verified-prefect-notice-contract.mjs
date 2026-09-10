import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const root=new URL('../',import.meta.url);
const sql=await readFile(new URL('supabase/migrations/20260908234000_verified_2026_2027_prefect_appointments.sql',root),'utf8');
const workflow=await readFile(new URL('supabase/migrations/20260907222500_registry_v2_prefect_workflow.sql',root),'utf8');
const multiOffice=await readFile(new URL('supabase/migrations/20260908233000_allow_multiple_prefect_offices.sql',root),'utf8');
const pages=await readFile(new URL('registry/pages.js',root),'utf8');

const appointmentRows=[...sql.matchAll(/^\s*\(\d+,'WTS\/STU\/\d{6}'/gm)];
const permanentNumbers=new Set([...sql.matchAll(/'WTS\/STU\/(\d{6})'/g)].map((match)=>match[1]));
assert.equal(appointmentRows.length,35);
assert.equal(permanentNumbers.size,25);
for(const office of ['Ameerah','Assistant Ameer','Social Prefect Girl','Health Prefect Boy','Laboratory Prefect Girl','Punctuality Prefect Boy','Senior Prefect Boy','Senior Prefect Girl','Timekeeper']) assert.match(sql,new RegExp(`'${office.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')}'`));
assert.match(sql,/academic_session='2026\/2027'/);
assert.match(sql,/'2026-06-15 00:00:00\+01'/);
assert.match(sql,/VERIFIED_PREFECT_STUDENT_MATCH_FAILED/);
assert.match(sql,/class_at_import/);
assert.match(sql,/student\.prefect_appointment\.verified/);
assert.match(sql,/assignment_status='ended'/);
assert.doesNotMatch(sql,/delete\s+from/i);
assert.doesNotMatch(sql,/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i);
assert.match(workflow,/PREFECT_BOOTSTRAP_DUPLICATE_APPOINTMENT/);
assert.match(workflow,/lower\(trim\(coalesce\(a\.office_name,''\)\)\)=lower\(v_office\)/);
assert.match(multiOffice,/new\.portfolio_code <> 'student_executive_council'/);
assert.match(multiOffice,/lower\(trim\(coalesce\(a\.office_name,''\)\)\) = lower\(trim\(coalesce\(new\.office_name,''\)\)\)/);
assert.doesNotMatch(pages,/That exact student appointment is already in the verified list|prefectBootstrapAssignments/);

console.log('Verified 2026/2027 prefect notice contract passed');
