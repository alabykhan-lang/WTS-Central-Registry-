'use strict';

import { registryRequest } from './api-client.js';
import { state, hasCapability } from './state.js';
import { $, $$, esc, labelClass, formatDate, requestId, toast, setText } from './format.js';

async function read(action, payload = {}) { const key = `${action}:${JSON.stringify(payload)}`; if (state.cache.has(key)) return state.cache.get(key); const result = await registryRequest('read', action, payload); state.cache.set(key, result); return result; }
let portfolioCatalog=[];
let prefectBootstrapAssignments=[];
function clear(selector) { const node=$(selector); if (node) node.replaceChildren(); return node; }
function empty(node, message) { if (node) { node.textContent=message; node.hidden=false; } }
function row(text, detail, actions = []) { const node=document.createElement('div'); node.className='stack-row'; const main=document.createElement('div'); const strong=document.createElement('strong'); strong.textContent=text; const small=document.createElement('small'); small.textContent=detail || ''; main.append(strong,small); node.append(main); if (actions.length) { const buttons=document.createElement('div'); buttons.className='row-actions'; actions.forEach((button)=>buttons.append(button)); node.append(buttons); } return node; }

export async function loadDashboard() {
  const data=await read('dashboard'); const metrics=clear('#dashboardMetrics'); const cards=data.cards||[];
  cards.forEach((metric)=>{ const node=document.createElement('article'); node.className='metric-card'; const label=document.createElement('span'); label.textContent=metric.label; const value=document.createElement('strong'); value.textContent=String(metric.value ?? 0); node.append(label,value); metrics?.append(node); });
  const classes=clear('#dashboardClasses'); const classCards=data.classCards||[];
  if (!classCards.length) empty(classes, data.message || 'No class allocation is currently assigned.');
  classCards.forEach((item)=>classes?.append(row(item.label || labelClass(item.classKey),`${item.total ?? 0} active · ${item.female ?? 0} female · ${item.male ?? 0} male`,[Object.assign(document.createElement('button'),{className:'ghost',textContent:'Open class',type:'button',onclick:()=>{ document.querySelector('[data-route="students"]')?.click(); const select=$('#studentClass'); if(select){select.value=item.classKey; select.dispatchEvent(new Event('change'));}}})])));
  const readiness=clear('#guardianReadiness'); const labels=[['activeStudents','Active students'],['withPrimaryGuardian','Primary guardian'],['withPhone','Phone'],['withWhatsApp','WhatsApp'],['withConsent','Consent'],['invalidContacts','Missing contact']]; labels.forEach(([key,label])=>{const node=document.createElement('div');node.className='readiness-item';node.innerHTML=`<strong>${esc(data.guardianReadiness?.[key] ?? 0)}</strong><span>${esc(label)}</span>`;readiness?.append(node);});
}

export async function loadStudents() {
  const payload={search:$('#studentSearch')?.value || '',classKey:$('#studentClass')?.value || '',status:$('#studentStatus')?.value ?? 'active'}; const data=await read('students',payload); const rows=clear('#studentRows'); const emptyNode=$('#studentEmpty'); if(emptyNode) emptyNode.hidden=Boolean(data.students?.length);
  const canManageSchool=hasCapability('students.school.manage'); const classScopes=state.context?.entitlements?.classScopes || [];
  const canManage=(student)=>canManageSchool || (hasCapability('students.class.manage') && classScopes.includes(student.class_key));
  $('#newStudentButton')?.toggleAttribute('hidden',!(canManageSchool || (hasCapability('students.class.manage') && classScopes.length)));
  if(!data.students?.length)empty(rows,'No students found in your permitted scope.');
  data.students.forEach((student)=>{const node=document.createElement('tr');node.innerHTML=`<td><strong>${esc(student.name)}</strong><small>${esc(student.gender || '')}</small></td><td>${esc(student.class_label || labelClass(student.class_key))}</td><td>${esc(student.admno || 'Pending')}</td><td>${esc(student.guardian_count || 0)}</td><td><span class="badge ${student.archived?'archived':'active'}">${esc(student.lifecycle_status || (student.archived?'archived':'active'))}</span></td><td></td>`;if(canManage(student)){const actions=document.createElement('div');actions.className='row-actions';const edit=document.createElement('button');edit.type='button';edit.className='ghost';edit.textContent=student.archived?'Restore':'Edit';edit.dataset.studentAction=student.archived?'restore':'edit';edit.dataset.studentId=student.id;actions.append(edit);if(!student.archived){const archive=document.createElement('button');archive.type='button';archive.className='ghost';archive.textContent='Archive';archive.dataset.studentAction='archive';archive.dataset.studentId=student.id;actions.append(archive);}node.lastElementChild.append(actions);}rows?.append(node);});
  const classes=await read('catalog').catch(()=>null); const select=$('#studentClass'); if(select&&classes?.classes){const value=select.value;select.replaceChildren(new Option('All permitted classes',''));classes.classes.filter((c)=>c.is_active).forEach((c)=>select.append(new Option(c.display_name || labelClass(c.class_key),c.class_key)));select.value=value;}
}

export async function loadStaff() {
  const data=await read('staff',{search:$('#staffSearch')?.value || '',status:'active'}); const rows=clear('#staffRows'); const emptyNode=$('#staffEmpty'); if(emptyNode) emptyNode.hidden=Boolean(data.staff?.length); if(!data.staff?.length)empty(rows,'No staff records in your permitted scope.');
  data.staff.forEach((staff)=>{const node=document.createElement('tr');node.innerHTML=`<td><strong>${esc(staff.full_name)}</strong><small>${esc(staff.staff_number || '')}</small></td><td>${esc(staff.designation || staff.staff_category || 'Staff')}</td><td>${esc(staff.phone || staff.email || 'Not supplied')}</td><td><span class="badge ${staff.employment_status==='active'?'active':'archived'}">${esc(staff.employment_status || staff.registration_status)}</span></td>`;rows?.append(node);});
  const self=data.self || (data.staff||[]).find((x)=>x.central_person_id===state.context?.actor?.personId); if(self){$('#selfPhone').value=self.phone||'';$('#selfWhatsapp').value=self.whatsapp_number||'';$('#selfAddress').value=self.address||'';$('#selfEmergency').value=self.emergency_contact||'';$('#selfPhoto').value=self.photo||'';setText('#signatureStatus',self.signature_path?'Signature uploaded':'No signature uploaded.');}
}

export async function loadRegistrations() {
  const data=await read('registrations',{status:$('#registrationStatus')?.value || 'pending'}).catch((error)=>({ok:false,error})); const target=clear('#registrationRows'); const emptyNode=$('#registrationEmpty'); if(!data?.registrations?.length){emptyNode?.removeAttribute('hidden');empty(target,'No registrations found.');return;} emptyNode?.setAttribute('hidden','hidden'); data.registrations.forEach((item)=>{const actions=[];if(hasCapability('staff.school.read') && ['pending','under_review'].includes(item.registration_status)){const review=document.createElement('button');review.className='ghost';review.type='button';review.textContent='Mark under review';review.onclick=()=>window.RegistryApp.reviewRegistration(item,'under_review');actions.push(review);}if(hasCapability('portfolio.manage') && ['pending','under_review'].includes(item.registration_status)){const approve=document.createElement('button');approve.className='primary';approve.type='button';approve.textContent='Approve';approve.onclick=()=>window.RegistryApp.reviewRegistration(item,'registration.approve');const reject=document.createElement('button');reject.className='ghost';reject.type='button';reject.textContent='Reject';reject.onclick=()=>window.RegistryApp.reviewRegistration(item,'registration.reject');actions.push(approve,reject);}target?.append(row(item.full_name,`${item.email || 'No email'} · ${item.registration_status}${item.submitted_at ? ` · ${formatDate(item.submitted_at)}` : ''}`,actions));});
}

export async function loadAllocations() {
  const [catalog,data]=await Promise.all([read('catalog'),read('allocations')]);
  setText('#allocationContext',`${data.current?.academic_session || '—'} · ${data.current?.term || '—'}`);
  const canManageSchool=hasCapability('allocations.school.manage'); const canManageEarly=hasCapability('allocations.early_childhood.manage');
  $('#classAllocationCard')?.toggleAttribute('hidden',!canManageSchool&&!canManageEarly); $('#subjectAllocationCard')?.toggleAttribute('hidden',!canManageSchool);
  const classSelect=$('#allocationClass'); const subjectClass=$('#subjectClass'); const staffSelect=$('#allocationStaff'); const subjectStaff=$('#subjectStaff'); const fill=(select,items,placeholder,fn)=>{if(!select)return;const value=select.value;select.replaceChildren(new Option(placeholder,''));items.forEach((item)=>select.append(new Option(fn(item),item.class_key || item.id)));select.value=value;};
  fill(classSelect,catalog.classes||[],'Choose class',(x)=>x.display_name||labelClass(x.class_key)); fill(subjectClass,catalog.classes||[],'Choose class',(x)=>x.display_name||labelClass(x.class_key)); const staffs=catalog.staff||[]; [staffSelect,subjectStaff].forEach((s)=>fill(s,staffs,'Choose staff',(x)=>`${x.full_name} · ${x.staff_number || ''}`)); renderSubjects(catalog.subjects||[],subjectClass?.value);
  const rows=clear('#allocationRows'); const makeEnd=(item,type)=>{const button=document.createElement('button');button.type='button';button.className='ghost';button.textContent='End allocation';button.onclick=()=>window.RegistryApp.endAllocation(item,type);return button;};
  const classHistory=data.classAllocationHistory||data.classAllocations||[];const subjectHistory=data.subjectAllocationHistory||data.subjectAllocations||[];const current=data.current||{};const isCurrent=(item)=>item.allocation_status==='active'&&item.academic_session===current.academic_session&&item.term_name===current.term;
  if(!classHistory.length&&!subjectHistory.length){empty(rows,(canManageSchool||canManageEarly)?'No allocations have been recorded. Use the approved forms above when management supplies the real assignments.':'No allocation history is available in your permitted scope.');return;}
  classHistory.forEach((item)=>rows?.append(row(labelClass(item.class_key),`${item.academic_session} · ${item.term_name} · ${item.full_name || item.person_id} · ${item.responsibility?.replaceAll('_',' ') || 'class allocation'} · ${item.allocation_status}`,(isCurrent(item)&&(canManageSchool||canManageEarly))?[makeEnd(item,'allocations.class.end')]:[])));
  subjectHistory.forEach((item)=>rows?.append(row(`${labelClass(item.class_key)} · ${item.subject_name || `Subject ${item.subject_index}`}`,`${item.academic_session} · ${item.term_name} · ${item.full_name || item.person_id} · ${item.allocation_status}`,(isCurrent(item)&&canManageSchool)?[makeEnd(item,'allocations.subject.end')]:[])));
}
export function renderSubjects(subjects,classKey){const node=clear('#subjectChoices');const filtered=subjects.filter((s)=>!classKey || s.class_key===classKey);if(!filtered.length){empty(node,'Choose a class to see its active subjects.');return;}filtered.forEach((s)=>{const label=document.createElement('label');const input=document.createElement('input');input.type='checkbox';input.value=s.subject_index;label.append(input,document.createTextNode(s.subject_name || `Subject ${s.subject_index}`));node?.append(label);});}

export async function loadPortalAccess() {
  const search=$('#accessSearch')?.value || '';
  const selected=window.RegistryApp.selectedPersonId || '';
  const data=await read('portal_access',{personId:selected,search});
  const resultsControl=data.resultsOperatingControl || {};
  const resultsOnHold=resultsControl.operating_mode!=='active';
  const badge=$('#resultsOperatingBadge');
  if(badge){badge.textContent=resultsOnHold?'On hold':'Recording open';badge.className=`badge ${resultsOnHold?'revoked':'active'}`;}
  setText('#resultsOperatingMessage',resultsControl.reason || (resultsOnHold?'Result recording is on hold.':'Result recording is open.'));
  const operatingForm=$('#resultsOperatingForm');
  operatingForm?.toggleAttribute('hidden',!data.canManageOperatingControls);
  const operatingButton=$('#resultsOperatingToggle');
  if(operatingButton){operatingButton.textContent=resultsOnHold?'Resume result recording':'Put result recording on hold';operatingButton.dataset.nextMode=resultsOnHold?'active':'read_only';}
  const list=clear('#accessStaffList');
  (data.staff||[]).forEach((staff)=>{const button=document.createElement('button');button.type='button';button.className=`access-person-button ${staff.central_person_id===selected?'active':''}`;button.innerHTML=`<strong>${esc(staff.full_name)}</strong><small>${esc(staff.staff_number || staff.designation || '')}</small>`;button.onclick=()=>{window.RegistryApp.selectedPersonId=staff.central_person_id;state.cache.delete(`portal_access:${JSON.stringify({personId:staff.central_person_id,search})}`);loadPortalAccess();};list?.append(button);});
  const detail=$('#accessDetail');
  if(!selected){detail.innerHTML='<div class="empty">Select a staff member.</div>';return;}
  const selectedStaff=(data.staff||[]).find((x)=>x.central_person_id===selected);
  detail.replaceChildren();
  const title=document.createElement('h3');title.textContent=selectedStaff?.full_name || 'Portal access';detail.append(title);
  const grid=document.createElement('div');grid.className='portal-grid';
  (data.catalog||[]).forEach((portal)=>{
    const grant=(data.grants||[]).find((g)=>g.app_code===portal.app_code);
    const mode=portal.operating_mode || 'disabled';
    const globallyUnavailable=mode==='disabled' || (mode==='pilot'&&!selectedStaff?.technical_pilot_user);
    const card=document.createElement('article');card.className=`portal-card ${grant?.grant_status==='active'?'isActive':''}`;
    card.innerHTML=`<header><strong>${esc(portal.app_name || portal.app_code)}</strong><span class="badge ${grant?.grant_status==='active'?'active':'revoked'}">${esc(grant?.grant_status || 'not assigned')}</span></header><p>${esc(portal.description || '')}</p><small class="muted">Operating mode: ${esc(mode.replaceAll('_',' '))}${portal.operating_reason?` · ${esc(portal.operating_reason)}`:''}</small>`;
    const controls=document.createElement('div');controls.className='portal-controls';
    const role=document.createElement('select');role.setAttribute('aria-label',`${portal.app_name || portal.app_code} role`);
    const fallbackRoles=portal.app_code==='results'?['staff','results_admin']:portal.app_code==='attendance'?['staff','attendance_admin']:portal.app_code==='notifications'?['staff','notification_admin']:portal.app_code==='central_registry'?['staff','registry_admin']:['staff'];
    const roles=[...(Array.isArray(portal.default_roles)&&portal.default_roles.length?portal.default_roles:fallbackRoles)];if(grant?.access_role&&!roles.includes(grant.access_role))roles.push(grant.access_role);roles.forEach((value)=>role.append(new Option(String(value).replaceAll('_',' '),value)));role.value=grant?.access_role || roles[0];
    role.disabled=globallyUnavailable || (!hasCapability('portal.results.admin')&&!hasCapability('attendance.setup')&&roles.some((value)=>['admin','administrator','registry_admin','results_admin','attendance_admin'].includes(String(value).toLowerCase())));
    const button=document.createElement('button');button.type='button';button.className=grant?.grant_status==='active'?'ghost':'primary';button.textContent=grant?.grant_status==='active'?'Disable entry':'Enable entry';button.disabled=globallyUnavailable&&grant?.grant_status!=='active';button.onclick=()=>window.RegistryApp.write('portal.access.set',{personId:selected,appCode:portal.app_code,enabled:grant?.grant_status!=='active',accessRole:role.value});
    controls.append(role,button);card.append(controls);grid.append(card);
  });
  detail.append(grid);
}

export async function loadCalendar() { const data=await read('calendar');setText('#calendarCurrent',`${data.current?.academic_session || '—'} · ${data.current?.term || '—'}`);const warning=clear('#calendarWarnings');(data.configurationWarnings||[]).forEach((item)=>{const node=document.createElement('div');node.className='warning';node.textContent=item.message;warning?.append(node);});const terms=clear('#calendarTerms');(data.terms||[]).forEach((term)=>terms?.append(row(`${term.academic_session} · ${term.term_name}`,`${term.term_status}${term.is_current?' · current':''}`)));const current=data.current||{};$('#sourceSession').value=current.academic_session||'';$('#targetSession').value=current.academic_session ? current.academic_session.replace(/^(\d{4})\/(\d{4})$/,(_,a,b)=>`${Number(a)+1}/${Number(b)+1}`):'';if(!hasCapability('academic_calendar.manage'))$('#transitionCard')?.setAttribute('hidden','hidden');}

export async function loadPortfolio() {
  const data=await read('portfolio'); const target=clear('#portfolioRows'); const assignments=data.assignments||[]; const canManage=hasCapability('portfolio.manage');
  setText('#portfolioManagement h3','Assignment history');
  $('#portfolioAssignmentForm')?.toggleAttribute('hidden',!canManage);
  if(canManage){
    const catalog=await read('catalog').catch(()=>({classes:[],staff:[]}));
    const students=await read('students',{status:'active'}).catch(()=>({students:[]}));
    fillPortfolioOptions(data.catalog||[],catalog,students.students||[]);
  }
  if(!assignments.length)empty(target,'No portfolio assignment history exists in your permitted view.');
  assignments.forEach((item)=>{const actions=[];if(canManage&&item.assignment_status==='active'){const end=document.createElement('button');end.type='button';end.className='ghost';end.textContent='End assignment';end.onclick=()=>window.RegistryApp.endAllocation(item,'portfolio.assignment.end');actions.push(end);}target?.append(row(item.portfolio_code,`${item.assignment_status}${item.office_name?` · ${item.office_name}`:''} · ${item.academic_session || 'ongoing'} · ${item.scope_type}${item.stage_code?` · ${item.stage_code}`:''}${item.class_key?` · ${item.class_key}`:''} · ${item.holder_person_id || item.staff_id || item.student_id || ''} · since ${formatDate(item.effective_from)}`,actions));});
  const prefect=await read('prefect').catch(()=>({candidates:[]})); await renderPrefectBootstrap(prefect); const ptarget=clear('#prefectRows'); if(!prefect.candidates?.length)empty(ptarget,'No prefect candidates are open.'); prefect.candidates?.forEach((candidate)=>{const action=document.createElement('button');action.className='ghost';action.type='button';action.textContent=candidate.candidate_status==='candidate'?'Select':candidate.candidate_status.replaceAll('_',' ');action.disabled=!prefect.canManage || candidate.candidate_status!=='candidate';const office=document.createElement('input');office.className='compact-input';office.placeholder='Office / title';office.maxLength=120;office.value=candidate.office_name || '';office.disabled=action.disabled;action.onclick=()=>window.RegistryApp.write('prefect.select',{cycleId:candidate.cycle_id,studentId:candidate.student_id,selected:true,officeName:office.value.trim()});ptarget?.append(row(candidate.student_name || candidate.student_number || candidate.student_id,`${candidate.class_key || ''} · ${candidate.candidate_status}${candidate.office_name?` · ${candidate.office_name}`:''}`,[office,action]));}); $('#prefectPanel')?.toggleAttribute('hidden',!hasCapability('student.prefect.manage')&&!assignments.some((x)=>x.portfolio_code==='student_executive_council'&&x.assignment_status==='active')); $('#openPrefectCycle').disabled=!prefect.canManage || state.context?.academicContext?.term!=='3rd Term';
}
async function renderPrefectBootstrap(prefect){
  const panel=$('#prefectPanel');if(!panel)return;let node=$('#prefectBootstrap');
  if(!node){
    node=document.createElement('div');node.id='prefectBootstrap';node.className='panel-divider';
    node.innerHTML='<p class="panelEyebrow">VERIFIED CURRENT SS3 PREFECTS</p><p class="muted">Register only appointments confirmed by the school document. Each entry requires the present SS3 student and the verified office/post.</p><div class="prefect-import-row"><select id="prefectBootstrapStudents" aria-label="Current SS3 student"></select><input id="prefectBootstrapOffice" maxlength="120" placeholder="Verified office / post"><button class="ghost" id="prefectBootstrapAdd" type="button">Add appointment</button></div><div id="prefectBootstrapPending" class="stack-list"></div><button class="primary" id="prefectBootstrapSave" type="button">Register verified current prefects</button>';
    panel.insertBefore(node,$('#prefectRows'));
  }
  const completed=Boolean(prefect.bootstrap?.completed_at);node.hidden=!prefect.canBootstrap||completed;if(node.hidden)return;
  const groups=await Promise.all(['ss3-general','ss3-science','ss3-arts','ss3-business'].map((classKey)=>read('students',{status:'active',classKey}).catch(()=>({students:[]}))));
  const students=groups.flatMap((group)=>group.students||[]);const select=$('#prefectBootstrapStudents');select.replaceChildren(new Option('Choose current SS3 student',''));students.forEach((student)=>select.append(new Option(`${student.name} · ${student.admno || student.class_key}`,student.id)));
  const renderPending=()=>{const target=clear('#prefectBootstrapPending');if(!prefectBootstrapAssignments.length){empty(target,'No verified prefect appointment has been added.');return;}prefectBootstrapAssignments.forEach((assignment,index)=>{const student=students.find((item)=>item.id===assignment.studentId);const remove=document.createElement('button');remove.type='button';remove.className='ghost';remove.textContent='Remove';remove.onclick=()=>{prefectBootstrapAssignments.splice(index,1);renderPending();};target?.append(row(student?.name||assignment.studentId,assignment.officeName,[remove]));});};
  $('#prefectBootstrapAdd').onclick=()=>{const studentId=select.value;const officeName=$('#prefectBootstrapOffice').value.trim();if(!studentId||officeName.length<2){toast('Choose an SS3 student and enter the verified office.','error');return;}if(prefectBootstrapAssignments.some((item)=>item.studentId===studentId&&item.officeName.toLowerCase()===officeName.toLowerCase())){toast('That exact student appointment is already in the verified list.','error');return;}prefectBootstrapAssignments.push({studentId,officeName});select.value='';$('#prefectBootstrapOffice').value='';renderPending();};
  $('#prefectBootstrapSave').onclick=async()=>{if(!prefectBootstrapAssignments.length){toast('Add at least one verified SS3 prefect appointment.','error');return;}const assignments=[...prefectBootstrapAssignments];prefectBootstrapAssignments=[];renderPending();try{await window.RegistryApp.write('prefect.bootstrap',{assignments});}catch(error){prefectBootstrapAssignments=assignments;renderPending();}};renderPending();
}
function fillPortfolioOptions(portfolios,catalog,students){portfolioCatalog=portfolios;const portfolioSelect=$('#portfolioCode');const staffSelect=$('#portfolioStaff');const studentSelect=$('#portfolioStudent');const classSelect=$('#portfolioClass');if(portfolioSelect){const value=portfolioSelect.value;portfolioSelect.replaceChildren(new Option('Choose portfolio',''));portfolios.forEach((item)=>portfolioSelect.append(new Option(item.portfolio_name || item.portfolio_code,item.portfolio_code)));portfolioSelect.value=value;}if(staffSelect){const value=staffSelect.value;staffSelect.replaceChildren(new Option('Choose staff',''));(catalog.staff||[]).forEach((item)=>staffSelect.append(new Option(`${item.full_name} · ${item.staff_number || ''}`,item.staff_id || item.id)));staffSelect.value=value;}if(studentSelect){const value=studentSelect.value;studentSelect.replaceChildren(new Option('Choose student',''));students.forEach((item)=>studentSelect.append(new Option(`${item.name} · ${item.admno || item.class_key || ''}`,item.id)));studentSelect.value=value;}if(classSelect){const value=classSelect.value;classSelect.replaceChildren(new Option('Choose class',''));(catalog.classes||[]).forEach((item)=>classSelect.append(new Option(item.display_name || labelClass(item.class_key),item.class_key)));classSelect.value=value;}syncPortfolioForm(portfolios);}
export function syncPortfolioForm(portfolios=portfolioCatalog) {const selected=portfolios.find((item)=>item.portfolio_code===$('#portfolioCode')?.value);const holder=selected?.holder_type || $('#portfolioHolderType')?.value || 'staff';if(selected&&$('#portfolioHolderType'))$('#portfolioHolderType').value=holder;const jurisdiction=holder==='student'?'self':(selected?.jurisdiction || 'school');const student=$('#portfolioStudentField');const staff=$('#portfolioStaffField');const scope=$('#portfolioScopeType');const stage=$('#portfolioStageField');const cls=$('#portfolioClassField');if(staff)staff.hidden=holder!=='staff';if(student)student.hidden=holder!=='student';if(scope){scope.replaceChildren(new Option(jurisdiction.replaceAll('_',' '),jurisdiction));scope.value=jurisdiction;}if(stage)stage.hidden=jurisdiction!=='stage';if(cls)cls.hidden=jurisdiction!=='class';}

export function invalidate(action) { for (const key of state.cache.keys()) if (key.startsWith(`${action}:`)) state.cache.delete(key); }
