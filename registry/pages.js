'use strict';

import { registryRequest } from './api-client.js';
import { state, hasCapability } from './state.js';
import { $, esc, labelClass, formatDate, setText } from './format.js';

async function read(action, payload = {}) {
  const key = `${action}:${JSON.stringify(payload)}`;
  if (state.cache.has(key)) return state.cache.get(key);
  const result = await registryRequest('read', action, payload);
  if (action === 'catalog' && result && result.classes) {
    result.classes = result.classes.filter(c => !c.class_key.includes('::'));
  }
  state.cache.set(key, result);
  return result;
}

let allocationSnapshot = null;

function clear(selector) {
  const node = $(selector);
  if (node) node.replaceChildren();
  return node;
}

function empty(node, message) {
  if (node) {
    node.textContent = message;
    node.hidden = false;
  }
}

function row(text, detail, actions = []) {
  const node = document.createElement('div');
  node.className = 'stack-row';
  const main = document.createElement('div');
  const strong = document.createElement('strong');
  strong.textContent = text;
  const small = document.createElement('small');
  small.textContent = detail || '';
  main.append(strong, small);
  node.append(main);
  if (actions.length) {
    const buttons = document.createElement('div');
    buttons.className = 'row-actions';
    actions.forEach((button) => buttons.append(button));
    node.append(buttons);
  }
  return node;
}

function avatar(src, name) {
  const img = document.createElement('img');
  img.className = 'directory-avatar';
  img.src = src || '/public-school-logo.webp';
  img.alt = name ? `${name} picture` : 'Profile picture';
  img.onerror = () => { img.src = '/public-school-logo.webp'; };
  return img;
}

export async function loadDashboard() {
  const data = await read('dashboard');
  const metrics = clear('#dashboardMetrics');
  (data.cards || []).forEach((metric) => {
    const node = document.createElement('article');
    node.className = 'metric-card';
    const label = document.createElement('span');
    label.textContent = metric.label;
    const value = document.createElement('strong');
    value.textContent = String(metric.value ?? 0);
    node.append(label, value);
    metrics?.append(node);
  });
}

export async function loadStudents() {
  const catalog = await read('catalog').catch(() => null);
  const select = $('#studentClass');
  if (select && catalog?.classes && select.options.length <= 1) {
    catalog.classes.filter((item) => item.is_active).forEach((item) => select.append(new Option(item.display_name || labelClass(item.class_key), item.class_key)));
  }
  const classKey = select?.value || '';
  const search = $('#studentSearch');
  const status = $('#studentStatus');
  const searchButton = $('#studentSearchButton');
  [search, status, searchButton].forEach((node) => { if (node) node.disabled = !classKey; });
  $('#studentPrompt')?.toggleAttribute('hidden', Boolean(classKey));
  $('#studentResults')?.toggleAttribute('hidden', !classKey);
  const rows = clear('#studentRows');
  const canManageSchool = hasCapability('students.school.manage');
  const classScopes = state.context?.entitlements?.classScopes || [];
  const canEdit = (student) => canManageSchool || (hasCapability('students.class.manage') && classScopes.includes(student.class_key));
  const canProfile = (student) => canEdit(student) || hasCapability('portfolio.manage');
  $('#newStudentButton')?.toggleAttribute('hidden', !(canManageSchool || (hasCapability('students.class.manage') && classScopes.length)));
  if (!classKey) return;
  const payload = { search: search?.value || '', classKey, status: status?.value ?? 'active' };
  const data = await read('students', payload);
  const emptyNode = $('#studentEmpty');
  if (emptyNode) emptyNode.hidden = Boolean(data.students?.length);
  if (!data.students?.length) empty(rows, 'No students found in your permitted scope.');
  data.students.forEach((student) => {
    const node = document.createElement('tr');
    
    const person = document.createElement('td');
    const wrap = document.createElement('div');
    wrap.className = 'person-cell';
    const names = document.createElement('div');
    names.innerHTML = `<strong>${esc(student.name)}</strong><small>${esc(student.gender || '')}</small>`;
    wrap.append(avatar(student.photo, student.name), names);
    person.append(wrap);
    node.append(person);
    node.insertAdjacentHTML('beforeend', `<td>${esc(student.class_label || labelClass(student.class_key))}</td><td>${esc(student.admno || 'Pending')}</td><td>${esc(student.guardian_count || 0)}</td><td><span class="badge ${student.archived ? 'archived' : 'active'}">${esc(student.lifecycle_status || (student.archived ? 'archived' : 'active'))}</span></td><td></td>`);
    if (canProfile(student)) {
      const actions = document.createElement('div');
      actions.className = 'row-actions';
      const profile = document.createElement('button');
      profile.type = 'button';
      profile.className = 'ghost';
      profile.textContent = 'Profile';
      profile.dataset.studentAction = 'profile';
      profile.dataset.studentId = student.id;
      actions.append(profile);
      if (canEdit(student)) {
        const edit = document.createElement('button');
        edit.type = 'button';
        edit.className = 'ghost';
        edit.textContent = student.archived ? 'Restore' : 'Edit';
        edit.dataset.studentAction = student.archived ? 'restore' : 'edit';
        edit.dataset.studentId = student.id;
        actions.append(edit);
        if (!student.archived) {
          const archive = document.createElement('button');
          archive.type = 'button';
          archive.className = 'ghost';
          archive.textContent = 'Archive';
          archive.dataset.studentAction = 'archive';
          archive.dataset.studentId = student.id;
          actions.append(archive);
        }
      }
      node.lastElementChild.append(actions);
    }
    rows?.append(node);
  });
}

export async function loadStaff() {
  const data = await read('staff', { search: $('#staffSearch')?.value || '', status: 'active' });
  const directory = $('#staffDirectoryCard');
  directory?.toggleAttribute('hidden', Boolean(data.selfOnly));
  const rows = clear('#staffRows');
  const emptyNode = $('#staffEmpty');
  if (emptyNode) emptyNode.hidden = Boolean(data.staff?.length);
  setText('#staffCount', `${(data.staff || []).length} staff member(s) — tap to expand or collapse`);
  if (!data.staff?.length) empty(rows, 'No staff records in your permitted scope.');
  data.staff.forEach((staff) => {
    const node = document.createElement('tr');
    if (hasCapability('portfolio.manage')) { node.className = 'clickable-row'; node.dataset.staffAction = 'profile'; node.dataset.staffId = staff.staff_id || staff.id; node.title = 'Open profile'; }
    const person = document.createElement('td');
    const wrap = document.createElement('div');
    wrap.className = 'person-cell';
    const names = document.createElement('div');
    names.innerHTML = `<strong>${esc(staff.full_name)}</strong><small>${esc(staff.staff_number || '')}</small>`;
    wrap.append(avatar(staff.photo, staff.full_name), names);
    person.append(wrap);
    node.append(person);
    node.insertAdjacentHTML('beforeend', `<td>${esc(staff.designation || staff.staff_category || 'Staff')}</td><td>${esc(staff.phone || staff.email || 'Not supplied')}</td><td><span class="badge ${staff.employment_status === 'active' ? 'active' : 'archived'}">${esc(staff.employment_status || staff.registration_status)}</span></td><td></td>`);
    if (hasCapability('portfolio.manage')) {
      const action = document.createElement('button');
      action.type = 'button';
      action.className = 'ghost';
      action.textContent = 'Open profile';
      action.dataset.staffAction = 'profile';
      action.dataset.staffId = staff.staff_id || staff.id;
      node.lastElementChild.append(action);
    }
    rows?.append(node);
  });
  const self = data.self || (data.staff || []).find((item) => item.central_person_id === state.context?.actor?.personId);
  if (self) {
    $('#selfPhone').value = self.phone || '';
    $('#selfWhatsapp').value = self.whatsapp_number || '';
    $('#selfAddress').value = self.address || '';
    $('#selfEmergency').value = self.emergency_contact || '';
    const preview = $('#selfPhotoPreview');
    if (preview) preview.src = self.photo || '/public-school-logo.webp';
    setText('#signatureStatus', self.signature_path ? 'Signature uploaded' : 'No signature uploaded.');
  }
}

export async function loadRegistrations() {
  const data = await read('registrations', { status: $('#registrationStatus')?.value || 'pending' }).catch((error) => ({ ok: false, error }));
  const target = clear('#registrationRows');
  const emptyNode = $('#registrationEmpty');
  if (!data?.registrations?.length) {
    emptyNode?.removeAttribute('hidden');
    empty(target, 'No registrations found.');
    return;
  }
  emptyNode?.setAttribute('hidden', 'hidden');
  data.registrations.forEach((item) => {
    const actions = [];
    if (hasCapability('staff.school.read') && ['pending', 'under_review'].includes(item.registration_status)) {
      const review = document.createElement('button');
      review.className = 'ghost';
      review.type = 'button';
      review.textContent = 'Mark under review';
      review.onclick = () => window.RegistryApp.reviewRegistration(item, 'under_review');
      actions.push(review);
    }
    if (hasCapability('portfolio.manage') && ['pending', 'under_review'].includes(item.registration_status)) {
      const approve = document.createElement('button');
      approve.className = 'primary';
      approve.type = 'button';
      approve.textContent = 'Approve';
      approve.onclick = () => window.RegistryApp.reviewRegistration(item, 'registration.approve');
      const reject = document.createElement('button');
      reject.className = 'ghost';
      reject.type = 'button';
      reject.textContent = 'Reject';
      reject.onclick = () => window.RegistryApp.reviewRegistration(item, 'registration.reject');
      actions.push(approve, reject);
    }
    target?.append(row(item.full_name, `${item.email || 'No email'} · ${item.registration_status}${item.submitted_at ? ` · ${formatDate(item.submitted_at)}` : ''}`, actions));
  });
}

export async function loadAllocations() {
  const [catalog, data] = await Promise.all([read('catalog'), read('allocations')]);
  allocationSnapshot = { catalog, data };
  setText('#allocationContext', `${data.current?.academic_session || '—'} · ${data.current?.term || '—'}`);
  const canManageSchool = hasCapability('allocations.school.manage');
  
  const reportSelect = $('#responsibilityClass');
  if (reportSelect && reportSelect.options.length <= 1) (catalog.classes || []).filter((item) => item.is_active !== false).forEach((item) => reportSelect.append(new Option(item.display_name || labelClass(item.class_key), item.class_key)));
  renderSelectedResponsibilities(reportSelect?.value || '');
}

export function renderSubjects(subjects, classKey) {
  const node = clear('#subjectChoices');
  if ($('#subjectChoicesFieldset')) $('#subjectChoicesFieldset').hidden = !classKey;
  const filtered = subjects.filter((item) => !classKey || item.class_key === classKey);
  if (!filtered.length) {
    empty(node, 'Choose a class to see its active subjects.');
    return;
  }
  filtered.forEach((item) => {
    const label = document.createElement('label');
    const input = document.createElement('input');
    input.type = 'checkbox';
    input.value = item.subject_index;
    label.append(input, document.createTextNode(item.subject_name || `Subject ${item.subject_index}`));
    node?.append(label);
  });
}

export function renderSelectedResponsibilities(classKey) {
  const target = clear('#allocationRows');
  const classPrint = $('#printClassResponsibilities');
  const subjectPrint = $('#printSubjectResponsibilities');
  if (classPrint) classPrint.disabled = !classKey;
  if (subjectPrint) subjectPrint.disabled = !classKey;
  if (!classKey || !allocationSnapshot) {
    if (target) {
      target.className = 'responsibility-sheet-placeholder';
      target.innerHTML = '<img src="/public-school-logo.webp" alt=""><p>Select a class to view its current responsibilities.</p>';
    }
    return;
  }
  const { catalog, data } = allocationSnapshot;
  const current = data.current || {};
  const isCurrent = (item) => item.allocation_status === 'active' && item.academic_session === current.academic_session && item.term_name === current.term && item.class_key === classKey;
  const classes = (data.classAllocationHistory || data.classAllocations || []).filter(isCurrent);
  const subjects = (data.subjectAllocationHistory || data.subjectAllocations || []).filter(isCurrent);
  const main = classes.find((item) => item.responsibility === 'class_teacher');
  const assistants = classes.filter((item) => item.responsibility === 'assistant_class_teacher');
  const className = (catalog.classes || []).find((item) => item.class_key === classKey)?.display_name || labelClass(classKey);
  const classRows = `<tr><td>Class Teacher</td><td>${esc(main?.full_name || 'Not assigned')}</td></tr>${assistants.map((item, index) => `<tr><td>Assistant${assistants.length > 1 ? ` ${index + 1}` : ''}</td><td>${esc(item.full_name || 'Not assigned')}</td></tr>`).join('')}`;
  const subjectRows = subjects.length
    ? subjects.slice().sort((a, b) => String(a.subject_name || '').localeCompare(String(b.subject_name || ''))).map((item) => `<tr><td>${esc(item.subject_name || `Subject ${item.subject_index}`)}</td><td>${esc(item.full_name || 'Not assigned')}</td></tr>`).join('')
    : '<tr><td colspan="2" class="empty-inline">No subject teachers assigned.</td></tr>';
  const canManage = hasCapability('allocations.school.manage');
  target.className = 'official-responsibility-sheet';
  target.dataset.classKey = classKey;
  const classObj = (catalog.classes || []).find(c => c.class_key === classKey);
    const isSecondary = classObj && classObj.stage_code === 'secondary';
    target.innerHTML = `<header><img src="/public-school-logo.webp" alt="School logo"><div><small>WAY TO SUCCESS STANDARD SCHOOLS · EJIGBO</small><h2>${esc(className)} Responsibilities</h2><p>${esc(current.academic_session || '')} · ${esc(current.term || '')}</p></div></header><section data-print-section="class"><h3>Class responsibilities</h3><table class="responsibility-table"><thead><tr><th>Responsibility</th><th>Assigned staff</th></tr></thead><tbody>${classRows}</tbody></table></section>${isSecondary ? `<section data-print-section="subjects"><h3>Subject teachers</h3><table class="responsibility-table"><thead><tr><th>Subject</th><th>Assigned teacher</th></tr></thead><tbody>${subjectRows}</tbody></table></section>` : ''}`;
  if (canManage) {
    const controls = document.createElement('div');
    controls.className = 'responsibility-admin-actions no-print';
    [...classes, ...subjects].forEach((item) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'ghost';
      button.textContent = `Remove ${item.subject_name || item.responsibility?.replaceAll('_', ' ')}`;
      button.onclick = () => window.RegistryApp.endAllocation(item, item.subject_name ? 'allocations.subject.end' : 'allocations.class.end');
      controls.append(button);
    });
    target.append(controls);
  }
}

export function printResponsibilities(type) {
  const sheet = $('#allocationRows');
  if (!sheet?.dataset.classKey) return;
  document.body.dataset.printResponsibility = type;
  window.print();
  delete document.body.dataset.printResponsibility;
}

export async function loadCalendar() {
  const data = await read('calendar');
  const current = data.current || {};
  const session = current.academic_session || '';
  const currentTerm = current.term || '';
  const canManage = hasCapability('academic_calendar.manage');
  setText('#calendarCurrent', `${session || '\u2014'} \u00b7 ${currentTerm || '\u2014'}`);
  const warning = clear('#calendarWarnings');
  (data.configurationWarnings || []).forEach((item) => {
    const node = document.createElement('div');
    node.className = 'warning';
    node.textContent = item.message;
    warning?.append(node);
  });

  const termNames = ['1st Term', '2nd Term', '3rd Term'];
  const rows = data.terms || [];
  const doTransition = async (payload, question) => {
    if (!window.confirm(question)) return;
    try {
      await window.RegistryApp.write('calendar.transition', { ...payload, reason: 'Approved handover', confirmed: true });
    } catch (error) { /* write() already reports the error */ }
  };

  // Current session with its terms
  const currentTitle = $('#currentSessionTitle');
  if (currentTitle) currentTitle.textContent = session ? `${session} (current session)` : 'Current session';
  const termList = clear('#calendarCurrentTerms');
  termNames.forEach((name, index) => {
    const found = rows.find((t) => t.academic_session === session && t.term_name === name);
    const isCurrent = name === currentTerm;
    const status = found ? found.term_status : 'not started';
    const actions = [];
    if (canManage && isCurrent && index < termNames.length - 1) {
      const next = termNames[index + 1];
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'primary';
      button.textContent = `Carry forward to ${next}`;
      button.onclick = () => doTransition(
        { sourceSession: session, sourceTerm: name, targetSession: session, targetTerm: next },
        `Carry ${session} ${name} forward to ${next}?`
      );
      actions.push(button);
    }
    termList?.append(row(name, `${status}${isCurrent ? ' \u00b7 current' : ''}`, actions));
  });

  // Separate move to next session
  const nextSession = session ? session.replace(/^(\d{4})\/(\d{4})$/, (_, a, b) => `${Number(a) + 1}/${Number(b) + 1}`) : '';
  const moveText = $('#sessionMoveText');
  if (moveText) moveText.textContent = nextSession ? `Start ${nextSession} (1st Term) when ${session} is complete.` : '';
  const moveAction = clear('#sessionMoveAction');
  const moveCard = $('#transitionCard');
  if (moveCard) moveCard.hidden = !canManage || !nextSession;
  if (canManage && nextSession && moveAction) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'primary';
    button.textContent = `Move forward to ${nextSession}`;
    button.onclick = () => doTransition(
      { sourceSession: session, sourceTerm: currentTerm || '3rd Term', targetSession: nextSession, targetTerm: '1st Term' },
      `Close ${session} and move forward to ${nextSession}?`
    );
    moveAction.append(button);
  }

  // Past sessions: sessions only, no terms
  const past = clear('#calendarTerms');
  const seen = new Set();
  rows.forEach((term) => {
    if (term.academic_session === session || seen.has(term.academic_session)) return;
    seen.add(term.academic_session);
  });
  [...seen].sort().reverse().forEach((name) => past?.append(row(name, 'closed')));
  if (!seen.size && past) past.textContent = 'No past sessions yet.';
}

export function invalidate(action) {
  for (const key of state.cache.keys()) if (key.startsWith(`${action}:`)) state.cache.delete(key);
}






