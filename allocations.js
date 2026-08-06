'use strict';

(() => {
  const W = window.WTSRegistry;
  if (!W) return;
  const { $, state, esc, toast, registerView } = W;
  let allocationData = null;
  let calendarData = null;

  async function management(operation, action, payload = {}) {
    const response = await fetch('/api/registry-management', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ operation, action, payload }),
    });
    const result = await response.json().catch(() => ({ ok: false, code: 'REGISTRY_MANAGEMENT_INVALID_RESPONSE' }));
    if (!response.ok || result?.ok === false) throw Object.assign(new Error(result?.code || 'REGISTRY_MANAGEMENT_FAILED'), { code: result?.code });
    return result;
  }

  function context() {
    return { academicSession: allocationData?.academic_session, term: allocationData?.term };
  }

  function options(items, valueKey, label) {
    return items.map((item) => `<option value="${esc(item[valueKey])}">${esc(label(item))}</option>`).join('');
  }

  function setSelects() {
    const staff = allocationData?.staff || [];
    const classes = allocationData?.classes || [];
    const staffOptions = `<option value="">Choose a teacher</option>${options(staff, 'staff_id', (item) => `${item.full_name} · ${item.staff_number || 'No number'}`)}`;
    const classOptions = `<option value="">Choose a class</option>${options(classes, 'class_key', (item) => item.display_name)}`;
    const staffValue = $('#allocationStaff').value || $('#subjectStaff').value;
    const classValue = $('#allocationClass').value || $('#subjectClass').value;
    $('#allocationStaff').innerHTML = staffOptions;
    $('#subjectStaff').innerHTML = staffOptions;
    $('#allocationClass').innerHTML = classOptions;
    $('#subjectClass').innerHTML = classOptions;
    if (staffValue && staff.some((item) => item.staff_id === staffValue)) {
      $('#allocationStaff').value = staffValue;
      $('#subjectStaff').value = staffValue;
    }
    if (classValue && classes.some((item) => item.class_key === classValue)) {
      $('#allocationClass').value = classValue;
      $('#subjectClass').value = classValue;
    }
    renderSubjectChoices();
  }

  function renderSubjectChoices() {
    const classKey = $('#subjectClass').value;
    const staffId = $('#subjectStaff').value;
    const subjects = (allocationData?.subjects || []).filter((item) => item.class_key === classKey);
    const selected = new Set((allocationData?.subject_allocations || [])
      .filter((item) => item.staff_id === staffId && item.class_key === classKey && item.allocation_status === 'active')
      .map((item) => String(item.subject_index)));
    $('#subjectChoices').innerHTML = subjects.length
      ? subjects.map((subject) => `<label class="subject-check"><input type="checkbox" value="${subject.subject_index}" ${selected.has(String(subject.subject_index)) ? 'checked' : ''}> <span>${esc(subject.subject_name)}</span></label>`).join('')
      : '<div class="empty">No active subjects are configured for this class.</div>';
  }

  function renderAllocations() {
    const classes = (allocationData?.class_allocations || []).filter((item) => item.allocation_status === 'active');
    const subjects = (allocationData?.subject_allocations || []).filter((item) => item.allocation_status === 'active');
    $('#allocationRows').innerHTML = classes.length ? classes.map((item) => `<div class="allocation-row"><div><strong>${esc(item.class_name || item.class_key)}</strong><small>${esc(item.full_name)} · ${esc(item.staff_number || 'No staff number')} · ${esc(item.responsibility.replaceAll('_', ' '))}</small></div><div class="row-actions"><span class="badge active">Active</span><button type="button" data-revoke-class="${item.id}" data-staff-id="${item.staff_id}" data-class-key="${item.class_key}" data-responsibility="${item.responsibility}">End allocation</button></div></div>`).join('') : '<div class="empty">No class allocations for this official term.</div>';
    $('#subjectAllocationRows').innerHTML = subjects.length ? subjects.map((item) => `<div class="allocation-row"><div><strong>${esc(item.subject_name || `Subject ${item.subject_index}`)}</strong><small>${esc(item.full_name)} · ${esc(item.class_name || item.class_key)}</small></div><div class="row-actions"><span class="badge active">Active</span></div></div>`).join('') : '<div class="empty">No subject allocations for this official term.</div>';
    document.querySelectorAll('[data-revoke-class]').forEach((button) => {
      button.onclick = async () => {
        const reason = prompt('Why is this class allocation ending?');
        if (!reason?.trim()) return;
        try {
          await management('allocationWrite', 'setClass', {
            ...context(), allocationId: button.dataset.revokeClass, staffId: button.dataset.staffId,
            classKey: button.dataset.classKey, responsibility: button.dataset.responsibility,
            enabled: false, reason: reason.trim(),
          });
          toast('Class allocation ended. Its history was preserved.', 'success');
          await load();
        } catch (error) { toast(error.message, 'error'); }
      };
    });
  }

  function setCopyOptions() {
    const sessions = calendarData?.sessions || [];
    const terms = calendarData?.terms || [];
    $('#copySourceSession').innerHTML = sessions.length ? options(sessions, 'session_name', (item) => item.display_name) : '<option value="">No sessions</option>';
    const current = context();
    const firstSource = terms.find((item) => item.academic_session !== current.academicSession || item.term_name !== current.term);
    if (firstSource) {
      $('#copySourceSession').value = firstSource.academic_session;
      $('#copySourceTerm').value = firstSource.term_name;
    }
    refreshCopyTerms();
  }

  function refreshCopyTerms() {
    const session = $('#copySourceSession').value;
    const terms = (calendarData?.terms || []).filter((item) => item.academic_session === session);
    $('#copySourceTerm').innerHTML = terms.length ? options(terms, 'term_name', (item) => `${item.term_name} · ${item.term_status}`) : '<option value="">No terms</option>';
  }

  async function load() {
    try {
      [allocationData, calendarData] = await Promise.all([
        management('allocationRead', 'read'),
        management('calendarRead', 'read'),
      ]);
      state.allocationData = allocationData;
      const current = context();
      $('#allocationContext').textContent = `${current.academicSession || 'No session'} · ${current.term || 'No term'}`;
      $('#allocationContextNote').textContent = allocationData?.current?.term_status === 'open' ? 'New allocations use the official current term by default.' : 'The official term is read-only until management changes it.';
      setSelects();
      setCopyOptions();
      renderAllocations();
    } catch (error) { toast(error.message, 'error'); }
  }

  $('#allocationStaff').onchange = () => { $('#subjectStaff').value = $('#allocationStaff').value; renderSubjectChoices(); };
  $('#subjectStaff').onchange = renderSubjectChoices;
  $('#subjectClass').onchange = renderSubjectChoices;
  $('#copySourceSession').onchange = refreshCopyTerms;
  $('#allocationClassForm').onsubmit = async (event) => {
    event.preventDefault();
    try {
      await management('allocationWrite', 'setClass', {
        ...context(), staffId: $('#allocationStaff').value, classKey: $('#allocationClass').value,
        responsibility: $('#allocationResponsibility').value, enabled: true,
        reason: $('#allocationClassReason').value.trim(),
      });
      toast('Class allocation saved.', 'success');
      event.currentTarget.reset();
      await load();
    } catch (error) { toast(error.message, 'error'); }
  };
  $('#subjectAllocationForm').onsubmit = async (event) => {
    event.preventDefault();
    try {
      const subjectIndexes = [...document.querySelectorAll('#subjectChoices input[type="checkbox"]:checked')].map((input) => Number(input.value));
      await management('allocationWrite', 'setSubjects', {
        ...context(), staffId: $('#subjectStaff').value, classKey: $('#subjectClass').value,
        subjectIndexes, reason: $('#subjectAllocationReason').value.trim(),
      });
      toast('Subject allocations saved.', 'success');
      await load();
    } catch (error) { toast(error.message, 'error'); }
  };
  $('#copyAllocations').onclick = async () => {
    try {
      const sourceAcademicSession = $('#copySourceSession').value;
      const sourceTerm = $('#copySourceTerm').value;
      const result = await management('allocationWrite', 'copyContext', { ...context(), sourceAcademicSession, sourceTerm, reason: $('#copyReason').value.trim() });
      toast(`Copied ${result.class_allocations_copied || 0} class and ${result.subject_allocations_copied || 0} subject allocations.`, 'success');
      await load();
    } catch (error) { toast(error.message, 'error'); }
  };
  $('#startFreshAllocations').onclick = () => {
    $('#allocationClassForm').reset();
    $('#subjectAllocationForm').reset();
    renderSubjectChoices();
    toast('Start Fresh selected. No allocations were created.', 'success');
  };
  $('#allocationRefresh').onclick = load;

  registerView('allocations', load);
  window.WTSAllocations = { load };
})();
