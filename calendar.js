'use strict';

(() => {
  const W = window.WTSRegistry;
  if (!W) return;
  const { $, esc, toast, registerView } = W;
  let data = null;

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

  function range(item) {
    return item.starts_on || item.ends_on ? `${item.starts_on || 'Start not set'} → ${item.ends_on || 'End not set'}` : 'Dates not set';
  }

  function render() {
    const current = data?.current || {};
    $('#calendarCurrentSession').textContent = current.academic_session || 'Not configured';
    $('#calendarCurrentTerm').textContent = current.term || 'Not configured';
    $('#newTermSession').innerHTML = (data?.sessions || []).map((item) => `<option value="${esc(item.session_name)}">${esc(item.display_name)}</option>`).join('') || '<option value="">Create a session first</option>';
    $('#calendarTerms').innerHTML = (data?.terms || []).length ? data.terms.map((term) => {
      const currentMark = term.is_current ? '<span class="badge active">Current</span>' : `<span class="badge ${term.term_status === 'open' ? 'active' : term.term_status === 'archived' ? 'archived' : 'revoked'}">${esc(term.term_status)}</span>`;
      const actions = [];
      if (!term.is_current && term.term_status === 'open') actions.push(`<button type="button" data-calendar-current="${term.id}">Set current</button>`, `<button type="button" data-calendar-close="${term.id}">${term.last_reopened_at ? 'Close after correction' : 'Close term'}</button>`);
      if (!term.is_current && term.term_status === 'closed') actions.push(`<button type="button" data-calendar-reopen="${term.id}">Reopen for correction</button>`, `<button type="button" data-calendar-archive="${term.id}">Archive</button>`);
      return `<div class="calendar-term-row ${term.is_current ? 'is-current' : ''}"><div><strong>${esc(term.academic_session)} · ${esc(term.term_name)}</strong><small>${esc(range(term))}${term.last_reopened_at ? ` · Reopened ${esc(new Date(term.last_reopened_at).toLocaleString('en-NG', { dateStyle: 'medium' }))}` : ''}</small></div><div class="term-actions">${currentMark}${actions.join('')}</div></div>`;
    }).join('') : '<div class="empty">No academic terms are configured.</div>';
    bindRows();
  }

  async function load() {
    try {
      data = await management('calendarRead', 'read');
      window.WTSCalendarData = data;
      render();
    } catch (error) { toast(error.message, 'error'); }
  }

  async function act(action, term, extra = {}) {
    try {
      const result = await management('calendarWrite', action, { academicSession: term.academic_session, term: term.term_name, ...extra });
      toast(String(result.code || 'Calendar updated').replaceAll('_', ' ').toLowerCase(), 'success');
      await load();
      if (window.WTSAllocations?.load) await window.WTSAllocations.load();
    } catch (error) { toast(error.message, 'error'); }
  }

  function termById(id) { return (data?.terms || []).find((item) => item.id === id); }

  function bindRows() {
    document.querySelectorAll('[data-calendar-current]').forEach((button) => button.onclick = () => { const term = termById(button.dataset.calendarCurrent); if (term) act('setCurrent', term); });
    document.querySelectorAll('[data-calendar-close]').forEach((button) => button.onclick = () => { const term = termById(button.dataset.calendarClose); const reason = prompt('Why is this term being closed?'); if (term && reason?.trim()) act('closeAfterCorrection', term, { reason: reason.trim() }); });
    document.querySelectorAll('[data-calendar-reopen]').forEach((button) => button.onclick = () => { const term = termById(button.dataset.calendarReopen); const reason = prompt('Why must this closed term be reopened?'); if (!reason?.trim()) return; const approvalReference = prompt('Enter the management approval reference.'); if (term && approvalReference?.trim()) act('reopen', term, { reason: reason.trim(), approvalReference: approvalReference.trim() }); });
    document.querySelectorAll('[data-calendar-archive]').forEach((button) => button.onclick = () => { const term = termById(button.dataset.calendarArchive); if (term && confirm('Archive this closed term? Academic history remains read-only.')) act('archive', term); });
  }

  $('#sessionForm').onsubmit = async (event) => {
    event.preventDefault();
    try {
      await management('calendarWrite', 'createSession', { sessionName: $('#newSessionName').value.trim(), displayName: $('#newSessionName').value.trim(), startsOn: $('#newSessionStarts').value, endsOn: $('#newSessionEnds').value });
      toast('Academic session created.', 'success');
      event.currentTarget.reset();
      await load();
    } catch (error) { toast(error.message, 'error'); }
  };
  $('#termForm').onsubmit = async (event) => {
    event.preventDefault();
    try {
      await management('calendarWrite', 'createTerm', { academicSession: $('#newTermSession').value, term: $('#newTermName').value, startsOn: $('#newTermStarts').value, endsOn: $('#newTermEnds').value });
      toast('Academic term created.', 'success');
      event.currentTarget.reset();
      await load();
    } catch (error) { toast(error.message, 'error'); }
  };
  $('#calendarRefresh').onclick = load;
  registerView('calendar', load);
  window.WTSCalendar = { load, get data() { return data; } };
})();
