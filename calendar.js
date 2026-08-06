'use strict';

(() => {
  const W = window.WTSRegistry;
  if (!W) return;
  const { $, esc, toast, registerView } = W;
  let data = null;
  let transitionData = null;

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

  function render() {
    const current = data?.current || {};
    $('#calendarCurrentSession').textContent = current.academic_session || 'Not configured';
    $('#calendarCurrentTerm').textContent = current.term || 'Not configured';
    $('#calendarCurrentSessionSummary').textContent = current.academic_session || 'Not configured';
    $('#calendarCurrentTermSummary').textContent = current.term || 'Not configured';
    const next = transitionData?.next || {};
    $('#calendarNextSession').textContent = next.target_session || 'Next session';
    $('#calendarNextTerm').textContent = next.target_term || '1st Term';
    const transitionButton = $('#transitionNextSession');
    const canTransition = current.term === '3rd Term' && current.term_status !== 'archived';
    if (transitionButton) {
      transitionButton.disabled = !canTransition;
      transitionButton.textContent = canTransition ? 'Carry forward and open next session' : 'Available after 3rd Term is complete';
      transitionButton.title = canTransition ? 'Apply the configured promotion rules and open the next session.' : 'The current official term is not the completed 3rd Term.';
    }
    $('#calendarTerms').innerHTML = (data?.terms || []).length ? data.terms.map((term) => {
      const currentMark = term.is_current ? '<span class="badge active">Current</span>' : `<span class="badge ${term.term_status === 'open' ? 'active' : term.term_status === 'archived' ? 'archived' : 'revoked'}">${esc(term.term_status)}</span>`;
      const actions = [];
      if (!term.is_current && term.term_status === 'open') actions.push(`<button type="button" data-calendar-current="${term.id}">Set current</button>`, `<button type="button" data-calendar-close="${term.id}">${term.last_reopened_at ? 'Close after correction' : 'Close term'}</button>`);
      if (!term.is_current && term.term_status === 'closed') actions.push(`<button type="button" data-calendar-reopen="${term.id}">Reopen for correction</button>`, `<button type="button" data-calendar-archive="${term.id}">Archive</button>`);
      return `<div class="calendar-term-row ${term.is_current ? 'is-current' : ''}"><div><strong>${esc(term.academic_session)} · ${esc(term.term_name)}</strong><small>Official record · ${esc(term.term_status)}${term.last_reopened_at ? ` · Reopened ${esc(new Date(term.last_reopened_at).toLocaleString('en-NG', { dateStyle: 'medium' }))}` : ''}</small></div><div class="term-actions">${currentMark}${actions.join('')}</div></div>`;
    }).join('') : '<div class="empty">No academic terms are configured.</div>';
    bindRows();
  }

  async function load() {
    try {
      [data, transitionData] = await Promise.all([
        management('calendarRead', 'read'),
        management('transitionRead', 'read'),
      ]);
      window.WTSCalendarData = data;
      window.WTSTransitionData = transitionData;
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

  $('#transitionNextSession').onclick = async () => {
    const current = data?.current || {};
    if (current.term !== '3rd Term') return toast('The next-session handover becomes available after 3rd Term.', 'error');
    const next = transitionData?.next || {};
    if (!confirm(`Carry ${current.academic_session} 3rd Term into ${next.target_session || 'the next session'} 1st Term? Promotion thresholds will be applied and SS3 will be archived as graduating.`)) return;
    try {
      const result = await management('transitionWrite', 'transition', { reason: `Central Registry completed the ${current.academic_session} 3rd Term carry-forward into ${next.target_session || 'the next session'}` });
      toast(`Transition complete: ${result.promoted || 0} promoted, ${result.retained || 0} detained/retained, ${result.graduated || 0} graduated.`, 'success');
      await load();
      if (window.WTSAllocations?.load) await window.WTSAllocations.load();
    } catch (error) { toast(error.message, 'error'); }
  };
  $('#calendarRefreshSecondary').onclick = load;
  $('#calendarRefresh').onclick = load;
  registerView('calendar', load);
  window.WTSCalendar = { load, get data() { return data; } };
})();
