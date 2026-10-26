/* Guardian contact bulk import — paste-to-register, one student per line.
 *
 * Lives on the Central Registry's Students page. The guardian write goes through the
 * existing API (`/api/registry-v2`, action `guardian.upsert`), which owns the scope
 * check, the phone normaliser and the audit trail. This file only parses, validates
 * and reports — it never writes to the database directly.
 *
 * Line format (comma, semicolon or tab separated):
 *   student name, father number, mother number
 *   student name, 08012345678          (one number only)
 */
'use strict';

(() => {
  const MOBILE = /^0[789][01]\d{8}$/;
  const SEPARATOR = /\t|,|;/;

  let rows = [];
  let roster = [];
  let rosterLoaded = false;

  const $ = (sel) => document.querySelector(sel);

  function esc(value) {
    return String(value ?? '').replace(/[&<>'"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[c]));
  }

  function toast(message, type) {
    if (window.WTSRegistry && typeof window.WTSRegistry.toast === 'function') {
      window.WTSRegistry.toast(message, type);
      return;
    }
    const box = document.getElementById('guardianImportSummary');
    if (box) box.textContent = message;
  }

  /** Normalise a Nigerian mobile number to 11-digit local form, or report why it cannot be. */
  function normaliseNumber(raw) {
    const digits = String(raw || '').replace(/[^\d]/g, '');
    if (!digits) return { ok: false, code: 'EMPTY', value: '' };
    let local = digits;
    if (/^234[789][01]\d{8}$/.test(digits)) local = '0' + digits.slice(3);
    else if (/^[789][01]\d{8}$/.test(digits)) local = '0' + digits;
    if (!MOBILE.test(local)) return { ok: false, code: 'INVALID_FORMAT', value: digits };
    return { ok: true, code: 'OK', value: local };
  }

  function parseLines(text) {
    const out = [];
    String(text || '')
      .split(/\r?\n/)
      .forEach((line, index) => {
        const trimmed = line.trim();
        if (!trimmed) return;
        const parts = trimmed.split(SEPARATOR).map((p) => p.trim()).filter(Boolean);
        out.push({
          line: index + 1,
          name: parts[0] || '',
          father: parts[1] || '',
          mother: parts[2] || '',
        });
      });
    return out;
  }

  function validateRow(row) {
    const father = normaliseNumber(row.father);
    const mother = normaliseNumber(row.mother);
    const problems = [];
    if (!row.name) problems.push('NAME_MISSING');
    if (row.father && !father.ok) problems.push('FATHER_INVALID');
    if (row.mother && !mother.ok) problems.push('MOTHER_INVALID');
    if (!row.father && !row.mother) problems.push('NO_NUMBER');
    return {
      ...row,
      father: father.ok ? father.value : row.father,
      mother: mother.ok ? mother.value : row.mother,
      fatherOk: father.ok,
      motherOk: mother.ok,
      problems,
      state: problems.length ? 'problem' : 'ready',
    };
  }

  function indexRoster(list) {
    const map = new Map();
    list.forEach((s) => {
      const key = String(s.name || '').trim().toLowerCase().replace(/\s+/g, ' ');
      if (!key) return;
      if (!map.has(key)) map.set(key, []);
      map.get(key).push(s);
    });
    return map;
  }

  /** Exact name first, then every-word containment, never a blind nearest guess. */
  function matchStudent(map, rawName) {
    const key = String(rawName || '').trim().toLowerCase().replace(/\s+/g, ' ');
    const exact = map.get(key);
    if (exact && exact.length === 1) return { ok: true, student: exact[0] };
    if (exact && exact.length > 1) return { ok: false, code: 'AMBIGUOUS_NAME' };
    const words = key.split(' ').filter(Boolean);
    if (!words.length) return { ok: false, code: 'NAME_MISSING' };
    const candidates = [];
    map.forEach((bucket) => {
      bucket.forEach((s) => {
        const target = String(s.name || '').toLowerCase();
        if (words.every((w) => target.includes(w))) candidates.push(s);
      });
    });
    if (candidates.length === 1) return { ok: true, student: candidates[0], fuzzy: true };
    if (candidates.length > 1) return { ok: false, code: 'AMBIGUOUS_NAME' };
    return { ok: false, code: 'STUDENT_NOT_FOUND' };
  }

  async function registryCall(kind, action, payload) {
    const response = await fetch('/api/registry-v2', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ kind, action, payload: payload || {} }),
      cache: 'no-store',
    });
    const result = await response.json().catch(() => ({ ok: false, code: 'REGISTRY_INVALID_RESPONSE' }));
    if (!response.ok || result.ok === false) {
      throw Object.assign(new Error(result.code || 'REGISTRY_REQUEST_FAILED'), { code: result.code });
    }
    return result;
  }

  async function loadRoster() {
    if (rosterLoaded) return indexRoster(roster);
    const result = await registryCall('read', 'students', { status: 'active' });
    roster = (result.students || []).filter((s) => !s.archived);
    rosterLoaded = true;
    return indexRoster(roster);
  }

  function render() {
    const body = $('#guardianImportRows');
    if (!body) return;
    if (!rows.length) {
      body.innerHTML = '<tr><td colspan="6" class="empty">Paste lines above, then press Check lines.</td></tr>';
    } else {
      body.innerHTML = rows
        .map((row) => {
          const badge =
            row.state === 'ready'
              ? '<span class="badge active">Ready</span>'
              : row.state === 'done'
                ? '<span class="badge active">Saved</span>'
                : row.state === 'saving'
                  ? '<span class="badge">Saving…</span>'
                  : row.state === 'failed'
                    ? '<span class="badge revoked">' + esc(row.serverCode || 'FAILED') + '</span>'
                    : '<span class="badge revoked">NEEDS FIX</span>';
          const who = row.student ? esc(row.student.name) + ' <small>' + esc(row.student.class_key || '') + '</small>' : esc(row.name);
          const note = row.problems && row.problems.length ? esc(row.problems.join(', ')) : row.serverCode ? esc(row.serverCode) : '';
          return (
            '<tr>' +
            '<td>' + row.line + '</td>' +
            '<td>' + who + '</td>' +
            '<td>' + esc(row.father || '—') + (row.father && !row.fatherOk ? ' <small>bad</small>' : '') + '</td>' +
            '<td>' + esc(row.mother || '—') + (row.mother && !row.motherOk ? ' <small>bad</small>' : '') + '</td>' +
            '<td>' + badge + '</td>' +
            '<td><small>' + note + '</small></td>' +
            '</tr>'
          );
        })
        .join('');
    }
    const ready = rows.filter((r) => r.state === 'ready').length;
    const saved = rows.filter((r) => r.state === 'done').length;
    const bad = rows.filter((r) => r.state === 'problem' || r.state === 'failed').length;
    const summary = $('#guardianImportSummary');
    if (summary && rows.length) {
      summary.textContent = rows.length + ' lines · ' + ready + ' ready · ' + saved + ' saved · ' + bad + ' with problems';
    }
    const saveButton = $('#guardianImportSave');
    if (saveButton) saveButton.disabled = ready === 0;
  }

  async function checkLines() {
    const text = ($('#guardianImportText') || {}).value || '';
    const parsed = parseLines(text).map(validateRow);
    if (!parsed.length) {
      toast('Paste at least one line first.', 'error');
      return;
    }
    const map = await loadRoster();
    rows = parsed.map((row) => {
      const match = matchStudent(map, row.name);
      if (!match.ok) return { ...row, state: 'problem', problems: [...row.problems, match.code] };
      return { ...row, student: match.student, fuzzy: !!match.fuzzy };
    });
    render();
  }

  async function saveReady() {
    const ready = rows.filter((r) => r.state === 'ready' && r.student);
    if (!ready.length) return;
    let saved = 0;
    let failed = 0;
    for (const row of ready) {
      row.state = 'saving';
      render();
      const surname = String(row.student.name || '').trim().split(/\s+/).slice(-1)[0] || 'Guardian';
      const guardianName = row.father ? 'Mr. ' + surname : 'Mrs. ' + surname;
      try {
        await registryCall('write', 'guardian.upsert', {
          studentId: row.student.student_id || row.student.id,
          fullName: guardianName,
          relationship: row.father && row.mother ? 'Parent/Guardian' : row.father ? 'Father' : 'Mother',
          phone: row.father || row.mother,
          whatsappNumber: row.father && row.mother ? row.mother : '',
          isPrimary: true,
          isLegalGuardian: true,
          notificationConsent: true,
          preferredLanguage: 'english',
        });
        row.state = 'done';
        saved += 1;
      } catch (error) {
        row.state = 'failed';
        row.serverCode = (error && error.code) || 'FAILED';
        failed += 1;
      }
      render();
    }
    toast(saved + ' guardian record(s) saved' + (failed ? ', ' + failed + ' rejected' : '') + '.', failed ? 'error' : 'success');
  }

  function mount() {
    const page = document.querySelector('[data-page="students"]');
    if (!page || document.getElementById('guardianImportCard')) return;
    const card = document.createElement('article');
    card.className = 'card';
    card.id = 'guardianImportCard';
    card.style.marginTop = '18px';
    card.innerHTML =
      '<div class="section-head"><div><p class="panelEyebrow">GUARDIAN CONTACTS</p>' +
      '<h3>Bulk phone numbers</h3>' +
      '<p class="muted small">One student per line: <code>name, father number, mother number</code>. ' +
      'Father goes to Phone, mother to WhatsApp. Invalid numbers are listed and skipped — never guessed.</p></div></div>' +
      '<textarea id="guardianImportText" rows="7" spellcheck="false" style="width:100%;font-family:monospace" ' +
      'placeholder="Oladejo Samuel, 09121875253, 08146082051&#10;Bakare Mojeed, 09057118608"></textarea>' +
      '<div class="row-actions" style="margin-top:8px">' +
      '<button class="ghost" type="button" id="guardianImportCheck">Check lines</button>' +
      '<button class="primary" type="button" id="guardianImportSave" disabled>Save checked lines</button>' +
      '</div><p class="muted small" id="guardianImportSummary"></p>' +
      '<div class="table-wrap"><table><thead><tr><th>#</th><th>Student</th><th>Phone (father)</th>' +
      '<th>WhatsApp (mother)</th><th>Status</th><th>Note</th></tr></thead>' +
      '<tbody id="guardianImportRows"><tr><td colspan="6" class="empty">Paste lines above, then press Check lines.</td></tr></tbody></table></div>';
    page.appendChild(card);
    $('#guardianImportCheck').addEventListener('click', () => {
      checkLines().catch((error) => toast((error && error.code) || 'CHECK_FAILED', 'error'));
    });
    $('#guardianImportSave').addEventListener('click', () => {
      saveReady().catch((error) => toast((error && error.code) || 'SAVE_FAILED', 'error'));
    });
  }

  function boot() {
    mount();
    const observer = new MutationObserver(() => {
      if (!document.getElementById('guardianImportCard')) mount();
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();

  window.WTSGuardianImport = { parseLines, validateRow, normaliseNumber, matchStudent };
})();
