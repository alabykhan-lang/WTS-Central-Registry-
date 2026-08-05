'use strict';

(() => {
  const W = window.WTSRegistry;
  if (!W) return;
  const { $, state, esc, toast, registerView, form, field, select, vals } = W;

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

  function date(value) {
    return value ? new Date(value).toLocaleString('en-NG', { dateStyle: 'medium', timeStyle: 'short' }) : 'Not set';
  }

  async function load() {
    try {
      const result = await management('registrationRead', 'list', { status: $('#registrationStatus').value });
      state.registrations = result.registrations || [];
      $('#registrationEmpty').hidden = state.registrations.length > 0;
      $('#registrationRows').innerHTML = state.registrations.map((registration) => {
        const reviewable = ['pending', 'under_review'].includes(registration.registration_status);
        return `<article class="registration-card ${registration.registration_status === 'under_review' ? 'is-reviewing' : ''}"><div><strong>${esc(registration.full_name)}</strong><small>${esc(registration.email || 'No email')} · ${esc(registration.phone || 'No phone')}</small><div class="registration-meta"><span>${esc(registration.registration_status.replaceAll('_', ' '))}</span><span>Submitted ${esc(date(registration.submitted_at))}</span>${registration.has_photo ? '<span>Photo supplied</span>' : '<span>No photo</span>'}${registration.emergency_contact_supplied ? '<span>Emergency contact supplied</span>' : ''}</div></div><div class="row-actions">${reviewable ? `<button type="button" data-registration-review="${registration.id}">Mark under review</button><button type="button" class="primary" data-registration-approve="${registration.id}">Approve</button><button type="button" data-registration-reject="${registration.id}">Reject</button>` : `<button type="button" data-registration-detail="${registration.id}">View details</button>`}</div></article>`;
      }).join('');
      bind();
    } catch (error) {
      toast(error.message, 'error');
    }
  }

  function approveForm(registration) {
    form(
      'Approve staff registration',
      `<div class="full"><strong>${esc(registration.full_name)}</strong><p class="form-help">Approval creates one active identity and a server-generated immutable staff number. It does not create a password or grant specialist modules.</p></div>`
        + field('designation', 'Position', '', 'text', 'full')
        + field('department', 'Department')
        + field('schoolSection', 'School section')
        + select('staffCategory', 'Staff category', [['teaching', 'Teaching'], ['non_teaching', 'Non-teaching'], ['management', 'Management'], ['contract', 'Contract'], ['casual', 'Casual']], 'teaching')
        + field('reason', 'Approval note', 'Approved after management review', 'text', 'full'),
      async (element) => {
        const values = vals(element);
        const result = await management('registrationWrite', 'approve', { registrationId: registration.id, ...values });
        toast(`Approved. Staff number: ${result.staff_number}`, 'success');
        await load();
      },
    );
  }

  async function bind() {
    document.querySelectorAll('[data-registration-review]').forEach((button) => {
      button.onclick = async () => {
        try {
          await management('registrationWrite', 'underReview', { registrationId: button.dataset.registrationReview });
          toast('Registration marked under review.', 'success');
          await load();
        } catch (error) { toast(error.message, 'error'); }
      };
    });
    document.querySelectorAll('[data-registration-approve]').forEach((button) => {
      button.onclick = () => {
        const registration = state.registrations.find((item) => item.id === button.dataset.registrationApprove);
        if (registration) approveForm(registration);
      };
    });
    document.querySelectorAll('[data-registration-reject]').forEach((button) => {
      button.onclick = async () => {
        const reason = prompt('Why is this registration being rejected?');
        if (!reason?.trim()) return;
        try {
          await management('registrationWrite', 'reject', { registrationId: button.dataset.registrationReject, reason: reason.trim() });
          toast('Registration rejected. No identity was created.', 'success');
          await load();
        } catch (error) { toast(error.message, 'error'); }
      };
    });
    document.querySelectorAll('[data-registration-detail]').forEach((button) => {
      button.onclick = async () => {
        try {
          const result = await management('registrationRead', 'detail', { registrationId: button.dataset.registrationDetail });
          const item = result.registration;
          alert(`${item.full_name}\n${item.email || 'No email'}\n${item.phone || 'No phone'}\n${item.address || 'No address'}\n${item.emergency_contact || 'No emergency contact'}`);
        } catch (error) { toast(error.message, 'error'); }
      };
    });
  }

  registerView('registration', load);
  $('#registrationStatus').onchange = load;
  $('#registrationFind').onclick = load;
  window.WTSRegistrationAdmin = { load };
})();
