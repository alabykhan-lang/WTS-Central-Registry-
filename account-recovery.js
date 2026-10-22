'use strict';

// Password set/reset page.
//  - Default: Staff Number + shared WTS teacher code + new password. No email needed.
//  - If the page is opened with ?token=… (a link we email later), it asks only
//    for the new password and posts the token instead.

(() => {
  const $ = (selector) => document.querySelector(selector);
  const token = new URLSearchParams(location.search).get('token') || '';
  const form = $('#recoveryCodeForm');
  const statusNode = $('#recoveryStatus');

  function setStatus(message, type = '') {
    if (!statusNode) return;
    statusNode.textContent = message;
    statusNode.className = `recovery-status ${type}`;
  }

  function friendly(code) {
    return ({
      SHARED_TEACHER_CODE_REQUIRED: 'Enter your Staff Number and the shared WTS teacher code.',
      SHARED_TEACHER_CODE_INVALID: 'That Staff Number and teacher code did not match an active teacher record.',
      PASSWORD_CONFIRMATION_REQUIRED: 'Enter the new password twice, matching.',
      PASSWORD_REQUIREMENTS_NOT_MET: 'Use at least 10 characters with an uppercase letter, lowercase letter and number.',
      RECOVERY_TOKEN_REQUIRED: 'That link is incomplete. Use the teacher code instead.',
      RECOVERY_TOKEN_INVALID: 'That reset link is not valid. Use the teacher code instead.',
      RECOVERY_TOKEN_EXPIRED: 'That reset link has expired. Use the teacher code instead.',
      RECOVERY_TOKEN_USED: 'That reset link has already been used. Use the teacher code instead.',
      RECOVERY_SERVICE_NOT_CONFIGURED: 'Password management is not configured. Contact Registry management.',
      RECOVERY_SERVICE_UNAVAILABLE: 'The service is unavailable. Try again shortly.',
      PASSWORD_RESET_FAILED: 'The password could not be saved. Please contact Registry management.',
    })[code] || String(code || 'Request failed.').replaceAll('_', ' ');
  }

  document.querySelectorAll('[data-password-toggle]').forEach((button) => {
    button.onclick = () => {
      const input = document.getElementById(button.dataset.passwordToggle);
      const visible = input.type === 'text';
      input.type = visible ? 'password' : 'text';
      button.textContent = visible ? 'Show password' : 'Hide password';
    };
  });

  if (token) {
    const loginField = $('#recoveryLogin');
    const codeField = $('#recoveryTeacherCode');
    if (loginField) loginField.closest('label').hidden = true;
    if (codeField) codeField.closest('label').hidden = true;
    const hint = $('#recoveryHowTo');
    if (hint) hint.textContent = 'Your reset link works once and expires 30 minutes after it was sent.';
  }

  form.onsubmit = async (event) => {
    event.preventDefault();
    const button = $('#recoveryCodeButton');
    const password = $('#recoveryPassword').value;
    const confirmPassword = $('#recoveryPasswordConfirm').value;
    if (password !== confirmPassword) return setStatus('The passwords do not match.', 'error');

    const body = token
      ? { action: 'complete', token, password, confirmPassword }
      : {
          action: 'shared_code',
          login: $('#recoveryLogin').value.trim(),
          code: $('#recoveryTeacherCode').value.trim(),
          password,
          confirmPassword,
        };

    button.disabled = true;
    setStatus('Saving your password…');
    try {
      const response = await fetch('/api/account-recovery', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify(body),
      });
      const result = await response.json().catch(() => ({ ok: false, code: 'PASSWORD_RESET_FAILED' }));
      if (!response.ok || result?.ok === false) throw Object.assign(new Error(result?.code || 'PASSWORD_RESET_FAILED'), { code: result?.code });
      form.hidden = true;
      setStatus('Password saved. You can now sign in with your Staff Number.', 'success');
    } catch (error) {
      setStatus(friendly(error.code || error.message), 'error');
    } finally {
      button.disabled = false;
    }
  };
})();
