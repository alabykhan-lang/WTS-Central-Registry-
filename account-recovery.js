'use strict';

(() => {
  const $ = (selector) => document.querySelector(selector);
  function setStatus(message, type = '') { const node = $('#recoveryStatus'); node.textContent = message; node.className = `recovery-status ${type}`; }
  function friendly(code) {
    return ({
      PASSWORD_RESET_INPUT_REQUIRED: 'Enter your Staff Number, registered email or phone and matching passwords.',
      STAFF_RECORD_VERIFICATION_FAILED: 'The Staff Number and registered email or phone do not match an active staff record.',
      ACCOUNT_TEMPORARILY_LOCKED: 'Password access is temporarily locked. Please wait 15 minutes and try again.',
      PASSWORD_REQUIREMENTS_NOT_MET: 'Use at least 10 characters with uppercase, lowercase and a number.',
      PASSWORD_RESET_FAILED: 'The password could not be saved. Please contact Registry management.',
    })[code] || String(code || 'Request failed.').replaceAll('_', ' ');
  }
  async function savePassword(event) {
    event.preventDefault();
    const button = $('#recoveryCodeButton');
    const password = $('#recoveryPassword').value;
    const confirmPassword = $('#recoveryPasswordConfirm').value;
    if (password !== confirmPassword) return setStatus('The passwords do not match.', 'error');
    button.disabled = true;
    setStatus('Verifying your staff record and saving your password…');
    try {
      const response = await fetch('/api/account-recovery', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ action: 'reset', login: $('#recoveryLogin').value.trim(), contact: $('#recoveryContact').value.trim(), password, confirmPassword }),
      });
      const result = await response.json().catch(() => ({ ok: false, code: 'PASSWORD_RESET_FAILED' }));
      if (!response.ok || result?.ok === false) throw Object.assign(new Error(result?.code || 'PASSWORD_RESET_FAILED'), { code: result?.code });
      event.currentTarget.hidden = true;
      setStatus('Password saved. You can now sign in directly with your Staff Number or email.', 'success');
    } catch (error) { setStatus(friendly(error.code || error.message), 'error'); }
    finally { button.disabled = false; }
  }
  document.querySelectorAll('[data-password-toggle]').forEach((button) => {
    button.onclick = () => { const input = document.getElementById(button.dataset.passwordToggle); const visible = input.type === 'text'; input.type = visible ? 'password' : 'text'; button.textContent = visible ? 'Show password' : 'Hide password'; };
  });
  $('#recoveryCodeForm').onsubmit = savePassword;
})();
