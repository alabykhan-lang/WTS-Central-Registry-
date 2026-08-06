'use strict';

(() => {
  const $ = (selector) => document.querySelector(selector);
  const params = new URLSearchParams(window.location.search);
  const mode = params.get('mode') === 'reset' ? 'reset' : 'activation';
  const isReset = mode === 'reset';

  function setStatus(message, type = '') {
    const node = $('#recoveryStatus');
    node.textContent = message;
    node.className = `recovery-status ${type}`;
  }

  function friendly(code) {
    return ({
      MANAGEMENT_CODE_INPUT_REQUIRED: 'Enter your Staff Number, management code and matching passwords.',
      MANAGEMENT_CODE_INVALID: 'That code is invalid, expired or already used. Ask authorised management for a new code.',
      ACCOUNT_NOT_ACTIVE: 'This staff identity is not active. Contact Registry management.',
      PASSWORD_REQUIREMENTS_NOT_MET: 'Use at least 10 characters with uppercase, lowercase and a number.',
      MANAGEMENT_CODE_COMPLETION_FAILED: 'The account could not be updated. Ask authorised management to issue a new code.',
    })[code] || String(code || 'Request failed.').replaceAll('_', ' ');
  }

  async function completeAccess(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const button = $('#recoveryCodeButton');
    const password = $('#recoveryPassword').value;
    const confirmPassword = $('#recoveryPasswordConfirm').value;
    if (password !== confirmPassword) return setStatus('The passwords do not match.', 'error');
    button.disabled = true;
    setStatus('Checking the one-time code and saving your password…');
    try {
      const response = await fetch('/api/account-recovery', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({
          action: 'complete_code',
          purpose: isReset ? 'password_reset' : 'activation',
          login: $('#recoveryLogin').value.trim(),
          code: $('#recoveryCode').value.trim(),
          password,
          confirmPassword,
        }),
      });
      const result = await response.json().catch(() => ({ ok: false, code: 'MANAGEMENT_CODE_COMPLETION_FAILED' }));
      if (!response.ok || result?.ok === false) throw Object.assign(new Error(result?.code || 'MANAGEMENT_CODE_COMPLETION_FAILED'), { code: result?.code });
      form.hidden = true;
      setStatus(isReset
        ? 'Password reset complete. You can now sign in to Workspace.'
        : 'Account activated. You can now sign in to Workspace.', 'success');
    } catch (error) {
      setStatus(friendly(error.code || error.message), 'error');
    } finally {
      button.disabled = false;
    }
  }

  function configure() {
    $('#recoveryTitle').textContent = isReset ? 'Reset your WTS password' : 'Activate your existing account';
    $('#recoveryKicker').textContent = isReset ? 'PASSWORD RECOVERY' : 'EXISTING STAFF';
    $('#recoveryIntro').textContent = isReset
      ? 'Use the one-time password-recovery code issued by authorised WTS management. Email is not required.'
      : 'Use the one-time activation code issued by authorised WTS management. Email is not required.';
    $('#recoveryCodeButton').textContent = isReset ? 'Reset password' : 'Activate account';
    $('#activationModeLink').classList.toggle('active', !isReset);
    $('#resetModeLink').classList.toggle('active', isReset);
    document.querySelectorAll('[data-password-toggle]').forEach((button) => {
      button.onclick = () => {
        const input = document.getElementById(button.dataset.passwordToggle);
        const visible = input.type === 'text';
        input.type = visible ? 'password' : 'text';
        button.textContent = visible ? 'Show password' : 'Hide password';
      };
    });
  }

  configure();
  $('#recoveryCodeForm').onsubmit = completeAccess;
})();
