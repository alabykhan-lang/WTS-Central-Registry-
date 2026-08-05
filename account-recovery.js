'use strict';

(() => {
  const $ = (selector) => document.querySelector(selector);
  const params = new URLSearchParams(window.location.search);
  const token = params.get('token') || '';
  const mode = params.get('mode') === 'reset' ? 'reset' : 'activation';
  const isReset = mode === 'reset';

  function setStatus(message, type = '') {
    const node = $('#recoveryStatus');
    node.textContent = message;
    node.className = `recovery-status ${type}`;
  }

  function friendly(code) {
    return ({
      RECOVERY_EMAIL_NOT_CONFIGURED: 'Email delivery is not configured yet. Please contact Registry management.',
      RECOVERY_EMAIL_DELIVERY_FAILED: 'The email could not be sent. Please try again later.',
      RECOVERY_LOGIN_REQUIRED: 'Enter your Staff Number or registered email.',
      RECOVERY_EMAIL_REQUIRED: 'Enter the verified email on your Registry identity.',
      PASSWORD_CONFIRMATION_REQUIRED: 'Enter the same new password twice.',
      PASSWORD_REQUIREMENTS_NOT_MET: 'Use at least 10 characters with uppercase, lowercase and a number.',
      RECOVERY_TOKEN_INVALID: 'This security link is not valid. Request a new one.',
      RECOVERY_TOKEN_ALREADY_USED: 'This security link has already been used. Request a new one.',
      RECOVERY_TOKEN_EXPIRED: 'This security link has expired. Request a new one.',
      ACCOUNT_NOT_ACTIVE: 'This staff identity is not active. Contact Registry management.',
    })[code] || String(code || 'Request failed.').replaceAll('_', ' ');
  }

  async function requestAccess(event) {
    event.preventDefault();
    const button = $('#recoveryRequestButton');
    button.disabled = true;
    setStatus('Checking the Registry and preparing a secure email…');
    try {
      const response = await fetch('/api/account-recovery', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ action: 'request', purpose: isReset ? 'reset' : 'activation', login: $('#recoveryLogin').value.trim() }),
      });
      const result = await response.json().catch(() => ({ ok: false, code: 'RECOVERY_INVALID_RESPONSE' }));
      if (!response.ok || result?.ok === false) throw Object.assign(new Error(result?.code || 'RECOVERY_FAILED'), { code: result?.code });
      $('#recoveryRequestForm').hidden = true;
      setStatus(result.message || 'If the details are on file, a secure email has been sent.', 'success');
    } catch (error) {
      setStatus(friendly(error.code || error.message), 'error');
    } finally { button.disabled = false; }
  }

  async function completeAccess(event) {
    event.preventDefault();
    const password = $('#recoveryPassword').value;
    const confirmPassword = $('#recoveryPasswordConfirm').value;
    if (password !== confirmPassword) return setStatus('The passwords do not match.', 'error');
    const button = event.currentTarget.querySelector('button[type="submit"]');
    button.disabled = true;
    setStatus('Saving your password securely…');
    try {
      const response = await fetch('/api/account-recovery', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ action: 'complete', token, password, confirmPassword }),
      });
      const result = await response.json().catch(() => ({ ok: false, code: 'RECOVERY_INVALID_RESPONSE' }));
      if (!response.ok || result?.ok === false) throw Object.assign(new Error(result?.code || 'RECOVERY_FAILED'), { code: result?.code });
      $('#recoveryCompleteForm').hidden = true;
      setStatus(isReset ? 'Password reset complete. You can now sign in.' : 'Account activated. You can now sign in to Workspace.', 'success');
    } catch (error) {
      setStatus(friendly(error.code || error.message), 'error');
    } finally { button.disabled = false; }
  }

  function configure() {
    $('#recoveryTitle').textContent = isReset ? 'Reset your WTS password' : 'Activate your existing account';
    $('#recoveryKicker').textContent = isReset ? 'PASSWORD RECOVERY' : 'EXISTING STAFF';
    $('#recoveryIntro').textContent = isReset
      ? 'Use the verified email on your Registry identity. We will send a secure, one-time password reset link.'
      : 'Use your Staff Number or registered email. We will send a secure, one-time activation link to the email already on your Registry identity.';
    $('#recoveryLoginLabel').firstChild.textContent = isReset ? 'Verified email' : 'Staff Number or registered email';
    $('#recoveryRequestHelp').textContent = isReset
      ? 'For security, password recovery accepts email only and never reveals whether an account exists.'
      : 'No new identity is created. Ownership is verified through the registered email.';
    $('#recoveryRequestButton').textContent = isReset ? 'Send password reset email' : 'Send activation email';
    $('#activationModeLink').classList.toggle('active', !isReset);
    $('#resetModeLink').classList.toggle('active', isReset);
    $('#recoveryRequestForm').hidden = Boolean(token);
    $('#recoveryCompleteForm').hidden = !token;
    $('#recoveryCompleteIntro').textContent = isReset ? 'Create a new password. Old sessions will be revoked.' : 'Create a password to finish activation and open Workspace.';
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
  $('#recoveryRequestForm').onsubmit = requestAccess;
  $('#recoveryCompleteForm').onsubmit = completeAccess;
})();
