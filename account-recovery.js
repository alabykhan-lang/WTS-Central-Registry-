'use strict';

(() => {
  const $ = (selector) => document.querySelector(selector);
  const params = new URLSearchParams(location.search);
  const token = params.get('token') || '';

  const requestForm = $('#recoveryRequestForm');
  const completeForm = $('#recoveryCodeForm');
  const statusNode = $('#recoveryStatus');

  function setStatus(message, type = '') {
    if (!statusNode) return;
    statusNode.textContent = message;
    statusNode.className = `recovery-status ${type}`;
  }

  function friendly(code) {
    return ({
      RECOVERY_LOGIN_REQUIRED: 'Enter your Staff Number or the email held by the Registry.',
      RECOVERY_TOKEN_REQUIRED: 'That link is incomplete. Request a new reset email.',
      RECOVERY_TOKEN_INVALID: 'That reset link is not valid. Request a new one.',
      RECOVERY_TOKEN_EXPIRED: 'That reset link has expired. Request a new one.',
      RECOVERY_TOKEN_USED: 'That reset link has already been used. Request a new one.',
      PASSWORD_CONFIRMATION_REQUIRED: 'Enter the new password twice, matching.',
      PASSWORD_REQUIREMENTS_NOT_MET: 'Use at least 10 characters with an uppercase letter, lowercase letter and number.',
      RECOVERY_EMAIL_NOT_CONFIGURED: 'Password recovery email is not set up yet. Please contact Registry management.',
      RECOVERY_SERVICE_NOT_CONFIGURED: 'Password recovery email is not set up yet. Please contact Registry management.',
      RECOVERY_SERVICE_UNAVAILABLE: 'The recovery service is unavailable. Try again shortly.',
      PASSWORD_RESET_FAILED: 'The password could not be saved. Request a new link and try again.',
    })[code] || String(code || 'Request failed.').replaceAll('_', ' ');
  }

  function enableToggles() {
    document.querySelectorAll('[data-password-toggle]').forEach((button) => {
      button.onclick = () => {
        const input = document.getElementById(button.dataset.passwordToggle);
        const visible = input.type === 'text';
        input.type = visible ? 'password' : 'text';
        button.textContent = visible ? 'Show password' : 'Hide password';
      };
    });
  }

  // --- Step 2: the emailed link carries the token -------------------------
  if (token) {
    if (requestForm) requestForm.hidden = true;
    if (completeForm) completeForm.hidden = false;
    const hint = $('#recoveryHowTo');
    if (hint) hint.textContent = 'Your reset link works once and expires 30 minutes after it was sent.';
    enableToggles();
    completeForm.onsubmit = async (event) => {
      event.preventDefault();
      const button = $('#recoveryCodeButton');
      const password = $('#recoveryPassword').value;
      const confirmPassword = $('#recoveryPasswordConfirm').value;
      if (password !== confirmPassword) return setStatus('The passwords do not match.', 'error');
      button.disabled = true;
      setStatus('Saving your new password…');
      try {
        const response = await fetch('/api/account-recovery', {
          method: 'POST', credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
          body: JSON.stringify({ action: 'complete', token, password, confirmPassword }),
        });
        const result = await response.json().catch(() => ({ ok: false, code: 'PASSWORD_RESET_FAILED' }));
        if (!response.ok || result?.ok === false) throw Object.assign(new Error(result?.code || 'PASSWORD_RESET_FAILED'), { code: result?.code });
        completeForm.hidden = true;
        setStatus('Password saved. You can now sign in with your Staff Number or email.', 'success');
      } catch (error) {
        setStatus(friendly(error.code || error.message), 'error');
      } finally {
        button.disabled = false;
      }
    };
    return;
  }

  // --- Step 1: ask for the email ------------------------------------------
  if (completeForm) completeForm.hidden = true;
  if (requestForm) requestForm.hidden = false;
  requestForm.onsubmit = async (event) => {
    event.preventDefault();
    const button = $('#recoveryRequestButton');
    const login = $('#recoveryLogin').value.trim();
    if (!login) return setStatus('Enter your Staff Number or the email held by the Registry.', 'error');
    button.disabled = true;
    setStatus('Sending your secure link…');
    try {
      const response = await fetch('/api/account-recovery', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ action: 'request', purpose: 'password_reset', login }),
      });
      const result = await response.json().catch(() => ({ ok: false, code: 'RECOVERY_SERVICE_UNAVAILABLE' }));
      if (!response.ok || result?.ok === false) throw Object.assign(new Error(result?.code || 'RECOVERY_SERVICE_UNAVAILABLE'), { code: result?.code });
      requestForm.hidden = true;
      setStatus(result.message || 'If that staff record exists, a secure reset link has been emailed to the address on file.', 'success');
    } catch (error) {
      setStatus(friendly(error.code || error.message), 'error');
    } finally {
      button.disabled = false;
    }
  };
})();
