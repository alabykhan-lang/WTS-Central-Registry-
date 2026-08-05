"use strict";
(() => {
  const $ = (selector) => document.querySelector(selector);

  async function sessionRequest(action, payload = {}) {
    const response = await fetch("/api/registry-session", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ action, ...payload }),
    });
    const responsePayload = await response.json().catch(() => ({ ok: false, code: "INVALID_SERVER_RESPONSE" }));
    if (!response.ok || responsePayload?.ok === false) {
      const error = new Error(responsePayload?.code || "LOGIN_FAILED");
      error.code = responsePayload?.code || "LOGIN_FAILED";
      throw error;
    }
    return responsePayload;
  }

  async function logoutCentral() {
    try {
      await fetch("/api/registry-session", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "logout" }),
      });
    } catch {}
  }

  function friendly(code) {
    return ({
      INVALID_LOGIN: "The staff number/email or password is incorrect. Check your current password and try again.",
      LOGIN_AND_PASSWORD_REQUIRED: "Enter your staff number or official email and password.",
      ACCOUNT_NOT_ACTIVE: "This staff account is not active.",
      ACCOUNT_TEMPORARILY_LOCKED: "Too many failed attempts. Try again later or ask management to unlock the account.",
      PORTAL_ACCESS_NOT_GRANTED: "Central Registry management access has not been granted to this staff account.",
      MANAGEMENT_ACCESS_DENIED: "Central Registry management permission has not been granted to this staff account.",
      PASSWORD_REQUIREMENTS_NOT_MET: "New password must be at least 10 characters and contain uppercase, lowercase and a number.",
      PASSWORD_MISMATCH: "The new passwords do not match.",
       CENTRAL_SESSION_SERVICE_UNAVAILABLE: "The secure Registry session could not be created. Try again.",
    })[code] || String(code || "Login failed.").replaceAll("_", " ");
  }

  async function changeRequired(login, current) {
    const dialog = $("#requiredPasswordDialog");
    const form = $("#requiredPasswordForm");
    const nextInput = $("#requiredPassword");
    const confirmInput = $("#requiredPasswordConfirm");
    const error = $("#requiredPasswordError");
    if (!dialog || !form) throw Object.assign(new Error("Password change is required before first login."), { code: "PASSWORD_CHANGE_REQUIRED" });
    return new Promise((resolve, reject) => {
      const close = () => { if (dialog.open) dialog.close(); };
      const cancel = () => { cleanup(); close(); reject(Object.assign(new Error("Password change is required before first login."), { code: "PASSWORD_CHANGE_REQUIRED" })); };
      const submit = async (event) => {
        event.preventDefault();
        const next = nextInput.value;
        const confirmPassword = confirmInput.value;
        if (next !== confirmPassword) { error.textContent = friendly("PASSWORD_MISMATCH"); return; }
        error.textContent = "Saving password…";
        try {
          await sessionRequest("change_password", { login, current_password: current, new_password: next });
          cleanup();
          close();
          nextInput.value = "";
          confirmInput.value = "";
          resolve();
        } catch (changeError) { error.textContent = friendly(changeError.code || changeError.message); }
      };
      const cleanup = () => {
        form.removeEventListener("submit", submit);
        $("#requiredPasswordCancel")?.removeEventListener("click", cancel);
        dialog.removeEventListener("cancel", cancel);
      };
      form.addEventListener("submit", submit);
      $("#requiredPasswordCancel")?.addEventListener("click", cancel);
      dialog.addEventListener("cancel", cancel, { once: true });
      error.textContent = "";
      nextInput.value = "";
      confirmInput.value = "";
      dialog.showModal();
      nextInput.focus();
    });
  }

  function install() {
    const form = $("#gateForm");
    const login = $("#adminCode");
    const password = $("#adminSecret");
    const error = $("#authError");
    if (!form || typeof form.onsubmit !== "function") return setTimeout(install, 40);
    login.closest("label").childNodes[0].textContent = "Staff number or official email";
    password.closest("label").childNodes[0].textContent = "Password";
    document.querySelectorAll("[data-password-toggle]").forEach((button) => {
      button.onclick = () => {
        const input = document.getElementById(button.dataset.passwordToggle);
        const visible = input.type === "text";
        input.type = visible ? "password" : "text";
        button.textContent = visible ? "Show password" : "Hide password";
      };
    });
    form.onsubmit = async (event) => {
      event.preventDefault();
      const enteredLogin = login.value.trim();
      const enteredPassword = password.value;
      if (!enteredLogin || !enteredPassword) {
        error.textContent = friendly("LOGIN_AND_PASSWORD_REQUIRED");
        (enteredLogin ? password : login).focus();
        return;
      }
      error.textContent = "Checking central access...";
      try {
        const result = await sessionRequest("login", { login: enteredLogin, password: enteredPassword });
        if (result.must_change_password) {
          await changeRequired(enteredLogin, enteredPassword);
          error.textContent = "Password changed. Sign in again.";
          password.value = "";
          return;
        }
        login.value = enteredLogin;
        password.value = "";
        error.textContent = "";
        await window.WTSRecords.loadContext();
        window.WTSRegistry.connected(true);
      } catch (centralError) {
        await logoutCentral();
        password.value = "";
        window.WTSRegistry.connected(false, friendly(centralError.code || centralError.message));
      }
    };
  }
  install();
})();

