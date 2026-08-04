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
      INVALID_LOGIN: "Invalid staff number, email or password.",
      ACCOUNT_NOT_ACTIVE: "This staff account is not active.",
      ACCOUNT_TEMPORARILY_LOCKED: "Too many failed attempts. Try again later or ask management to unlock the account.",
      PORTAL_ACCESS_NOT_GRANTED: "Central Registry management access has not been granted to this staff account.",
      PASSWORD_REQUIREMENTS_NOT_MET: "New password must be at least 10 characters and contain uppercase, lowercase and a number.",
       CENTRAL_SESSION_SERVICE_UNAVAILABLE: "The secure Registry session could not be created. Try again.",
    })[code] || String(code || "Login failed.").replaceAll("_", " ");
  }

  async function changeRequired(login, current) {
    const next = prompt("Create a new password. Use at least 10 characters with uppercase, lowercase and a number.");
    if (!next) throw Object.assign(new Error("Password change is required before first login."), { code: "PASSWORD_CHANGE_REQUIRED" });
    const confirmPassword = prompt("Enter the new password again.");
    if (next !== confirmPassword) throw Object.assign(new Error("The new passwords do not match."), { code: "PASSWORD_MISMATCH" });
    await sessionRequest("change_password", { login, current_password: current, new_password: next });
    alert("Password changed successfully. Sign in again with the new password.");
  }

  function install() {
    const form = $("#gateForm");
    const login = $("#adminCode");
    const password = $("#adminSecret");
    const error = $("#authError");
    if (!form || typeof form.onsubmit !== "function") return setTimeout(install, 40);
    login.closest("label").childNodes[0].textContent = "Staff number or official email";
    password.closest("label").childNodes[0].textContent = "Password";
    form.onsubmit = async (event) => {
      event.preventDefault();
      const enteredLogin = login.value.trim();
      const enteredPassword = password.value;
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
