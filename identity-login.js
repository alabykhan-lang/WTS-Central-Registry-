"use strict";
(() => {
  const APP = "central_registry";
  const CFG = window.WTS_CONFIG;
  const $ = (selector) => document.querySelector(selector);

  async function call(name, args) {
    const response = await fetch(`${CFG.supabaseUrl}/rest/v1/rpc/${name}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", apikey: CFG.publishableKey },
      body: JSON.stringify(args),
    });
    const payload = await response.json().catch(() => ({ ok: false, code: "INVALID_SERVER_RESPONSE" }));
    if (!response.ok || payload?.ok === false) {
      const error = new Error(payload?.code || "LOGIN_FAILED");
      error.code = payload?.code || "LOGIN_FAILED";
      throw error;
    }
    return payload;
  }

  async function exchangeSecureSession(result) {
    const response = await fetch("/api/registry-session", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ action: "exchange", client_code: result.client_code, client_secret: result.client_secret }),
    });
    const payload = await response.json().catch(() => ({ ok: false, code: "CENTRAL_SESSION_EXCHANGE_FAILED" }));
    if (!response.ok || payload?.ok === false) {
      const error = new Error(payload?.code || "CENTRAL_SESSION_EXCHANGE_FAILED");
      error.code = payload?.code || "CENTRAL_SESSION_EXCHANGE_FAILED";
      throw error;
    }
    return payload;
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
      CENTRAL_SESSION_EXCHANGE_FAILED: "The secure Registry session could not be created. Try again.",
    })[code] || String(code || "Login failed.").replaceAll("_", " ");
  }

  async function changeRequired(login, current) {
    const next = prompt("Create a new password. Use at least 10 characters with uppercase, lowercase and a number.");
    if (!next) throw Object.assign(new Error("Password change is required before first login."), { code: "PASSWORD_CHANGE_REQUIRED" });
    const confirmPassword = prompt("Enter the new password again.");
    if (next !== confirmPassword) throw Object.assign(new Error("The new passwords do not match."), { code: "PASSWORD_MISMATCH" });
    await call("school_identity_change_password", { p_login: login, p_current_password: current, p_new_password: next });
    alert("Password changed successfully. Sign in again with the new password.");
  }

  function install() {
    const form = $("#gateForm");
    const login = $("#adminCode");
    const password = $("#adminSecret");
    const error = $("#authError");
    if (!form || typeof form.onsubmit !== "function") return setTimeout(install, 40);
    login.closest("label").childNodes[0].textContent = "Staff number, email or administrator code";
    password.closest("label").childNodes[0].textContent = "Password";
    form.onsubmit = async (event) => {
      event.preventDefault();
      const enteredLogin = login.value.trim();
      const enteredPassword = password.value;
      error.textContent = "Checking central access...";
      try {
        const result = await call("school_identity_portal_login", { p_login: enteredLogin, p_password: enteredPassword, p_app_code: APP });
        if (result.must_change_password) {
          await changeRequired(enteredLogin, enteredPassword);
          error.textContent = "Password changed. Sign in again.";
          password.value = "";
          return;
        }
        await exchangeSecureSession(result);
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