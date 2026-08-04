"use strict";
(() => {
  const APP = "central_registry";
  const STORE = "wts_registry_session";
  const META = "wts_registry_identity_meta";
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

  function friendly(code) {
    return ({
      INVALID_LOGIN: "Invalid staff number, email or password.",
      ACCOUNT_NOT_ACTIVE: "This staff account is not active.",
      ACCOUNT_TEMPORARILY_LOCKED: "Too many failed attempts. Try again later or ask management to unlock the account.",
      PORTAL_ACCESS_NOT_GRANTED: "Central Registry management access has not been granted to this staff account.",
      PASSWORD_REQUIREMENTS_NOT_MET: "New password must be at least 10 characters and contain uppercase, lowercase and a number.",
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

  async function logoutCentral() {
    try {
      await fetch("/api/registry-session", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action: "logout" }) });
    } catch {}
    try {
      const session = JSON.parse(sessionStorage.getItem(STORE) || "null");
      if (session?.code && session?.secret) await call("school_identity_portal_logout", { p_client_code: session.code, p_client_secret: session.secret });
    } catch {}
    sessionStorage.removeItem(META);
  }

  function install() {
    const form = $("#gateForm");
    const login = $("#adminCode");
    const password = $("#adminSecret");
    const error = $("#authError");
    if (!form || typeof form.onsubmit !== "function") return setTimeout(install, 40);
    login.closest("label").childNodes[0].textContent = "Staff number, email or administrator code";
    password.closest("label").childNodes[0].textContent = "Password or administrator secret";
    const legacy = form.onsubmit;
    form.onsubmit = async (event) => {
      event.preventDefault();
      const enteredLogin = login.value.trim();
      const enteredPassword = password.value;
      error.textContent = "Checking central access…";
      try {
        const result = await call("school_identity_portal_login", { p_login: enteredLogin, p_password: enteredPassword, p_app_code: APP });
        if (result.must_change_password) {
          await changeRequired(enteredLogin, enteredPassword);
          error.textContent = "Password changed. Sign in again.";
          password.value = "";
          return;
        }
        try {
          await exchangeSecureSession(result);
        } catch (secureError) {
          console.warn("Central secure session exchange unavailable; compatibility session retained.", secureError?.code || secureError);
        }
        sessionStorage.setItem(META, JSON.stringify({ mode: "central", loginName: enteredLogin, appCode: APP, expiresAt: result.expires_at, person: result.person, accessRole: result.access_role }));
        login.value = result.client_code;
        password.value = result.client_secret;
        legacy.call(form, event);
        setTimeout(() => { login.value = enteredLogin; password.value = ""; }, 0);
      } catch (centralError) {
        login.value = enteredLogin;
        password.value = enteredPassword;
        legacy.call(form, event);
        setTimeout(() => {
          if (document.body.classList.contains("locked")) {
            error.textContent = friendly(centralError.code || centralError.message);
            password.value = "";
          }
        }, 650);
      }
    };
    $("#login")?.addEventListener("click", () => { void logoutCentral(); }, true);
    try {
      const meta = JSON.parse(sessionStorage.getItem(META) || "null");
      if (meta?.loginName && !login.value) login.value = meta.loginName;
    } catch {}
  }
  install();
})();
