"use strict";
(() => {
  const $ = (selector) => document.querySelector(selector);

  const TRANSACTION_KEY = "wts_central_registry_pkce_transaction";
  const CFG = window.WTS_CONFIG || {};

  function base64Url(bytes) {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function randomToken() {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return base64Url(bytes);
  }

  async function codeChallenge(verifier) {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
    return base64Url(new Uint8Array(digest));
  }

  function saveTransaction(transaction) {
    sessionStorage.setItem(TRANSACTION_KEY, JSON.stringify(transaction));
  }

  function loadTransaction() {
    try {
      const transaction = JSON.parse(sessionStorage.getItem(TRANSACTION_KEY) || "null");
      if (!transaction || !transaction.verifier || !transaction.state || !transaction.nonce || Number(transaction.expires_at) <= Date.now()) return null;
      return transaction;
    } catch { return null; }
  }

  function clearTransaction() { sessionStorage.removeItem(TRANSACTION_KEY); }

  async function beginSso() {
    if (window.__WTS_CENTRAL_SSO_PENDING) return;
    window.__WTS_CENTRAL_SSO_PENDING = true;
    $("#authError").textContent = "Opening the existing WTS Workspace session…";
    const verifier = randomToken();
    const state = randomToken();
    const nonce = randomToken();
    const challenge = await codeChallenge(verifier);
    saveTransaction({ verifier, state, nonce, expires_at: Date.now() + 5 * 60 * 1000 });
    const authorize = new URL(CFG.authorizeUri);
    authorize.searchParams.set("response_type", "code");
    authorize.searchParams.set("client_id", "central_registry");
    authorize.searchParams.set("redirect_uri", CFG.redirectUri);
    authorize.searchParams.set("scope", "central_registry");
    authorize.searchParams.set("code_challenge", challenge);
    authorize.searchParams.set("code_challenge_method", "S256");
    authorize.searchParams.set("state", state);
    authorize.searchParams.set("nonce", nonce);
    window.location.assign(authorize.toString());
  }

  async function exchangeCallback() {
    const query = new URLSearchParams(window.location.search);
    const errorCode = query.get("error") || query.get("code_error");
    if (errorCode) throw Object.assign(new Error(friendly(errorCode)), { code: errorCode });
    const code = query.get("code");
    const returnedState = query.get("state");
    const returnedNonce = query.get("nonce");
    if (!code && !returnedState && !returnedNonce) return false;
    const transaction = loadTransaction();
    if (!code || !returnedState || !returnedNonce || !transaction || returnedState !== transaction.state || returnedNonce !== transaction.nonce) {
      clearTransaction();
      throw Object.assign(new Error("The Registry sign-in response could not be verified. Start again from the Staff Portal."), { code: "SSO_CALLBACK_INVALID" });
    }
    const result = await sessionRequest("sso_exchange", {
      grant_type: "authorization_code",
      client_id: "central_registry",
      redirect_uri: CFG.redirectUri,
      code,
      state: returnedState,
      nonce: returnedNonce,
      code_verifier: transaction.verifier,
    });
    clearTransaction();
    window.history.replaceState({}, document.title, `${window.location.pathname}${window.location.hash}`);
    return Boolean(result?.ok);
  }

  async function checkSession() {
    const response = await fetch("/api/registry-session", { credentials: "same-origin", headers: { Accept: "application/json" }, cache: "no-store" });
    const result = await response.json().catch(() => ({ ok: false }));
    if (!response.ok || !result?.ok) return false;
    await window.WTSRecords.loadContext();
    window.WTSRegistry.connected(true);
    return true;
  }

  async function bootstrap() {
    try {
      if (await exchangeCallback()) { await checkSession(); return; }
      if (await checkSession()) return;
      if (new URLSearchParams(window.location.search).get("sso") === "1") await beginSso();
    } catch (error) {
      clearTransaction();
      $("#authError").textContent = friendly(error.code || error.message);
    }
  }

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
       CENTRAL_REGISTRY_ACCESS_NOT_GRANTED: "Central Registry management access has not been granted to this staff account.",
       NOTIFICATIONS_ACCESS_NOT_GRANTED: "Notification access has not been granted to this staff account.",
       SSO_CALLBACK_INVALID: "The secure Registry response could not be verified. Start again from the Staff Portal.",
       SSO_REQUEST_INVALID: "The Registry sign-in request was not accepted.",
       SSO_EXCHANGE_FAILED: "The secure Registry sign-in could not be completed. Start again from the Staff Portal.",
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
    void bootstrap();
  }
  install();
})();

