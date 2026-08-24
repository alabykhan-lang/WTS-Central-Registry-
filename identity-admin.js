"use strict";

(() => {
  const W = window.WTSRegistry;
  if (!W) return;
  const { $, state, esc, toast } = W;
  let accounts = [];
  let loading = false;

  async function read(action, payload = {}) {
    const response = await fetch("/api/registry-management", {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ operation: "identityRead", action, payload }),
    });
    const result = await response.json().catch(() => ({ ok: false, code: "REGISTRY_MANAGEMENT_INVALID_RESPONSE" }));
    if (!response.ok || result?.ok === false) throw Object.assign(new Error(result?.code || "REGISTRY_MANAGEMENT_FAILED"), { code: result?.code });
    return result;
  }

  async function loadAccounts(force = false) {
    if (loading || (accounts.length && !force)) return;
    loading = true;
    try {
      const result = await read("staffAccounts", {});
      accounts = Array.isArray(result.accounts) ? result.accounts : [];
    } catch (error) {
      toast(error instanceof Error ? error.message : "Identity account read failed.", "error");
    } finally {
      loading = false;
    }
  }

  function accountMessage(current) {
    const status = current.credential_status || "pending";
    if (status === "pending" || !current.credential_id) {
      return "This existing teacher can use the shared WTS teacher code with their Staff Number to create a password.";
    }
    if (current.must_change_password) return "The teacher can use the shared WTS teacher code to complete first-login password creation.";
    return "The teacher can sign in normally and may use the shared WTS teacher code for self-service password recovery.";
  }

  function codeCard(current) {
    return `<section class="identity-code-panel">
      <div class="identity-code-heading"><div><p class="panelEyebrow">TEACHER SELF-SERVICE</p><h3>Shared teacher access enabled</h3></div><span class="badge active">NO ISSUANCE NEEDED</span></div>
      <p>${esc(current.full_name)} can use their Staff Number and the school’s shared teacher access code on the activation or password-reset page. Management does not need to generate an individual code.</p>
      <small class="accessMeta">Every successful activation or password reset is recorded against the individual teacher account.</small>
    </section>`;
  }

  async function render() {
    if (!state.selectedAccess || $("#accessDetail")?.hidden) return;
    await loadAccounts();
    const current = accounts.find((account) => account.staff_id === state.selectedAccess);
    let card = $("#identityAccountCard");
    if (!card) {
      card = document.createElement("article");
      card.id = "identityAccountCard";
      card.className = "portal-card identity-account-card";
      $("#portalCards")?.prepend(card);
    }
    if (!current) {
      card.innerHTML = "<strong>Central WTS identity</strong><p>No linked identity account was found for this staff member.</p>";
      return;
    }
    const locked = current.locked_until && new Date(current.locked_until) > new Date();
    const status = current.credential_status || "pending";
    const accountStatus = current.account_status || "unavailable";
    card.innerHTML = `<header><strong>Central WTS identity</strong><span class="badge ${status === "active" && !locked ? "active" : "revoked"}">${esc(locked ? "locked" : status)}</span></header><p>Login: <strong>${esc(current.login_name || current.staff_number)}</strong></p><p>Account: <strong>${esc(accountStatus)}</strong>. ${esc(accountMessage(current))}</p>${codeCard(current)}`;
  }

  function install() {
    if (!window.WTSAccess || !$("#portalCards")) return setTimeout(install, 60);
    if (!window.__WTSIdentityAdminInstalled) {
      const originalSelect = window.WTSAccess.select;
      window.WTSAccess.select = async (id) => { await originalSelect(id); await render(); };
      window.__WTSIdentityAdminInstalled = true;
      new MutationObserver(() => {
        if (!$("#identityAccountCard")) setTimeout(() => { void render(); }, 0);
      }).observe($("#portalCards"), { childList: true });
    }
    void loadAccounts();
  }
  install();
})();
