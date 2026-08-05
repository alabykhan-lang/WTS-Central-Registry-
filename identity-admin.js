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
    } catch (error) { toast(error instanceof Error ? error.message : "Identity account read failed.", "error"); }
    finally { loading = false; }
  }

  async function render() {
    if (!state.selectedAccess || $("#accessDetail")?.hidden) return;
    await loadAccounts();
    const current = accounts.find((account) => account.staff_id === state.selectedAccess);
    let card = $("#identityAccountCard");
    if (!card) { card = document.createElement("article"); card.id = "identityAccountCard"; card.className = "portal-card identity-account-card"; $("#portalCards")?.prepend(card); }
    if (!current) { card.innerHTML = "<strong>Central login account</strong><p>No linked identity account was found for this staff member.</p>"; return; }
    const locked = current.locked_until && new Date(current.locked_until) > new Date();
    const status = current.credential_status || "pending";
    const accountStatus = current.account_status || "unavailable";
    const activationMessage = status === "pending"
      ? "This existing identity has no active password yet. The staff member should use Activate existing account; management does not create or see a password."
      : current.must_change_password
        ? "The account is ready for first-login password creation."
        : "The staff member can use the shared WTS password across assigned modules.";
    card.innerHTML = `<header><strong>Central staff identity</strong><span class="badge ${status === "active" && !locked ? "active" : "revoked"}">${esc(locked ? "locked" : status)}</span></header><p>Login: <strong>${esc(current.login_name || current.staff_number)}</strong></p><p>Account: <strong>${esc(accountStatus)}</strong>. ${esc(activationMessage)}</p><div class="portal-controls"><a class="primary" href="/activate.html?mode=activation" target="_blank" rel="noopener">Open activation instructions</a><small>Password recovery is self-service by verified email. Every credential change revokes old sessions and is audited.</small></div>`;
  }

  function install() {
    if (!window.WTSAccess || !$("#portalCards")) return setTimeout(install, 60);
    const originalSelect = window.WTSAccess.select;
    window.WTSAccess.select = async (id) => { await originalSelect(id); await render(); };
    new MutationObserver(() => { setTimeout(() => { void render(); }, 0); }).observe($("#portalCards"), { childList: true });
    void loadAccounts();
  }
  install();
})();
