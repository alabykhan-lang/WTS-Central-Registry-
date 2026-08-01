"use strict";
(() => {
  const W = window.WTSRegistry;
  if (!W) return;
  const { $, state, esc, toast, rpc } = W;
  let accounts = [];
  let loading = false;

  const read = (action, payload = {}) => rpc("school_identity_admin_read_api", action, payload);

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

  function accountFor(id) {
    return accounts.find((account) => account.staff_id === id);
  }

  async function render() {
    if (!state.selectedAccess || $("#accessDetail")?.hidden) return;
    await loadAccounts();
    const current = accountFor(state.selectedAccess);
    let card = $("#identityAccountCard");
    if (!card) {
      card = document.createElement("article");
      card.id = "identityAccountCard";
      card.className = "portal-card identity-account-card";
      $("#portalCards")?.prepend(card);
    }
    if (!current) {
      card.innerHTML = "<strong>Central login account</strong><p>No linked identity account was found for this staff member.</p>";
      return;
    }
    const locked = current.locked_until && new Date(current.locked_until) > new Date();
    const status = current.credential_status || "pending";
    const accountStatus = current.account_status || "unavailable";
    card.innerHTML = `
      <header><strong>Central staff login</strong><span class="badge ${status === "active" && !locked ? "active" : "revoked"}">${esc(locked ? "locked" : status)}</span></header>
      <p>Login name: <strong>${esc(current.login_name || current.staff_number)}</strong></p>
      <p>Account status: <strong>${esc(accountStatus)}</strong>. Credential state: <strong>${esc(current.must_change_password ? "password change required" : "active")}</strong>.</p>
      <div class="portal-controls"><small>Password activation and recovery are now handled in the protected WTS Workspace System Administration module. That flow requires a live access-management grant, records an audit event and never displays a password hash.</small></div>`;
  }

  function install() {
    if (!window.WTSAccess || !$("#portalCards")) return setTimeout(install, 60);
    const originalSelect = window.WTSAccess.select;
    window.WTSAccess.select = async (id) => {
      await originalSelect(id);
      await render();
    };
    new MutationObserver(() => { setTimeout(() => { void render(); }, 0); }).observe($("#portalCards"), { childList: true });
    void loadAccounts();
  }

  install();
})();
