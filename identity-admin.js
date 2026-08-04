"use strict";
(() => {
  const W = window.WTSRegistry;
  if (!W) return;
  const { $, state, esc, toast, rpc } = W;
  let accounts = [];
  let loading = false;
  let oneTimeCredential = null;
  let oneTimeCredentialStaffId = null;

  const read = (action, payload = {}) => rpc("school_identity_admin_read_api", action, payload);
  async function write(action, payload = {}) {
    const response = await fetch("/api/registry-management", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ operation: "credentialWrite", action, payload }),
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

  function accountFor(id) {
    return accounts.find((account) => account.staff_id === id);
  }

  async function render() {
    if (!state.selectedAccess || $("#accessDetail")?.hidden) return;
    await loadAccounts();
    const current = accountFor(state.selectedAccess);
    if (oneTimeCredentialStaffId !== state.selectedAccess) {
      oneTimeCredential = null;
      oneTimeCredentialStaffId = state.selectedAccess;
    }
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
      <div class="portal-controls"><small>Password activation and recovery use the existing person identity. Issuing a new one-time credential clears expired lock state, requires a password change at first login, revokes existing sessions and records the initiating administrator.</small><label>Reason for activation or recovery<input id="credentialReason" placeholder="At least 8 characters" maxlength="500"></label><button type="button" class="primary" id="issueCredential">Issue one-time credential</button><div id="credentialResult">${oneTimeCredential ? `<div class="credential-one-time"><strong>Display once through an approved private channel.</strong><p>Login: <code>${esc(oneTimeCredential.loginName)}</code></p><p>Temporary password: <code>${esc(oneTimeCredential.password)}</code></p><small>Password change is compulsory at first login. This value is not stored by the Registry interface.</small></div>` : ""}</div></div>`;
    $("#issueCredential").onclick = async () => {
      const reason = $("#credentialReason").value.trim();
      if (reason.length < 8) {
        toast("Enter a reason of at least 8 characters.", "error");
        return;
      }
      const button = $("#issueCredential");
      button.disabled = true;
      try {
        const result = await write("issueTemporaryCredential", { staffId: state.selectedAccess, reason });
        oneTimeCredential = { loginName: result.login_name || current.login_name || current.staff_number, password: result.temporary_password || "Unavailable" };
        await loadAccounts(true);
        await render();
      } catch (error) {
        toast(error instanceof Error ? error.message : "Credential recovery failed.", "error");
      } finally {
        button.disabled = false;
      }
    };
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

