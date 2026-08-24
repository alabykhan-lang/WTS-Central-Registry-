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

  async function write(action, payload = {}) {
    const response = await fetch("/api/registry-management", {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ operation: "identityWrite", action, payload }),
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

  function date(value) {
    if (!value) return "";
    const parsed = new Date(value);
    return Number.isNaN(parsed.valueOf()) ? "" : parsed.toLocaleString("en-NG", { dateStyle: "medium", timeStyle: "short" });
  }

  function accountMessage(current) {
    const status = current.credential_status || "pending";
    if (status === "pending" || !current.credential_id) {
      return "This existing identity has no active WTS password yet. Issue an activation code below; management never creates or sees a password.";
    }
    if (current.must_change_password) return "The account is ready for first-login password creation. A recovery code can complete that process without email.";
    return "The staff member can sign in normally. Issue a password-recovery code only when access needs to be restored.";
  }

  function codeCard(current) {
    return `<section class="identity-code-panel">
      <div class="identity-code-heading"><div><p class="panelEyebrow">NO-EMAIL ACCOUNT HELP</p><h3>Issue a one-time access code</h3></div><span class="badge active">MANAGEMENT ONLY</span></div>
      <p>Give the code directly to this existing staff member through the school office or official school WhatsApp. It expires in 30 minutes, works once, and does not create another identity.</p>
      <div class="row-actions identity-code-actions"><button class="primary" type="button" data-issue-code="activation">Issue activation code</button><button class="ghost" type="button" data-issue-code="password_reset">Issue password-recovery code</button></div>
      <div class="identity-code-result" id="identityCodeResult" hidden><strong>Share this code privately with ${esc(current.full_name)}.</strong><code id="identityCodeValue"></code><div class="row-actions"><button class="ghost" type="button" id="copyIdentityCode">Copy code</button><button class="ghost" type="button" id="hideIdentityCode">Hide code</button></div><small id="identityCodeExpiry"></small></div>
      <small class="accessMeta">The raw code is shown once in this management session. Only its hash is stored and every issuance/completion is audited.</small>
    </section>`;
  }

  function installCodeHandlers(current) {
    document.querySelectorAll("[data-issue-code]").forEach((button) => {
      button.onclick = async () => {
        const statusNode = $("#identityCodeExpiry");
        const purpose = button.dataset.issueCode;
        const buttons = document.querySelectorAll("[data-issue-code]");
        buttons.forEach((item) => { item.disabled = true; });
        if (statusNode) statusNode.textContent = "Generating a secure one-time code…";
        try {
          const result = await write("issueRecoveryCode", {
            staffId: current.staff_id,
            purpose,
          });
          if (!result.recovery_code) throw new Error("RECOVERY_CODE_ISSUE_FAILED");
          const output = $("#identityCodeResult");
          const value = $("#identityCodeValue");
          if (value) value.textContent = result.recovery_code;
          if (statusNode) statusNode.textContent = `Expires ${date(result.expires_at)} · ${purpose === "activation" ? "activation" : "password recovery"} code`;
          if (output) output.hidden = false;
          toast("One-time access code issued. Share it privately with the staff member.", "success");
        } catch (error) {
          if (statusNode) statusNode.textContent = String(error?.code || error?.message || "Code issue failed").replaceAll("_", " ");
          toast(error instanceof Error ? error.message : "Access code issue failed.", "error");
        } finally {
          buttons.forEach((item) => { item.disabled = false; });
        }
      };
    });
    $("#hideIdentityCode")?.addEventListener("click", () => { $("#identityCodeResult").hidden = true; });
    $("#copyIdentityCode")?.addEventListener("click", async () => {
      const value = $("#identityCodeValue")?.textContent || "";
      if (!value) return;
      try {
        await navigator.clipboard.writeText(value);
        toast("Code copied. Share it privately.", "success");
      } catch {
        toast("Copy was blocked by the browser. Select the code and copy it manually.", "error");
      }
    });
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
    installCodeHandlers(current);
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
