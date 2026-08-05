"use strict";

(() => {
  const W = window.WTSRegistry;
  if (!W) return;

  const { $, $$, state, esc, toast, registerView } = W;
  const read = (action, payload = {}) => secureManagement("scopeRead", action, payload);
  const write = (action, payload = {}) => secureManagement("accessWrite", action, payload);
  async function secureManagement(operation, action, payload = {}) {
    const response = await fetch("/api/registry-management", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ operation, action, payload }),
    });
    const result = await response.json().catch(() => ({ ok: false, code: "REGISTRY_MANAGEMENT_INVALID_RESPONSE" }));
    if (!response.ok || result?.ok === false) throw Object.assign(new Error(result?.code || "REGISTRY_MANAGEMENT_FAILED"), { code: result?.code });
    return result;
  }
  const scopeRead = (action, payload = {}) => secureManagement("scopeRead", action, payload);
  const scopeWrite = (action, payload = {}) => secureManagement("scopeWrite", action, payload);
  let catalog = null;
  const DEFAULT_MODULE_ENTRY_PERMISSIONS = {
    results: ["results.view_assigned"],
    attendance: ["attendance.view"],
    notifications: ["notifications.view"],
    central_registry: ["central_registry.view"],
    staff_self_service: ["staff_profile.view", "staff_profile.edit"],
  };

  const empty = (message) => `<div class="empty">${esc(message)}</div>`;
  const formatDate = (value) => value ? new Date(value).toLocaleString("en-NG", { dateStyle: "medium", timeStyle: "short" }) : "Not set";
  const dateValue = (value) => value ? new Date(value).toISOString().slice(0, 16) : "";

  function safeImage(value) {
    return value || "data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 width=%2264%22 height=%2264%22%3E%3Crect width=%2264%22 height=%2264%22 fill=%22%23e8eef6%22/%3E%3Ctext x=%2232%22 y=%2238%22 text-anchor=%22middle%22 font-size=%2224%22 fill=%22%23667085%22%3E%3F%3C/text%3E%3C/svg%3E";
  }

  async function loadCatalog() {
    if (!catalog) catalog = await scopeRead("catalog");
    return catalog;
  }

  async function load() {
    try {
      await loadCatalog();
      const data = await read("staff", { search: $("#accessSearch").value.trim() });
      state.accessStaff = data.staff || [];
      $("#accessStaffList").innerHTML = state.accessStaff.length
        ? state.accessStaff.map((staff) => `<button type="button" class="access-person-button ${state.selectedAccess === staff.staff_id ? "active" : ""}" data-access-staff="${staff.staff_id}"><strong>${esc(staff.full_name)}</strong><small>${esc(staff.staff_number || "No staff number")} · ${esc(staff.designation || staff.staff_category || "Staff")}</small><small>${staff.active_module_count || 0} active module grant${staff.active_module_count === 1 ? "" : "s"}</small></button>`).join("")
        : empty("No active staff member matched this search.");
      $$('[data-access-staff]').forEach((button) => { button.onclick = () => selectStaff(button.dataset.accessStaff); });
    } catch (error) {
      toast(error.message, "error");
    }
  }

  function moduleCard(portal, profile) {
    const grant = (profile.module_grants || []).find((item) => item.app_code === portal.app_code);
    const active = grant?.grant_status === "active";
    const isSelfService = portal.app_code === "staff_self_service";
    const hasEntryDefault = Boolean(
      (grant && Array.isArray(grant.permissions) && grant.permissions.length)
      || DEFAULT_MODULE_ENTRY_PERMISSIONS[portal.app_code]?.length
    );
    const description = isSelfService
      ? "This base profile grant supports the staff member’s unified workspace."
      : "This control grants entry to the module. Internal roles and action permissions remain managed inside the specialist module.";
    return '<article class="portal-card accessModuleCard ' + (active ? "isActive" : "") + '" data-module-card="' + esc(portal.app_code) + '">'
      + '<header><div><strong>' + esc(portal.app_name) + '</strong><small>' + esc(portal.app_code.replaceAll("_", " ")) + '</small></div><span class="badge ' + (active ? "active" : "revoked") + '">' + (active ? "Active" : (grant?.grant_status || "No access")) + '</span></header>'
      + '<p>' + description + '</p>'
      + '<div class="portal-controls">'
      + '<div class="switch-row"><label for="module-enabled-' + esc(portal.app_code) + '">Allow module entry</label><input id="module-enabled-' + esc(portal.app_code) + '" type="checkbox" data-module-enabled="' + esc(portal.app_code) + '" ' + (active ? "checked" : "") + ' ' + (isSelfService ? "disabled" : "") + '></div>'
      + '<div class="accessDateGrid"><label>Effective from<input type="datetime-local" data-module-from="' + esc(portal.app_code) + '" value="' + dateValue(grant?.valid_from) + '"></label><label>Expires (optional)<input type="datetime-local" data-module-until="' + esc(portal.app_code) + '" value="' + dateValue(grant?.valid_until) + '"></label></div>'
      + '<label>Reason<input data-module-reason="' + esc(portal.app_code) + '" value="" placeholder="Required context for this access decision"></label>'
      + '<small class="accessMeta">' + (grant ? ('Last state: ' + esc(grant.grant_status) + ' · existing internal permissions are preserved · effective ' + formatDate(grant.valid_from) + (grant.valid_until ? ' · expires ' + formatDate(grant.valid_until) : "")) : (hasEntryDefault ? "No grant record exists. A least-privilege module entry grant will be created." : "No entry permission is configured for this module yet.")) + '</small>'
      + (isSelfService || !hasEntryDefault ? "" : '<button class="primary" type="button" data-save-module="' + esc(portal.app_code) + '">Save module access</button>')
      + '</div></article>';
  }

  function renderAccount(profile) {
    const staff = profile.staff;
    const suspended = staff.account_status === "suspended";
    return `<article class="accessPanel"><header><div><p class="panelEyebrow">PORTAL ACCOUNT</p><h3>${suspended ? "Access suspended" : "Account active"}</h3></div><span class="badge ${suspended ? "suspended" : "active"}">${esc(staff.account_status)}</span></header><p>${suspended ? "The account cannot create a new workspace session. Existing Central Registry sessions are invalidated when suspension is saved." : "The account may authenticate only while its employment and explicit module grants remain active."}</p><div class="row-actions"><button class="${suspended ? "primary" : "ghost"}" type="button" data-account-status="${suspended ? "active" : "suspended"}">${suspended ? "Restore portal access" : "Suspend portal access"}</button></div></article>`;
  }

  function renderHistory(profile) {
    const history = profile.history || [];
    return `<article class="accessPanel accessHistory"><header><div><p class="panelEyebrow">AUDIT HISTORY</p><h3>Every access decision is recorded.</h3></div></header>${history.length ? `<ol>${history.map((entry) => `<li><strong>${esc(entry.action.replaceAll("_", " ").replaceAll(".", " · "))}</strong><small>${formatDate(entry.created_at)} · ${esc(entry.entity_type)}</small></li>`).join("")}</ol>` : empty("No access-change history was found for this staff member.")}</article>`;
  }

  function installHandlers(profile) {
    $$('[data-save-module]').forEach((button) => {
      button.onclick = async () => {
        const appCode = button.dataset.saveModule;
        const card = button.closest("[data-module-card]");
        const grant = (profile.module_grants || []).find((item) => item.app_code === appCode);
        const portal = (catalog.portals || []).find((item) => item.app_code === appCode);
        const enabled = card.querySelector('[data-module-enabled="' + CSS.escape(appCode) + '"]').checked;
        const permissions = grant
          ? (Array.isArray(grant.permissions) ? grant.permissions.slice() : [])
          : (DEFAULT_MODULE_ENTRY_PERMISSIONS[appCode] || []).slice();
        const accessRole = grant?.access_role || portal?.default_roles?.[0] || "staff";
        await perform("setModuleAccess", {
          staffId: state.selectedAccess,
          appCode,
          enabled,
          accessRole,
          permissions,
          effectiveFrom: card.querySelector('[data-module-from="' + CSS.escape(appCode) + '"]').value,
          expiresAt: card.querySelector('[data-module-until="' + CSS.escape(appCode) + '"]').value,
          reason: card.querySelector('[data-module-reason="' + CSS.escape(appCode) + '"]').value.trim(),
        });
      };
    });
    $("[data-account-status]").onclick = () => perform("setAccountStatus", {
      staffId: state.selectedAccess,
      accountStatus: $("[data-account-status]").dataset.accountStatus,
      reason: "Portal account status changed by management",
    });
  }

  async function perform(action, payload) {
    try {
      const result = action === "setScope" ? await scopeWrite("setScope", payload) : await write(action, payload);
      toast(String(result.code || "Access updated").replaceAll("_", " ").toLowerCase(), "success");
      scopeEditId = "";
      await selectStaff(state.selectedAccess);
      await load();
    } catch (error) {
      toast(error.message, "error");
    }
  }

  async function selectStaff(staffId) {
    try {
      await loadCatalog();
      state.selectedAccess = staffId;
      const profile = await read("staffAccessProfile", { staffId });
      const staff = profile.staff;
      $("#accessPlaceholder").hidden = true;
      $("#accessDetail").hidden = false;
      $("#accessName").textContent = staff.full_name;
      $("#accessMeta").textContent = `${staff.staff_number || "No staff number"} · ${staff.designation || staff.staff_category || "Staff"}`;
      $("#accessPhoto").src = safeImage("");
      $("#accessPhoto").alt = "";
      const modules = (catalog.portals || []).map((portal) => moduleCard(portal, profile)).join("");
      $("#portalCards").innerHTML = `<section class="accessModuleGrid"><div class="accessSectionHead"><div><p class="panelEyebrow">MODULE ACCESS</p><h3>Choose which WTS modules this staff member may enter.</h3></div><p>Central Registry controls module entry. Existing specialist roles, action permissions and Result scopes remain enforced inside their own modules.</p></div><div class="portal-grid">${modules}</div></section>${renderAccount(profile)}${renderHistory(profile)}`;
      installHandlers(profile);
    } catch (error) {
      toast(error.message, "error");
    }
  }

  registerView("access", load);
  window.WTSAccess = { load, select: selectStaff };
})();
