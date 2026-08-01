"use strict";

(() => {
  const W = window.WTSRegistry;
  if (!W) return;

  const { $, $$, state, esc, toast, rpc, registerView } = W;
  const read = (action, payload = {}) => rpc("school_access_management_read_api", action, payload);
  const write = (action, payload) => rpc("school_access_management_write_api", action, payload);
  let catalog = null;

  const empty = (message) => `<div class="empty">${esc(message)}</div>`;
  const formatDate = (value) => value ? new Date(value).toLocaleString("en-NG", { dateStyle: "medium", timeStyle: "short" }) : "Not set";
  const dateValue = (value) => value ? new Date(value).toISOString().slice(0, 16) : "";

  function safeImage(value) {
    return value || "data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 width=%2264%22 height=%2264%22%3E%3Crect width=%2264%22 height=%2264%22 fill=%22%23e8eef6%22/%3E%3Ctext x=%2232%22 y=%2238%22 text-anchor=%22middle%22 font-size=%2224%22 fill=%22%23667085%22%3E%3F%3C/text%3E%3C/svg%3E";
  }

  async function loadCatalog() {
    if (!catalog) catalog = await read("catalog");
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

  function portalRoleOptions(portal, grant) {
    const roles = [...new Set([grant?.access_role, ...(portal.default_roles || [])].filter(Boolean))];
    return roles.map((role) => `<option value="${esc(role)}" ${role === grant?.access_role ? "selected" : ""}>${esc(role.replaceAll("_", " "))}</option>`).join("");
  }

  function permissionPicker(appCode, grant) {
    const permissions = (catalog.permissions || []).filter((permission) => permission.app_code === appCode);
    if (!permissions.length) return `<p class="accessHint">No action permissions are configured for this module yet.</p>`;
    const granted = new Set(grant?.permissions || []);
    return `<fieldset class="permissionPicker"><legend>Action permissions</legend>${permissions.map((permission) => `<label><input type="checkbox" data-permission="${esc(permission.permission_code)}" ${granted.has(permission.permission_code) ? "checked" : ""}> <span>${esc(permission.module_name)} · ${esc(permission.action_code)}</span></label>`).join("")}</fieldset>`;
  }

  function moduleCard(portal, profile) {
    const grant = (profile.module_grants || []).find((item) => item.app_code === portal.app_code);
    const active = grant?.grant_status === "active";
    const isSelfService = portal.app_code === "staff_self_service";
    return `<article class="portal-card accessModuleCard ${active ? "isActive" : ""}" data-module-card="${esc(portal.app_code)}">
      <header><div><strong>${esc(portal.app_name)}</strong><small>${esc(portal.app_code.replaceAll("_", " "))}</small></div><span class="badge ${active ? "active" : "revoked"}">${active ? "Active" : grant?.grant_status || "No access"}</span></header>
      <p>${isSelfService ? "A current staff account needs this base profile grant to enter the unified workspace." : "Grant this module deliberately, then select the exact actions permitted for this staff member."}</p>
      <div class="portal-controls">
        <div class="switch-row"><label for="module-enabled-${esc(portal.app_code)}">Allow module</label><input id="module-enabled-${esc(portal.app_code)}" type="checkbox" data-module-enabled="${esc(portal.app_code)}" ${active ? "checked" : ""} ${isSelfService ? "disabled" : ""}></div>
        <label>Module role<select data-module-role="${esc(portal.app_code)}" ${isSelfService ? "disabled" : ""}>${portalRoleOptions(portal, grant)}</select></label>
        ${permissionPicker(portal.app_code, grant)}
        <div class="accessDateGrid"><label>Effective from<input type="datetime-local" data-module-from="${esc(portal.app_code)}" value="${dateValue(grant?.valid_from)}"></label><label>Expires (optional)<input type="datetime-local" data-module-until="${esc(portal.app_code)}" value="${dateValue(grant?.valid_until)}"></label></div>
        <label>Reason<input data-module-reason="${esc(portal.app_code)}" value="" placeholder="Required context for this access decision"></label>
        <small class="accessMeta">${grant ? `Last state: ${esc(grant.grant_status)} · effective ${formatDate(grant.valid_from)}${grant.valid_until ? ` · expires ${formatDate(grant.valid_until)}` : ""}` : "No grant record exists."}</small>
        ${isSelfService ? "" : `<button class="primary" type="button" data-save-module="${esc(portal.app_code)}">Save module access</button>`}
      </div>
    </article>`;
  }

  function renderRoleAssignments(profile) {
    const assigned = profile.role_assignments || [];
    const available = (catalog.roles || []).map((role) => `<option value="${esc(role.role_code)}">${esc(role.role_name)}</option>`).join("");
    return `<article class="accessPanel"><header><div><p class="panelEyebrow">SYSTEM ROLES</p><h3>Responsibilities do not auto-grant access.</h3></div></header><p>Assign role labels for the staff member’s responsibility, then use the module cards above to grant each permitted action explicitly.</p>
      <div class="assignmentForm"><label>Role<select id="systemRoleSelect">${available}</select></label><label>Effective from<input id="systemRoleFrom" type="datetime-local"></label><label>Expires (optional)<input id="systemRoleUntil" type="datetime-local"></label><label class="full">Reason<input id="systemRoleReason" placeholder="Reason for assigning this responsibility"></label><button type="button" class="primary" data-assign-role>Assign role</button></div>
      <div class="assignmentList">${assigned.length ? assigned.map((role) => `<div class="assignmentRow"><div><strong>${esc(role.role_name)}</strong><small>${esc(role.assignment_status)} · from ${formatDate(role.effective_from)}${role.effective_until ? ` · until ${formatDate(role.effective_until)}` : ""}</small></div>${role.assignment_status === "active" ? `<button type="button" class="ghost" data-revoke-role="${esc(role.role_code)}">Revoke</button>` : ""}</div>`).join("") : empty("No system role has been explicitly assigned.")}</div>
    </article>`;
  }

  function subjectOptions(classKey) {
    const subjects = (catalog.subjects || []).filter((subject) => subject.class_key === classKey);
    return `<option value="">Select subject</option>${subjects.map((subject) => `<option value="${subject.subject_index}">${esc(subject.subject_name)}</option>`).join("")}`;
  }

  function renderScopes(profile) {
    const scopes = profile.scopes || [];
    const classes = `<option value="">Select class</option>${(catalog.classes || []).map((item) => `<option value="${esc(item.class_key)}">${esc(item.display_name)}</option>`).join("")}`;
    return `<article class="accessPanel"><header><div><p class="panelEyebrow">RESULTS SCOPE</p><h3>Classes and subjects</h3></div></header><p>These scopes are the future server-side boundaries for Result Portal work. They do not change existing scores or class records.</p>
      <div class="assignmentForm scopesForm"><label>Class<select id="scopeClassSelect">${classes}</select></label><label>Subject<select id="scopeSubjectSelect" disabled><option value="">Select a class first</option></select></label><label>Effective from<input id="scopeFrom" type="datetime-local"></label><label>Expires (optional)<input id="scopeUntil" type="datetime-local"></label><label class="full">Reason<input id="scopeReason" placeholder="Reason for this class or subject assignment"></label><div class="scopeButtons"><button type="button" class="primary" data-assign-class>Assign whole class</button><button type="button" class="ghost" data-assign-subject>Assign selected subject</button></div></div>
      <div class="assignmentList">${scopes.length ? scopes.map((scope) => `<div class="assignmentRow"><div><strong>${esc(scope.display_name)}${scope.scope_type === "subject" ? ` · ${esc(scope.subject_name)}` : " · Whole class"}</strong><small>${esc(scope.scope_status)} · from ${formatDate(scope.effective_from)}${scope.effective_until ? ` · until ${formatDate(scope.effective_until)}` : ""}</small></div>${scope.scope_status === "active" ? `<button type="button" class="ghost" data-revoke-scope="${scope.id}">Revoke</button>` : ""}</div>`).join("") : empty("No class or subject has been assigned to this staff member.")}</div>
    </article>`;
  }

  function renderAccount(profile) {
    const staff = profile.staff;
    const suspended = staff.account_status === "suspended";
    return `<article class="accessPanel"><header><div><p class="panelEyebrow">PORTAL ACCOUNT</p><h3>${suspended ? "Access suspended" : "Account active"}</h3></div><span class="badge ${suspended ? "suspended" : "active"}">${esc(staff.account_status)}</span></header><p>${suspended ? "The account cannot create a new workspace session. Existing Central Registry sessions are invalidated when suspension is saved." : "The account may authenticate only while its employment and explicit module grants remain active."}</p><div class="row-actions"><button class="${suspended ? "primary" : "ghost"}" type="button" data-account-status="${suspended ? "active" : "suspended"}">${suspended ? "Restore portal access" : "Suspend portal access"}</button></div></article>`;
  }

  function renderDirectory(profile) {
    const staff = profile.staff;
    return `<article class="accessPanel"><header><div><p class="panelEyebrow">PUBLIC STAFF DIRECTORY</p><h3>Explicit publication approval</h3></div></header><p>Active employment alone never publishes a staff member. This only prepares Central Registry data for the public directory’s later approved synchronisation.</p><div class="assignmentForm"><label class="switch-row">Approve public visibility <input id="directoryApproved" type="checkbox" ${staff.public_visibility_approved ? "checked" : ""}></label><label>Approved display name<input id="directoryName" value="${esc(staff.public_display_name || "")}" placeholder="Leave blank to use approved future mapping"></label><label>Approved role<input id="directoryRole" value="${esc(staff.public_display_role || "")}" placeholder="Public designation"></label><label>Display order<input id="directoryOrder" inputmode="numeric" value="${staff.public_display_order ?? ""}"></label><button type="button" class="ghost" data-save-directory>Save directory approval</button></div></article>`;
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
        const enabled = card.querySelector(`[data-module-enabled="${CSS.escape(appCode)}"]`).checked;
        const accessRole = card.querySelector(`[data-module-role="${CSS.escape(appCode)}"]`).value;
        const permissions = [...card.querySelectorAll("[data-permission]:checked")].map((input) => input.dataset.permission);
        await perform("setModuleAccess", { staffId: state.selectedAccess, appCode, enabled, accessRole, permissions, effectiveFrom: card.querySelector(`[data-module-from="${CSS.escape(appCode)}"]`).value, expiresAt: card.querySelector(`[data-module-until="${CSS.escape(appCode)}"]`).value, reason: card.querySelector(`[data-module-reason="${CSS.escape(appCode)}"]`).value.trim() });
      };
    });
    $("[data-assign-role]").onclick = () => perform("setSystemRole", { staffId: state.selectedAccess, roleCode: $("#systemRoleSelect").value, enabled: true, effectiveFrom: $("#systemRoleFrom").value, expiresAt: $("#systemRoleUntil").value, reason: $("#systemRoleReason").value.trim() });
    $$('[data-revoke-role]').forEach((button) => { button.onclick = () => perform("setSystemRole", { staffId: state.selectedAccess, roleCode: button.dataset.revokeRole, enabled: false, reason: "Role responsibility revoked by management" }); });
    $("#scopeClassSelect").onchange = () => {
      const classKey = $("#scopeClassSelect").value;
      const select = $("#scopeSubjectSelect");
      select.disabled = !classKey;
      select.innerHTML = classKey ? subjectOptions(classKey) : "<option value=\"\">Select a class first</option>";
    };
    $("[data-assign-class]").onclick = () => assignScope("class");
    $("[data-assign-subject]").onclick = () => assignScope("subject");
    $$('[data-revoke-scope]').forEach((button) => {
      button.onclick = () => {
        const scope = (profile.scopes || []).find((item) => item.id === button.dataset.revokeScope);
        if (scope) perform("setScope", { staffId: state.selectedAccess, appCode: scope.app_code, scopeType: scope.scope_type, classKey: scope.class_key, subjectIndex: scope.subject_index, enabled: false, reason: "Scope revoked by management" });
      };
    });
    $("[data-account-status]").onclick = () => perform("setAccountStatus", { staffId: state.selectedAccess, accountStatus: $("[data-account-status]").dataset.accountStatus, reason: "Portal account status changed by management" });
    $("[data-save-directory]").onclick = () => perform("setPublicDirectoryVisibility", { staffId: state.selectedAccess, approved: $("#directoryApproved").checked, displayName: $("#directoryName").value.trim(), displayRole: $("#directoryRole").value.trim(), displayOrder: $("#directoryOrder").value.trim() });
  }

  function assignScope(scopeType) {
    const classKey = $("#scopeClassSelect").value;
    const subjectIndex = $("#scopeSubjectSelect").value;
    if (!classKey || (scopeType === "subject" && subjectIndex === "")) {
      toast(scopeType === "subject" ? "Select a class and subject first." : "Select a class first.", "error");
      return;
    }
    perform("setScope", { staffId: state.selectedAccess, appCode: "results", scopeType, classKey, subjectIndex: scopeType === "subject" ? subjectIndex : "", enabled: true, effectiveFrom: $("#scopeFrom").value, expiresAt: $("#scopeUntil").value, reason: $("#scopeReason").value.trim() });
  }

  async function perform(action, payload) {
    try {
      const result = await write(action, payload);
      toast(String(result.code || "Access updated").replaceAll("_", " ").toLowerCase(), "success");
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
      $("#portalCards").innerHTML = `<section class="accessModuleGrid"><div class="accessSectionHead"><div><p class="panelEyebrow">MODULE AND ACTION ACCESS</p><h3>Grant only what this staff member needs.</h3></div><p>Roles are descriptive. Access is enforced by the saved module, action and scope grants below.</p></div><div class="portal-grid">${modules}</div></section>${renderRoleAssignments(profile)}${renderScopes(profile)}${renderAccount(profile)}${renderDirectory(profile)}${renderHistory(profile)}`;
      installHandlers(profile);
    } catch (error) {
      toast(error.message, "error");
    }
  }

  registerView("access", load);
  window.WTSAccess = { load, select: selectStaff };
})();
