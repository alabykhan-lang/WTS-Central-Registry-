"use strict";
(() => {
  const CFG = window.WTS_CONFIG;
  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => [...document.querySelectorAll(selector)];
  const state = {
    context: null,
    students: [],
    staff: [],
    accessStaff: [],
    selectedAccess: null,
    handler: null,
    connected: false,
    currentView: "dashboard",
    views: {},
  };
  const esc = (value) => String(value ?? "").replace(/[&<>'\"]/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "'": "&#39;",
    "\"": "&quot;",
  }[character]));
  function toast(message, type = "") {
    const node = document.createElement("div");
    node.className = `toast ${type}`;
    node.textContent = message;
    $("#toasts")?.append(node);
    setTimeout(() => node.remove(), 4200);
  }
  async function registryRequest(operation, action, payload = {}) {
    const response = await fetch("/api/registry-records", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ operation, action, payload }),
    });
    const result = await response.json().catch(() => ({ ok: false, code: "REGISTRY_RECORDS_INVALID_RESPONSE" }));
    if (!response.ok || result?.ok === false) {
      if (response.status === 401) connected(false, "Central Registry session expired. Sign in again.");
      throw Object.assign(new Error(result?.code || "REGISTRY_RECORDS_FAILED"), { code: result?.code, status: response.status });
    }
    return result;
  }
  function connected(on, message = "") {
    state.connected = on;
    document.body.classList.toggle("locked", !on);
    $("#dot")?.classList.toggle("on", on);
    if ($("#connectionText")) $("#connectionText").textContent = on ? "Registry connected" : "Registry login required";
    if ($("#login")) $("#login").textContent = on ? "Sign out" : "Administrator login";
    if ($("#authError")) $("#authError").textContent = message;
  }
  async function signOut() {
    try {
      await fetch("/api/registry-session", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "logout" }),
      });
    } catch {}
    state.connected = false;
    state.students = [];
    state.staff = [];
    state.accessStaff = [];
    state.selectedAccess = null;
    connected(false);
    $("#adminSecret") && ($("#adminSecret").value = "");
    $("#adminCode")?.focus();
  }
  function registerView(name, loader) { state.views[name] = loader; }
  function view(name) {
    if (!state.connected) return;
    state.currentView = name;
    $$(".view").forEach((node) => node.classList.toggle("active", node.id === `view-${name}`));
    $$(".nav").forEach((button) => button.classList.toggle("active", button.dataset.view === name));
    $("#title").textContent = name === "students" ? "Student Records" : name === "staff" ? "Staff Records" : name === "access" ? "Portal Access" : "Central Registry";
    state.views[name]?.();
  }
  function form(title, html, handler, after) {
    $("#formTitle").textContent = title;
    $("#formBody").innerHTML = html;
    state.handler = handler;
    $("#formDialog").showModal();
    after?.();
  }
  const field = (name, label, value = "", type = "text", full = "") => `<label class="${full}">${label}<input name="${name}" type="${type}" value="${esc(value)}"></label>`;
  const select = (name, label, options, value = "") => `<label>${label}<select name="${name}">${options.map((option) => `<option value="${option[0]}" ${option[0] === value ? "selected" : ""}>${option[1]}</option>`).join("")}</select></label>`;
  const vals = (formElement) => Object.fromEntries(new FormData(formElement).entries());
  window.WTSRegistry = { CFG, $, $$, state, esc, toast, registryRequest, connected, signOut, registerView, view, form, field, select, vals };
})();