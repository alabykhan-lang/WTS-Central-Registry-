"use strict";
(() => {
  const $ = (selector) => document.querySelector(selector);
  const portalUrls = {
    attendance: "https://wts-attendance-system.vercel.app",
    notifications: "https://wts-notification-system.vercel.app",
    central_registry: "/",
    results: "https://wts-result-system.vercel.app",
    staff_self_service: "/staff",
  };
  let authenticated = false;
  let loginName = "";
  let currentPhoto = "";

  function toast(message, type = "") {
    const node = document.createElement("div");
    node.className = `toast ${type}`;
    node.textContent = message;
    $("#toasts")?.appendChild(node);
    setTimeout(() => node.remove(), 4200);
  }

  async function sessionRequest(action, payload = {}) {
    const response = await fetch("/api/staff-session", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ action, ...payload }),
    });
    const responsePayload = await response.json().catch(() => ({ ok: false, code: "INVALID_SERVER_RESPONSE" }));
    if (!response.ok || responsePayload?.ok === false) throw Object.assign(new Error(responsePayload?.code || "REQUEST_FAILED"), { code: responsePayload?.code || "REQUEST_FAILED" });
    return responsePayload;
  }

  async function secureRequest(action, payload = {}) {
    if (!authenticated) throw Object.assign(new Error("STAFF_SESSION_REQUIRED"), { code: "STAFF_SESSION_REQUIRED" });
    const response = await fetch("/api/staff-portal", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ action, payload }),
    });
    const result = await response.json().catch(() => ({ ok: false, code: "STAFF_PORTAL_INVALID_RESPONSE" }));
    if (!response.ok || result?.ok === false) throw Object.assign(new Error(result?.code || "STAFF_PORTAL_FAILED"), { code: result?.code || "STAFF_PORTAL_FAILED" });
    return result;
  }

  function lock(message = "") {
    authenticated = false;
    document.body.classList.add("staff-locked");
    $("#staffLoginError").textContent = message;
    $("#staffPassword").value = "";
    setTimeout(() => $("#staffLoginName")?.focus(), 0);
  }

  function unlock() {
    document.body.classList.remove("staff-locked");
    $("#staffLoginError").textContent = "";
  }

  function friendly(code) {
    return ({
      INVALID_LOGIN: "Invalid staff number, email or password.",
      ACCOUNT_NOT_ACTIVE: "Your staff account is not active.",
      ACCOUNT_TEMPORARILY_LOCKED: "Too many failed attempts. Ask management to unlock the account or try again later.",
      PORTAL_ACCESS_NOT_GRANTED: "Staff self-service access is not active.",
      PASSWORD_REQUIREMENTS_NOT_MET: "Use at least 10 characters with uppercase, lowercase and a number.",
      STAFF_SESSION_SERVICE_UNAVAILABLE: "The secure staff session could not be created. Try again.",
    })[code] || String(code || "Request failed.").replaceAll("_", " ");
  }

  async function firstPasswordChange(login, current) {
    const next = prompt("Create a new password. Use at least 10 characters with uppercase, lowercase and a number.");
    if (!next) throw Object.assign(new Error("Password change is required."), { code: "PASSWORD_CHANGE_REQUIRED" });
    const confirmPassword = prompt("Enter the new password again.");
    if (next !== confirmPassword) throw Object.assign(new Error("The new passwords do not match."), { code: "PASSWORD_MISMATCH" });
    await sessionRequest("change_password", { login, current_password: current, new_password: next });
    alert("Password changed successfully. Sign in again with the new password.");
  }

  async function login(event) {
    event.preventDefault();
    loginName = $("#staffLoginName").value.trim();
    const password = $("#staffPassword").value;
    $("#staffLoginError").textContent = "Checking account...";
    try {
      const result = await sessionRequest("login", { login: loginName, password });
      if (result.must_change_password) {
        await firstPasswordChange(loginName, password);
        lock("Password changed. Sign in again.");
        return;
      }
      authenticated = true;
      await loadProfile();
      unlock();
      toast("Staff portal opened.", "success");
    } catch (error) {
      await fetch("/api/staff-session", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action: "logout" }) }).catch(() => {});
      lock(friendly(error.code || error.message));
    }
  }

  async function logout() {
    await fetch("/api/staff-session", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action: "logout" }) }).catch(() => {});
    loginName = "";
    currentPhoto = "";
    lock();
    toast("Signed out.");
  }

  const blankPhoto = "data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 width=%22110%22 height=%22110%22%3E%3Crect width=%22110%22 height=%22110%22 rx=%2220%22 fill=%22%23e8eef6%22/%3E%3Ctext x=%2255%22 y=%2267%22 text-anchor=%22middle%22 font-size=%2236%22 fill=%22%23667085%22%3E?%3C/text%3E%3C/svg%3E";

  function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>'\"]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", "\"": "&quot;" }[character]));
  }

  function renderPortals(portals = []) {
    $("#staffPortalCards").innerHTML = portals.map((portal) => {
      const active = portal.grant_status === "active";
      const url = active ? portalUrls[portal.app_code] : null;
      return `<article class="staff-portal-card ${active ? "active" : ""}"><header><strong>${escapeHtml(portal.app_name)}</strong><span class="badge ${active ? "active" : "revoked"}">${active ? "Granted" : "Not granted"}</span></header><p>${escapeHtml(portal.description || "")}</p>${active && url ? `<a class="primary" href="${url}" ${url.startsWith("http") ? "target=\"_blank\" rel=\"noopener\"" : ""}>Open ${escapeHtml(portal.app_name)}</a>` : active ? "<span class=\"not-granted\">Access is active; the portal link will be added when that system is deployed.</span>" : "<span class=\"not-granted\">Management has not assigned this portal.</span>"}</article>`;
    }).join("");
  }

  async function loadProfile() {
    const result = await secureRequest("profile");
    const profile = result.profile;
    currentPhoto = profile.photo || "";
    $("#staffPhoto").src = currentPhoto || blankPhoto;
    $("#staffName").textContent = profile.full_name;
    $("#staffMeta").textContent = `${profile.staff_number} | ${profile.designation || profile.staff_category || "Staff"}${profile.department ? ` | ${profile.department}` : ""}`;
    $("#staffStatus").textContent = profile.employment_status;
    $("#profileEmail").value = profile.email || "";
    $("#profilePhone").value = profile.phone || "";
    $("#profileAddress").value = profile.address || "";
    renderPortals(result.portals || []);
  }

  async function compressPhoto(file) {
    if (!file?.type?.startsWith("image/")) throw new Error("Choose an image file.");
    if (file.size > 12 * 1024 * 1024) throw new Error("Choose a photo below 12 MB.");
    let source;
    if ("createImageBitmap" in window) source = await createImageBitmap(file, { imageOrientation: "from-image" });
    else source = await new Promise((resolve, reject) => { const image = new Image(); image.onload = () => resolve(image); image.onerror = reject; image.src = URL.createObjectURL(file); });
    const max = 560;
    const scale = Math.min(1, max / Math.max(source.width, source.height));
    const width = Math.max(1, Math.round(source.width * scale));
    const height = Math.max(1, Math.round(source.height * scale));
    const canvas = document.createElement("canvas");
    canvas.width = width;
    canvas.height = height;
    const context = canvas.getContext("2d");
    context.fillStyle = "#fff";
    context.fillRect(0, 0, width, height);
    context.drawImage(source, 0, 0, width, height);
    source.close?.();
    let quality = 0.76;
    let data = canvas.toDataURL("image/jpeg", quality);
    while (data.length > 180000 && quality > 0.42) { quality -= 0.08; data = canvas.toDataURL("image/jpeg", quality); }
    if (data.length > 220000) throw new Error("Use a smaller photo.");
    return data;
  }

  async function choosePhoto(file) {
    try {
      $("#staffPhoto").style.opacity = ".45";
      currentPhoto = await compressPhoto(file);
      $("#staffPhoto").src = currentPhoto;
      toast("Photo ready to save.", "success");
    } catch (error) {
      toast(error.message, "error");
    } finally {
      $("#staffPhoto").style.opacity = "1";
    }
  }

  async function saveProfile(event) {
    event.preventDefault();
    try {
      await secureRequest("updateProfile", { email: $("#profileEmail").value.trim(), phone: $("#profilePhone").value.trim(), address: $("#profileAddress").value.trim(), photo: currentPhoto });
      await loadProfile();
      toast("Profile updated.", "success");
    } catch (error) {
      toast(friendly(error.code || error.message), "error");
    }
  }

  async function changePassword() {
    const current = prompt("Enter your current password.");
    if (!current) return;
    const next = prompt("Enter a new password with at least 10 characters, uppercase, lowercase and a number.");
    if (!next) return;
    const again = prompt("Enter the new password again.");
    if (next !== again) return toast("The new passwords do not match.", "error");
    try {
      await sessionRequest("change_password", { login: loginName, current_password: current, new_password: next });
      alert("Password changed. Sign in again.");
      await logout();
    } catch (error) {
      toast(friendly(error.code || error.message), "error");
    }
  }

  async function restoreSession() {
    const response = await fetch("/api/sta