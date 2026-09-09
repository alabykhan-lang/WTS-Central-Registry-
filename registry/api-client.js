'use strict';

export async function sessionRequest(payload) {
  const response = await fetch('/api/registry-session', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(payload) });
  const result = await response.json().catch(() => ({ ok: false, code: 'REGISTRY_SESSION_INVALID_RESPONSE' }));
  if (!response.ok || result?.ok === false) throw Object.assign(new Error(result?.code || 'REGISTRY_SESSION_FAILED'), { code: result?.code, status: response.status });
  return result;
}

export async function getSession() {
  const response = await fetch('/api/registry-session', { credentials: 'same-origin', headers: { Accept: 'application/json' } });
  const result = await response.json().catch(() => ({ ok: false, code: 'REGISTRY_SESSION_INVALID_RESPONSE' }));
  if (!response.ok || result?.ok === false) throw Object.assign(new Error(result?.code || 'REGISTRY_SESSION_REQUIRED'), { code: result?.code, status: response.status });
  return result;
}

export async function registryRequest(kind, action, payload = {}) {
  const response = await fetch('/api/registry-v2', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ kind, action, payload }) });
  const result = await response.json().catch(() => ({ ok: false, code: 'REGISTRY_INVALID_RESPONSE' }));
  if (!response.ok || result?.ok === false) throw Object.assign(new Error(result?.code || 'REGISTRY_REQUEST_FAILED'), { code: result?.code, status: response.status });
  return result;
}

export async function uploadSignature(dataUrl, requestId) {
  const response = await fetch('/api/registry-signature', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ dataUrl, requestId }) });
  const result = await response.json().catch(() => ({ ok: false, code: 'SIGNATURE_INVALID_RESPONSE' }));
  if (!response.ok || result?.ok === false) throw Object.assign(new Error(result?.code || 'SIGNATURE_UPLOAD_FAILED'), { code: result?.code, status: response.status });
  return result;
}

export async function uploadPhoto(targetType, targetId, dataUrl, requestId) {
  const response = await fetch('/api/registry-photo', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ targetType, targetId, dataUrl, requestId }) });
  const result = await response.json().catch(() => ({ ok: false, code: 'PHOTO_INVALID_RESPONSE' }));
  if (!response.ok || result?.ok === false) throw Object.assign(new Error(result?.code || 'PHOTO_UPLOAD_FAILED'), { code: result?.code, status: response.status });
  return result;
}
