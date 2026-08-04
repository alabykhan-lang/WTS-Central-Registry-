'use strict';

const SUPABASE_URL = process.env.WTS_SUPABASE_URL || 'https://wuftzyeajmsxdrbwaawl.supabase.co';
const SUPABASE_KEY = process.env.WTS_SUPABASE_PUBLISHABLE_KEY
  || process.env.SUPABASE_PUBLISHABLE_KEY
  || process.env.SUPABASE_ANON_KEY
  || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Ind1ZnR6eWVham1zeGRyYndhYXdsIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzM4NjczNTgsImV4cCI6MjA4OTQ0MzM1OH0.QUeDRP1IpHCjvecqAOEZAqmMalEFlCLXylZP5D5iLog';
const COOKIE_NAME = 'wts_staff_session';
const MAX_AGE = 8 * 60 * 60;
const ALLOWED_ORIGINS = new Set(['https://wts-central-registry.vercel.app']);

function send(res, status, payload, cookie) {
  res.statusCode = status;
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  if (cookie) res.setHeader('Set-Cookie', cookie);
  res.end(JSON.stringify(payload));
}

function originAllowed(req) {
  const origin = String(req.headers.origin || '').trim();
  return !origin || ALLOWED_ORIGINS.has(origin)
    || String(process.env.WTS_REGISTRY_ALLOWED_ORIGINS || '').split(',').map((value) => value.trim()).includes(origin);
}

function session(req) {
  let value = '';
  for (const part of String(req.headers.cookie || '').split(';')) {
    const index = part.indexOf('=');
    if (index < 0 || part.slice(0, index).trim() !== COOKIE_NAME) continue;
    try { value = decodeURIComponent(part.slice(index + 1).trim()); } catch { value = ''; }
  }
  const separator = value.indexOf('.');
  if (separator <= 0 || separator === value.length - 1) return null;
  return { id: value.slice(0, separator), secret: value.slice(separator + 1) };
}

function clearCookie() {
  return `${COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
}

function sessionCookie(id, secret) {
  return `${COOKIE_NAME}=${encodeURIComponent(`${id}.${secret}`)}; Path=/; Max-Age=${MAX_AGE}; HttpOnly; Secure; SameSite=Lax`;
}

async function body(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  let raw = '';
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 16 * 1024) return null;
  }
  if (!raw) return {};
  try { return JSON.parse(raw); } catch { return null; }
}

async function rpc(name, payload) {
  const response = await fetch(`${SUPABASE_URL}/rest/v1/rpc/${name}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` },
    body: JSON.stringify(payload),
  });
  const result = await response.json().catch(() => ({ ok: false, code: 'STAFF_SESSION_INVALID_RESPONSE' }));
  return response.ok ? result : { ok: false, code: result.code || 'STAFF_SESSION_SERVICE_UNAVAILABLE' };
}

module.exports = async function staffSession(req, res) {
  if (!originAllowed(req)) return send(res, 403, { ok: false, code: 'ORIGIN_NOT_ALLOWED' }, clearCookie());
  if (req.method === 'GET') {
    const current = session(req);
    if (!current) return send(res, 401, { ok: false, code: 'STAFF_SESSION_REQUIRED' }, clearCookie());
    const result = await rpc('school_identity_session_context_api', {
      p_session_id: current.id, p_session_secret: current.secret, p_target_app_code: 'staff_self_service',
    });
    if (!result?.ok) return send(res, 401, result, clearCookie());
    return send(res, 200, result);
  }
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'GET, POST');
    return send(res, 405, { ok: false, code: 'METHOD_NOT_ALLOWED' });
  }
  const input = await body(req);
  if (!input || typeof input !== 'object') return send(res, 400, { ok: false, code: 'INVALID_REQUEST' });
  if (input.action === 'logout') {
    const current = session(req);
    if (current) await rpc('school_identity_session_revoke', { p_session_id: current.id, p_session_secret: current.secret, p_reason: 'STAFF_SELF_SERVICE_LOGOUT' });
    return send(res, 200, { ok: true, code: 'IDENTITY_SESSION_REVOKED' }, clearCookie());
  }
  if (input.action !== 'exchange') return send(res, 400, { ok: false, code: 'STAFF_SESSION_ACTION_REQUIRED' });
  const clientCode = typeof input.client_code === 'string' ? input.client_code.trim() : '';
  const clientSecret = typeof input.client_secret === 'string' ? input.client_secret : '';
  if (!clientCode || !clientSecret || clientSecret.length > 512) return send(res, 401, { ok: false, code: 'STAFF_SESSION_NOT_ACTIVE' }, clearCookie());
  const result = await rpc('school_identity_session_issue_api', {
    p_client_code: clientCode,
    p_client_secret: clientSecret,
    p_originating_app_code: 'staff_self_service',
    p_target_app_code: 'staff_self_service',
  });
  if (!result?.ok || !result.session_id || !result.session_secret) return send(res, 401, result || { ok: false, code: 'STAFF_SESSION_NOT_ACTIVE' }, clearCookie());
  return send(res, 200, {
    ok: true,
    code: result.code,
    expires_at: result.expires_at,
    person_id: result.person_id,
    identity_account_id: result.identity_account_id,
    access_role: result.access_role,
    permissions: result.permissions || [],
  }, sessionCookie(result.session_id, result.session_secret));
};