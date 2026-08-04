'use strict';

const SUPABASE_URL = process.env.WTS_SUPABASE_URL || 'https://wuftzyeajmsxdrbwaawl.supabase.co';
const SUPABASE_KEY = process.env.WTS_SUPABASE_PUBLISHABLE_KEY
  || process.env.SUPABASE_PUBLISHABLE_KEY
  || process.env.SUPABASE_ANON_KEY
  || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Ind1ZnR6eWVham1zeGRyYndhYXdsIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzM4NjczNTgsImV4cCI6MjA4OTQ0MzM1OH0.QUeDRP1IpHCjvecqAOEZAqmMalEFlCLXylZP5D5iLog';
const COOKIE_NAME = 'wts_staff_session';
const ALLOWED_ORIGINS = new Set(['https://wts-central-registry.vercel.app']);

function send(res, status, payload, clear = false) {
  res.statusCode = status;
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  if (clear) res.setHeader('Set-Cookie', `${COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);
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

async function readBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  let raw = '';
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 64 * 1024) return null;
  }
  if (!raw) return {};
  try { return JSON.parse(raw); } catch { return null; }
}

async function rpc(payload) {
  const response = await fetch(`${SUPABASE_URL}/rest/v1/rpc/school_staff_self_service_session_api`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` },
    body: JSON.stringify(payload),
  });
  const result = await response.json().catch(() => ({ ok: false, code: 'STAFF_PORTAL_INVALID_RESPONSE' }));
  return response.ok ? result : { ok: false, code: result.code || 'STAFF_PORTAL_SERVICE_UNAVAILABLE' };
}

function statusFor(code) {
  if (['STAFF_SESSION_REQUIRED', 'RESULT_SESSION_REQUIRED', 'RESULT_SESSION_NOT_ACTIVE', 'RESULT_SESSION_AUDIENCE_MISMATCH', 'CENTRAL_IDENTITY_NOT_ACTIVE', 'STAFF_NOT_ACTIVE'].includes(code)) return 401;
  if (['SELF_SERVICE_UPDATE_DENIED'].includes(code)) return 403;
  return 400;
}

module.exports = async function staffPortal(req, res) {
  if (!originAllowed(req)) return send(res, 403, { ok: false, code: 'ORIGIN_NOT_ALLOWED' }, true);
  if (req.method !== 'POST') { res.setHeader('Allow', 'POST'); return send(res, 405, { ok: false, code: 'METHOD_NOT_ALLOWED' }); }
  const current = session(req);
  if (!current) return send(res, 401, { ok: false, code: 'STAFF_SESSION_REQUIRED' }, true);
  const input = await readBody(req);
  if (!input || typeof input !== 'object' || typeof input.action !== 'string') return send(res, 400, { ok: false, code: 'STAFF_ACTION_REQUIRED' });
  const result = await rpc({
    p_session_id: current.id,
    p_session_secret: current.secret,
    p_action: input.action,
    p_payload: input.payload && typeof input.payload === 'object' ? input.payload : {},
  });
  if (!result?.ok) return send(res, statusFor(result?.code), result, statusFor(result?.code) === 401);
  return send(res, 200, result);
};
