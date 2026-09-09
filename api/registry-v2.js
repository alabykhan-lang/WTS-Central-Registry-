'use strict';

const SUPABASE_URL = process.env.WTS_SUPABASE_URL || 'https://wuftzyeajmsxdrbwaawl.supabase.co';
const SUPABASE_KEY = process.env.WTS_SUPABASE_SERVER_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.WTS_SUPABASE_PUBLISHABLE_KEY || process.env.SUPABASE_PUBLISHABLE_KEY || process.env.SUPABASE_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Ind1ZnR6eWVham1zeGRyYndhYXdsIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzM4NjczNTgsImV4cCI6MjA4OTQ0MzM1OH0.QUeDRP1IpHCjvecqAOEZAqmMalEFlCLXylZP5D5iLog';
const COOKIE_NAME = 'wts_registry_session';
const ORIGINS = new Set(['https://wts-central-registry.vercel.app']);

function send(res, status, body, clear = false) {
  res.statusCode = status;
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  if (clear) res.setHeader('Set-Cookie', `${COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);
  res.end(JSON.stringify(body));
}

function session(req) {
  const raw = String(req.headers.cookie || '').split(';').find((part) => part.trim().startsWith(`${COOKIE_NAME}=`))?.split('=').slice(1).join('=') || '';
  let value = '';
  try { value = decodeURIComponent(raw); } catch { return null; }
  const dot = value.indexOf('.');
  return dot > 0 && dot < value.length - 1 ? { id: value.slice(0, dot), secret: value.slice(dot + 1) } : null;
}

async function parseBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  let raw = '';
  for await (const chunk of req) { raw += chunk; if (raw.length > 128 * 1024) return null; }
  if (!raw) return {};
  try { return JSON.parse(raw); } catch { return null; }
}

async function rpc(name, payload) {
  if (!SUPABASE_KEY) return { ok: false, code: 'REGISTRY_SERVICE_KEY_MISSING' };
  try {
    const response = await fetch(`${SUPABASE_URL}/rest/v1/rpc/${name}`, { method: 'POST', headers: { 'Content-Type': 'application/json', apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` }, body: JSON.stringify(payload) });
    const result = await response.json().catch(() => ({ ok: false, code: 'REGISTRY_SERVICE_INVALID_RESPONSE' }));
    return response.ok ? result : { ok: false, code: result.code || 'REGISTRY_SERVICE_UNAVAILABLE' };
  } catch {
    return { ok: false, code: 'REGISTRY_SERVICE_UNAVAILABLE' };
  }
}

function statusFor(code) {
  if (['REGISTRY_SERVICE_KEY_MISSING','REGISTRY_SERVICE_UNAVAILABLE','REGISTRY_SERVICE_INVALID_RESPONSE'].includes(code)) return 503;
  if (['REGISTRY_SESSION_REQUIRED','REGISTRY_IDENTITY_NOT_ACTIVE'].includes(code)) return 401;
  if (['REGISTRY_ACCESS_NOT_GRANTED','REGISTRY_CAPABILITY_DENIED','REGISTRY_SCOPE_DENIED','TARGET_CLASS_OUT_OF_SCOPE','PROTECTED_PORTFOLIO_RESTRICTED'].includes(code)) return 403;
  if (['REGISTRY_CONFLICT','ACTIVE_MAIN_TEACHER_REQUIRED','PREFECT_CYCLE_ALREADY_EXISTS'].includes(code)) return 409;
  return 400;
}

module.exports = async function registryV2(req, res) {
  const origin = String(req.headers.origin || '').trim();
  if (origin && !ORIGINS.has(origin) && !String(process.env.WTS_REGISTRY_ALLOWED_ORIGINS || '').split(',').map((x) => x.trim()).includes(origin)) return send(res, 403, { ok: false, code: 'ORIGIN_NOT_ALLOWED' }, true);
  if (req.method !== 'POST') { res.setHeader('Allow', 'POST'); return send(res, 405, { ok: false, code: 'METHOD_NOT_ALLOWED' }); }
  const current = session(req);
  if (!current) return send(res, 401, { ok: false, code: 'REGISTRY_SESSION_REQUIRED' }, true);
  const input = await parseBody(req);
  if (!input || typeof input !== 'object') return send(res, 400, { ok: false, code: 'INVALID_REQUEST' });
  const action = typeof input.action === 'string' ? input.action.trim() : '';
  const payload = input.payload && typeof input.payload === 'object' ? input.payload : {};
  if (!action) return send(res, 400, { ok: false, code: 'REGISTRY_ACTION_REQUIRED' });
  const result = input.kind === 'write'
    ? await rpc('school_registry_write_v2', { p_session_id: current.id, p_session_secret: current.secret, p_action: action, p_payload: payload })
    : await rpc('school_registry_read_v2', { p_session_id: current.id, p_session_secret: current.secret, p_action: action, p_payload: payload });
  if (!result?.ok) return send(res, statusFor(result?.code), result, ['REGISTRY_SESSION_REQUIRED','REGISTRY_IDENTITY_NOT_ACTIVE','REGISTRY_ACCESS_NOT_GRANTED'].includes(result?.code));
  return send(res, 200, result);
};
