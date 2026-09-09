'use strict';

const SUPABASE_URL = process.env.WTS_SUPABASE_URL || 'https://wuftzyeajmsxdrbwaawl.supabase.co';
const SUPABASE_KEY = process.env.WTS_SUPABASE_PUBLISHABLE_KEY
  || process.env.SUPABASE_PUBLISHABLE_KEY
  || process.env.SUPABASE_ANON_KEY
  || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Ind1ZnR6eWVham1zeGRyYndhYXdsIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzM4NjczNTgsImV4cCI6MjA4OTQ0MzM1OH0.QUeDRP1IpHCjvecqAOEZAqmMalEFlCLXylZP5D5iLog';
const ALLOWED_ORIGINS = new Set(['https://wts-central-registry.vercel.app']);

function send(res, status, payload) {
  res.statusCode = status;
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(payload));
}
function originAllowed(req) {
  const origin = String(req.headers.origin || '').trim();
  return !origin || ALLOWED_ORIGINS.has(origin) || String(process.env.WTS_REGISTRY_ALLOWED_ORIGINS || '').split(',').map((value) => value.trim()).includes(origin);
}
async function body(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  let raw = '';
  for await (const chunk of req) { raw += chunk; if (raw.length > 16 * 1024) return null; }
  if (!raw) return {};
  try { return JSON.parse(raw); } catch { return null; }
}
async function resetPassword(payload) {
  const response = await fetch(`${SUPABASE_URL}/rest/v1/rpc/school_identity_password_reset_by_staff_record`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` },
    body: JSON.stringify(payload),
  });
  const result = await response.json().catch(() => ({ ok: false, code: 'PASSWORD_RESET_FAILED' }));
  return response.ok ? result : { ok: false, code: result?.code || 'PASSWORD_RESET_FAILED' };
}
module.exports = async function accountRecovery(req, res) {
  if (!originAllowed(req)) return send(res, 403, { ok: false, code: 'ORIGIN_NOT_ALLOWED' });
  if (req.method !== 'POST') { res.setHeader('Allow', 'POST'); return send(res, 405, { ok: false, code: 'METHOD_NOT_ALLOWED' }); }
  const input = await body(req);
  if (!input || typeof input !== 'object' || Array.isArray(input)) return send(res, 400, { ok: false, code: 'INVALID_REQUEST' });
  if (String(input.action || '').toLowerCase() !== 'reset') return send(res, 400, { ok: false, code: 'RECOVERY_ACTION_REQUIRED' });
  const login = typeof input.login === 'string' ? input.login.trim() : '';
  const contact = typeof input.contact === 'string' ? input.contact.trim() : '';
  const password = typeof input.password === 'string' ? input.password : '';
  const confirmPassword = typeof input.confirmPassword === 'string' ? input.confirmPassword : '';
  if (!login || !contact || !password || password !== confirmPassword || password.length > 512) return send(res, 400, { ok: false, code: 'PASSWORD_RESET_INPUT_REQUIRED' });
  const result = await resetPassword({ p_login: login, p_contact: contact, p_new_password: password });
  return send(res, result?.ok ? 200 : result?.code === 'ACCOUNT_TEMPORARILY_LOCKED' ? 429 : 400, result);
};
