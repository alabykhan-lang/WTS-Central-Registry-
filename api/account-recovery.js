'use strict';

// Two-step, token-based recovery. "request" emails a single-use link;
// "complete" consumes the token and sets the password. The old direct reset
// (staff number + email/phone, no token) is deliberately gone — see the
// 20261021_legacy_command_lockdown migration.
const { issueAndSendRecoveryEmail, serviceRpc, configured } = require('../lib/recovery-email');

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
const ACCEPTED = {
  ok: true,
  code: 'RECOVERY_REQUEST_ACCEPTED',
  message: 'If that staff record exists, a secure reset link has been emailed to the address on file.',
};

module.exports = async function accountRecovery(req, res) {
  if (!originAllowed(req)) return send(res, 403, { ok: false, code: 'ORIGIN_NOT_ALLOWED' });
  if (req.method !== 'POST') { res.setHeader('Allow', 'POST'); return send(res, 405, { ok: false, code: 'METHOD_NOT_ALLOWED' }); }
  const input = await body(req);
  if (!input || typeof input !== 'object' || Array.isArray(input)) return send(res, 400, { ok: false, code: 'INVALID_REQUEST' });

  const action = String(input.action || '').toLowerCase();

  // "reset" is the old client contract: it no longer resets anything, it only
  // triggers the email, so a cached old page cannot skip the token step.
  if (action === 'request' || action === 'reset') {
    const login = typeof input.login === 'string' ? input.login.trim().slice(0, 254) : '';
    if (!login) return send(res, 400, { ok: false, code: 'RECOVERY_LOGIN_REQUIRED' });
    if (!configured()) return send(res, 503, { ok: false, code: 'RECOVERY_EMAIL_NOT_CONFIGURED' });
    const purpose = input.purpose === 'activation' ? 'activation' : 'password_reset';
    try { await issueAndSendRecoveryEmail({ login, purpose }); } catch { /* never leak whether the record exists */ }
    return send(res, 200, ACCEPTED);
  }

  // Teacher self-service with the shared WTS teacher code (no email needed).
  // Used when a member of teaching staff needs to set or replace a password.
  if (action === 'shared_code' || action === 'teacher_code') {
    const login = typeof input.login === 'string' ? input.login.trim().slice(0, 64) : '';
    const code = typeof input.code === 'string' ? input.code.trim().slice(0, 64) : '';
    const password = typeof input.password === 'string' ? input.password : '';
    const confirmPassword = typeof input.confirmPassword === 'string' ? input.confirmPassword : '';
    if (!login || !code) return send(res, 400, { ok: false, code: 'SHARED_TEACHER_CODE_REQUIRED' });
    if (!password || password !== confirmPassword || password.length > 512) {
      return send(res, 400, { ok: false, code: 'PASSWORD_CONFIRMATION_REQUIRED' });
    }
    const result = await serviceRpc('school_identity_shared_teacher_code_consume', {
      p_login: login,
      p_code: code,
      p_new_password: password,
    });
    const status = result?.ok ? 200 : (result?.code === 'RECOVERY_SERVICE_NOT_CONFIGURED' ? 503 : 400);
    return send(res, status, result || { ok: false, code: 'PASSWORD_RESET_FAILED' });
  }

  if (action === 'complete') {
    const token = typeof input.token === 'string' ? input.token.trim().slice(0, 512) : '';
    const password = typeof input.password === 'string' ? input.password : '';
    const confirmPassword = typeof input.confirmPassword === 'string' ? input.confirmPassword : '';
    if (!token) return send(res, 400, { ok: false, code: 'RECOVERY_TOKEN_REQUIRED' });
    if (!password || password !== confirmPassword || password.length > 512) {
      return send(res, 400, { ok: false, code: 'PASSWORD_CONFIRMATION_REQUIRED' });
    }
    const result = await serviceRpc('school_identity_recovery_consume', { p_token: token, p_new_password: password });
    const status = result?.ok ? 200 : (result?.code === 'RECOVERY_SERVICE_NOT_CONFIGURED' ? 503 : 400);
    return send(res, status, result || { ok: false, code: 'PASSWORD_RESET_FAILED' });
  }

  return send(res, 400, { ok: false, code: 'RECOVERY_ACTION_REQUIRED' });
};
