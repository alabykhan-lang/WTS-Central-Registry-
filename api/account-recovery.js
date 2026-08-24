'use strict';

const SUPABASE_URL = process.env.WTS_SUPABASE_URL || 'https://wuftzyeajmsxdrbwaawl.supabase.co';
const SUPABASE_KEY = process.env.WTS_SUPABASE_PUBLISHABLE_KEY
  || process.env.SUPABASE_PUBLISHABLE_KEY
  || process.env.SUPABASE_ANON_KEY
  || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Ind1ZnR6eWVham1zeGRyYndhYXdsIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzM4NjczNTgsImV4cCI6MjA4OTQ0MzM1OH0.QUeDRP1IpHCjvecqAOEZAqmMalEFlCLXylZP5D5iLog';
const ALLOWED_ORIGINS = new Set(['https://wts-central-registry.vercel.app']);
const { issueAndSendRecoveryEmail } = require('../lib/recovery-email');

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
  return !origin || ALLOWED_ORIGINS.has(origin)
    || String(process.env.WTS_REGISTRY_ALLOWED_ORIGINS || '').split(',').map((value) => value.trim()).includes(origin);
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

async function consume(token, password) {
  const response = await fetch(`${SUPABASE_URL}/rest/v1/rpc/school_identity_recovery_consume`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` },
    body: JSON.stringify({ p_token: token, p_new_password: password }),
  });
  const result = await response.json().catch(() => ({ ok: false, code: 'RECOVERY_INVALID_RESPONSE' }));
  return response.ok ? result : { ok: false, code: result?.code || 'RECOVERY_SERVICE_UNAVAILABLE' };
}

async function consumeManagementCode({ login, purpose, code, password }) {
  const response = await fetch(`${SUPABASE_URL}/rest/v1/rpc/school_identity_management_code_consume`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` },
    body: JSON.stringify({
      p_login: login,
      p_purpose: purpose,
      p_code: code,
      p_new_password: password,
    }),
  });
  const result = await response.json().catch(() => ({ ok: false, code: 'RECOVERY_INVALID_RESPONSE' }));
  return response.ok ? result : { ok: false, code: result?.code || 'RECOVERY_SERVICE_UNAVAILABLE' };
}

async function consumeSharedTeacherCode({ login, code, password }) {
  const response = await fetch(`${SUPABASE_URL}/rest/v1/rpc/school_identity_shared_teacher_code_consume`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` },
    body: JSON.stringify({
      p_login: login,
      p_code: code,
      p_new_password: password,
    }),
  });
  const result = await response.json().catch(() => ({ ok: false, code: 'SHARED_TEACHER_RECOVERY_INVALID_RESPONSE' }));
  return response.ok ? result : { ok: false, code: result?.code || 'SHARED_TEACHER_RECOVERY_SERVICE_UNAVAILABLE' };
}

module.exports = async function accountRecovery(req, res) {
  if (!originAllowed(req)) return send(res, 403, { ok: false, code: 'ORIGIN_NOT_ALLOWED' });
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return send(res, 405, { ok: false, code: 'METHOD_NOT_ALLOWED' });
  }
  const input = await body(req);
  if (!input || typeof input !== 'object' || Array.isArray(input)) return send(res, 400, { ok: false, code: 'INVALID_REQUEST' });
  const action = typeof input.action === 'string' ? input.action.trim().toLowerCase() : '';

  if (action === 'request') {
    const purpose = input.purpose === 'reset' || input.purpose === 'password_reset' ? 'password_reset' : 'activation';
    const login = typeof input.login === 'string' ? input.login.trim() : '';
    if (!login || login.length > 254) return send(res, 400, { ok: false, code: 'RECOVERY_LOGIN_REQUIRED' });
    if (purpose === 'password_reset' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(login)) {
      return send(res, 400, { ok: false, code: 'RECOVERY_EMAIL_REQUIRED' });
    }
    const result = await issueAndSendRecoveryEmail({ login, purpose, reason: `public_${purpose}_request` });
    if (result.status === 'not_configured') return send(res, 503, { ok: false, code: 'RECOVERY_EMAIL_NOT_CONFIGURED' });
    if (result.status === 'failed') return send(res, 502, { ok: false, code: 'RECOVERY_EMAIL_DELIVERY_FAILED' });
    return send(res, 200, {
      ok: true,
      code: 'RECOVERY_REQUEST_ACCEPTED',
      message: purpose === 'password_reset'
        ? 'If the verified email is on file, a password reset link has been sent.'
        : 'If the staff number or registered email is on file, an activation link has been sent.',
    });
  }

  if (action === 'complete_code') {
    const purpose = input.purpose === 'password_reset' || input.purpose === 'reset' ? 'password_reset' : 'activation';
    const login = typeof input.login === 'string' ? input.login.trim() : '';
    const code = typeof input.code === 'string' ? input.code.trim() : '';
    const password = typeof input.password === 'string' ? input.password : '';
    const confirm = typeof input.confirmPassword === 'string' ? input.confirmPassword : '';
    if (!login || !code || !password || password !== confirm || password.length > 512) {
      return send(res, 400, { ok: false, code: 'MANAGEMENT_CODE_INPUT_REQUIRED' });
    }
    const sharedResult = await consumeSharedTeacherCode({ login, code, password });
    if (sharedResult?.ok) {
      return send(res, 200, {
        ok: true,
        code: sharedResult.code || 'SHARED_TEACHER_ACCESS_COMPLETED',
        purpose,
      });
    }
    const result = await consumeManagementCode({ login, purpose, code, password });
    if (!result?.ok) return send(res, 400, result || { ok: false, code: 'MANAGEMENT_CODE_COMPLETION_FAILED' });
    return send(res, 200, { ok: true, code: result.code || 'RECOVERY_COMPLETED', purpose: result.purpose });
  }

  if (action === 'complete') {
    const token = typeof input.token === 'string' ? input.token.trim() : '';
    const password = typeof input.password === 'string' ? input.password : '';
    const confirm = typeof input.confirmPassword === 'string' ? input.confirmPassword : '';
    if (!token || !password || password !== confirm || password.length > 512) return send(res, 400, { ok: false, code: 'PASSWORD_CONFIRMATION_REQUIRED' });
    const result = await consume(token, password);
    if (!result?.ok) return send(res, 400, result || { ok: false, code: 'RECOVERY_COMPLETION_FAILED' });
    return send(res, 200, { ok: true, code: result.code || 'RECOVERY_COMPLETED', purpose: result.purpose });
  }

  return send(res, 400, { ok: false, code: 'RECOVERY_ACTION_REQUIRED' });
};
