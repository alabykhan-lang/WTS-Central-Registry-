'use strict';

const SUPABASE_URL = process.env.WTS_SUPABASE_URL || 'https://wuftzyeajmsxdrbwaawl.supabase.co';
const SUPABASE_KEY = process.env.WTS_SUPABASE_PUBLISHABLE_KEY
  || process.env.SUPABASE_PUBLISHABLE_KEY
  || process.env.SUPABASE_ANON_KEY
  || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Ind1ZnR6eWVham1zeGRyYndhYXdsIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzM4NjczNTgsImV4cCI6MjA4OTQ0MzM1OH0.QUeDRP1IpHCjvecqAOEZAqmMalEFlCLXylZP5D5iLog';
const COOKIE_NAME = 'wts_registry_session';
const ALLOWED_ORIGINS = new Set(['https://wts-central-registry.vercel.app']);
const { issueAndSendRecoveryEmail, sendOperationalStaffEmail } = require('../lib/recovery-email');
const ROUTES = {
  scopeRead: 'school_access_management_scope_read_session_api',
  scopeWrite: 'school_access_management_scope_write_session_api',
  accessWrite: 'school_access_management_write_session_api',
  identityRead: 'school_identity_admin_read_session_api',
  identityWrite: 'school_identity_admin_write_session_api',
  registrationRead: 'school_staff_registration_management_session_api',
  registrationWrite: 'school_staff_registration_management_session_api',
  allocationRead: 'school_staff_allocation_management_session_api',
  allocationWrite: 'school_staff_allocation_management_session_api',
  calendarRead: 'school_academic_calendar_management_session_api',
  calendarWrite: 'school_academic_calendar_management_session_api',
  transitionRead: 'school_academic_transition_management_session_api',
  transitionWrite: 'school_academic_transition_management_session_api',
};

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
  if (!origin) return true;
  return ALLOWED_ORIGINS.has(origin)
    || String(process.env.WTS_REGISTRY_ALLOWED_ORIGINS || '').split(',').map((v) => v.trim()).includes(origin);
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

async function rpc(name, payload) {
  const response = await fetch(`${SUPABASE_URL}/rest/v1/rpc/${name}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` },
    body: JSON.stringify(payload),
  });
  const result = await response.json().catch(() => ({ ok: false, code: 'REGISTRY_MANAGEMENT_INVALID_RESPONSE' }));
  return response.ok ? result : { ok: false, code: result.code || 'REGISTRY_MANAGEMENT_SERVICE_UNAVAILABLE' };
}

function statusFor(code) {
  if (['RESULT_SESSION_REQUIRED', 'RESULT_SESSION_NOT_ACTIVE', 'RESULT_SESSION_AUDIENCE_MISMATCH', 'CENTRAL_IDENTITY_NOT_ACTIVE', 'RESULT_ACCESS_NOT_GRANTED'].includes(code)) return 401;
  if (['MANAGEMENT_ACCESS_DENIED', 'STAFF_NOT_ACTIVE', 'ACTIVE_CLASS_NOT_FOUND', 'ACTIVE_RESULT_SUBJECT_NOT_FOUND'].includes(code)) return 403;
  if (['CLASS_MAIN_TEACHER_ALREADY_ASSIGNED', 'ACADEMIC_TERM_READ_ONLY', 'CURRENT_TERM_REPLACEMENT_REQUIRED', 'DUPLICATE_STAFF_IDENTITY', 'RECOVERY_CODE_ISSUE_TOO_SOON', 'ACADEMIC_TRANSITION_ALREADY_APPLIED'].includes(code)) return 409;
  return 400;
}

module.exports = async function registryManagement(req, res) {
  if (!originAllowed(req)) return send(res, 403, { ok: false, code: 'ORIGIN_NOT_ALLOWED' }, true);
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return send(res, 405, { ok: false, code: 'METHOD_NOT_ALLOWED' });
  }
  const current = session(req);
  if (!current) return send(res, 401, { ok: false, code: 'REGISTRY_SESSION_REQUIRED' }, true);
  const input = await readBody(req);
  if (!input || typeof input !== 'object') return send(res, 400, { ok: false, code: 'INVALID_REQUEST' });
  const operation = typeof input.operation === 'string' ? input.operation.trim() : '';
  const rpcName = ROUTES[operation];
  if (!rpcName || typeof input.action !== 'string') return send(res, 400, { ok: false, code: 'MANAGEMENT_ACTION_REQUIRED' });
  const payload = input.payload && typeof input.payload === 'object' ? input.payload : {};
  const result = await rpc(rpcName, {
    p_session_id: current.id,
    p_session_secret: current.secret,
    p_action: input.action,
    p_payload: payload,
  });
  if (!result?.ok) return send(res, statusFor(result?.code), result, statusFor(result?.code) === 401);
  if (operation === 'registrationWrite' && input.action.trim().toLowerCase() === 'approve'
      && ['STAFF_REGISTRATION_APPROVED', 'STAFF_REGISTRATION_ALREADY_APPROVED'].includes(result.code)
      && result.staff_number) {
    const activation = await issueAndSendRecoveryEmail({
      login: result.staff_number,
      purpose: 'activation',
      reason: 'management_approved_staff_activation',
    });
    return send(res, 200, { ...result, activation_email_status: activation.status });
  }
  const action = input.action.trim().toLowerCase();
  if (payload.staffId && ((operation === 'accessWrite' && action === 'setmoduleaccess' && payload.enabled === true)
      || (operation === 'allocationWrite' && action === 'setclass' && payload.enabled !== false)
      || (operation === 'allocationWrite' && action === 'setsubjects' && Array.isArray(payload.subjectIndexes) && payload.subjectIndexes.length > 0))) {
    const eventType = operation === 'accessWrite' ? 'module_access' : action === 'setclass' ? 'class_assignment' : 'subject_assignment';
    const label = eventType === 'module_access' ? String(payload.appCode || 'WTS module').replaceAll('_', ' ') : eventType === 'class_assignment' ? `${payload.classKey || 'class'} · ${payload.responsibility || 'class responsibility'}` : `${payload.classKey || 'class'} · ${payload.subjectIndexes.length} subject(s)`;
    const notification = await sendOperationalStaffEmail({ staffId: payload.staffId, eventType, context: { label } });
    return send(res, 200, { ...result, staff_notification_status: notification.status });
  }
  return send(res, 200, result);
};
