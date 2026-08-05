'use strict';

const SUPABASE_URL = process.env.WTS_SUPABASE_URL || 'https://wuftzyeajmsxdrbwaawl.supabase.co';
const SUPABASE_KEY = process.env.WTS_SUPABASE_PUBLISHABLE_KEY
  || process.env.SUPABASE_PUBLISHABLE_KEY
  || process.env.SUPABASE_ANON_KEY
  || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Ind1ZnR6eWVham1zeGRyYndhYXdsIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzM4NjczNTgsImV4cCI6MjA4OTQ0MzM1OH0.QUeDRP1IpHCjvecqAOEZAqmMalEFlCLXylZP5D5iLog';
const { sendRegistrationReceivedEmail } = require('../lib/recovery-email');
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
  return !origin || ALLOWED_ORIGINS.has(origin)
    || String(process.env.WTS_REGISTRY_ALLOWED_ORIGINS || '').split(',').map((value) => value.trim()).includes(origin);
}

async function readBody(req) {
  if (req.body && typeof req.body === 'object') {
    return JSON.stringify(req.body).length <= 320 * 1024 ? req.body : null;
  }
  let raw = '';
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 320 * 1024) return null;
  }
  if (!raw) return {};
  try { return JSON.parse(raw); } catch { return null; }
}

async function rpc(payload) {
  const response = await fetch(`${SUPABASE_URL}/rest/v1/rpc/school_staff_public_registration_submit`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      apikey: SUPABASE_KEY,
      Authorization: `Bearer ${SUPABASE_KEY}`,
    },
    body: JSON.stringify({ p_payload: payload }),
  });
  const result = await response.json().catch(() => ({ ok: false, code: 'STAFF_REGISTRATION_INVALID_RESPONSE' }));
  return response.ok ? result : { ok: false, code: result.code || 'STAFF_REGISTRATION_SERVICE_UNAVAILABLE' };
}

function statusFor(code) {
  if (['FULL_NAME_REQUIRED', 'VALID_EMAIL_REQUIRED', 'PHONE_REQUIRED', 'WHATSAPP_NUMBER_INVALID', 'PHOTOGRAPH_INVALID'].includes(code)) return 400;
  return 400;
}

module.exports = async function staffRegistration(req, res) {
  if (!originAllowed(req)) return send(res, 403, { ok: false, code: 'ORIGIN_NOT_ALLOWED' });
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return send(res, 405, { ok: false, code: 'METHOD_NOT_ALLOWED' });
  }
  const input = await readBody(req);
  if (!input || typeof input !== 'object' || Array.isArray(input)) return send(res, 400, { ok: false, code: 'INVALID_REQUEST' });
  const payload = {
    fullName: input.fullName,
    email: input.email,
    phone: input.phone,
    whatsappNumber: input.whatsappNumber,
    address: input.address,
    emergencyContact: input.emergencyContact,
    photo: input.photo,
  };
  const result = await rpc(payload);
  if (result?.ok && result.code === 'STAFF_REGISTRATION_SUBMITTED') {
    const notification = await sendRegistrationReceivedEmail({
      fullName: payload.fullName,
      email: payload.email,
      registrationId: result.registration_id,
    });
    return send(res, 200, { ...result, registration_notification_status: notification.status });
  }
  return send(res, result?.ok ? 200 : statusFor(result?.code), result);
};
