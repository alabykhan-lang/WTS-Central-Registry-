'use strict';

const SUPABASE_URL = process.env.WTS_SUPABASE_URL || 'https://wuftzyeajmsxdrbwaawl.supabase.co';
const SERVICE_ROLE_KEY = process.env.WTS_SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const RESEND_API_KEY = process.env.WTS_RESEND_API_KEY || process.env.RESEND_API_KEY || '';
const EMAIL_FROM = process.env.WTS_EMAIL_FROM || '';
const PUBLIC_URL = (process.env.WTS_REGISTRY_PUBLIC_URL || 'https://wts-central-registry.vercel.app').replace(/\/$/, '');
const MANAGEMENT_EMAIL = process.env.WTS_REGISTRY_MANAGEMENT_EMAIL || process.env.WTS_REGISTRY_ADMIN_EMAIL || '';

function configured() {
  return Boolean(SERVICE_ROLE_KEY && RESEND_API_KEY && EMAIL_FROM);
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>'"]/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;',
  }[character]));
}

async function serviceRpc(name, payload) {
  if (!SERVICE_ROLE_KEY) return { ok: false, code: 'RECOVERY_SERVICE_NOT_CONFIGURED' };
  const response = await fetch(`${SUPABASE_URL}/rest/v1/rpc/${name}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      apikey: SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
    },
    body: JSON.stringify(payload),
  });
  const result = await response.json().catch(() => ({ ok: false, code: 'RECOVERY_SERVICE_INVALID_RESPONSE' }));
  return response.ok ? result : { ok: false, code: result?.code || 'RECOVERY_SERVICE_UNAVAILABLE' };
}

async function sendEmail({ to, subject, text, html }) {
  if (!RESEND_API_KEY || !EMAIL_FROM) return { ok: false, code: 'RECOVERY_EMAIL_NOT_CONFIGURED' };
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: EMAIL_FROM, to: [to], subject, text, html }),
  });
  if (!response.ok) return { ok: false, code: 'RECOVERY_EMAIL_PROVIDER_FAILED' };
  return { ok: true, code: 'RECOVERY_EMAIL_SENT' };
}

async function markDelivery(tokenId, delivered, errorCode = '') {
  if (!tokenId || !SERVICE_ROLE_KEY) return;
  await serviceRpc('school_identity_recovery_mark_delivery', {
    p_token_id: tokenId,
    p_delivered: delivered,
    p_error: errorCode || null,
  }).catch(() => {});
}

async function issueAndSendRecoveryEmail({ login, purpose, reason }) {
  if (!configured()) return { status: 'not_configured', code: 'RECOVERY_EMAIL_NOT_CONFIGURED' };
  const issued = await serviceRpc('school_identity_recovery_issue_service', {
    p_login: login,
    p_purpose: purpose,
    p_reason: reason || `self_service_${purpose}`,
  });
  if (!issued?.ok) return { status: 'failed', code: issued?.code || 'RECOVERY_ISSUE_FAILED' };
  if (!issued.deliverable || !issued.token || !issued.destination_email) {
    return { status: 'accepted', code: 'RECOVERY_REQUEST_ACCEPTED' };
  }

  const url = new URL('/activate.html', PUBLIC_URL);
  url.searchParams.set('mode', purpose === 'password_reset' ? 'reset' : 'activation');
  url.searchParams.set('token', issued.token);
  const action = purpose === 'password_reset' ? 'reset your WTS password' : 'activate your existing WTS account';
  const subject = purpose === 'password_reset' ? 'WTS Central Registry password reset' : 'Activate your WTS staff account';
  const text = `Use this secure link to ${action}: ${url.toString()}\n\nThis link expires in 30 minutes and can be used once. If you did not request this, ignore this email.`;
  const html = `<p>Use the secure link below to ${escapeHtml(action)}.</p><p><a href="${escapeHtml(url.toString())}">Continue to WTS Central Registry</a></p><p>This link expires in 30 minutes and can be used once. If you did not request this, ignore this email.</p>`;
  const sent = await sendEmail({ to: issued.destination_email, subject, text, html });
  await markDelivery(issued.token_id, sent.ok, sent.code);
  return sent.ok
    ? { status: 'sent', code: 'RECOVERY_EMAIL_SENT' }
    : { status: 'failed', code: sent.code || 'RECOVERY_EMAIL_PROVIDER_FAILED' };
}

async function sendRegistrationReceivedEmail({ fullName, email, registrationId }) {
  if (!configured() || !MANAGEMENT_EMAIL) return { status: 'not_configured', code: 'REGISTRATION_EMAIL_NOT_CONFIGURED' };
  const subject = 'WTS staff registration received';
  const text = `A new staff registration is pending management review.\n\nName: ${fullName}\nEmail: ${email}\nReference: ${registrationId}`;
  const html = `<p>A new staff registration is pending management review.</p><p><strong>Name:</strong> ${escapeHtml(fullName)}<br><strong>Email:</strong> ${escapeHtml(email)}<br><strong>Reference:</strong> ${escapeHtml(registrationId)}</p>`;
  const sent = await sendEmail({ to: MANAGEMENT_EMAIL, subject, text, html });
  return sent.ok ? { status: 'sent', code: sent.code } : { status: 'failed', code: sent.code };
}

async function sendOperationalStaffEmail({ staffId, eventType, context = {} }) {
  if (!configured() || !staffId) return { status: 'not_configured', code: 'OPERATIONAL_EMAIL_NOT_CONFIGURED' };
  const recipient = await serviceRpc('school_registry_staff_notification_recipient_service', { p_staff_id: staffId });
  if (!recipient?.ok || !recipient.email) return { status: 'not_sent', code: recipient?.code || 'STAFF_EMAIL_NOT_AVAILABLE' };
  const labels = {
    class_assignment: 'class responsibility',
    subject_assignment: 'subject assignment',
    module_access: 'module access',
  };
  const label = labels[eventType] || 'Registry update';
  const subject = `WTS ${label} update`;
  const detail = context.label ? `\n\nDetails: ${context.label}` : '';
  const text = `Hello ${recipient.full_name},\n\nA ${label} has been updated for your WTS staff identity.${detail}\n\nSign in to Workspace to view your current Registry summary.`;
  const html = `<p>Hello ${escapeHtml(recipient.full_name)},</p><p>A <strong>${escapeHtml(label)}</strong> has been updated for your WTS staff identity.</p>${context.label ? `<p><strong>Details:</strong> ${escapeHtml(context.label)}</p>` : ''}<p>Sign in to Workspace to view your current Registry summary.</p>`;
  const sent = await sendEmail({ to: recipient.email, subject, text, html });
  return sent.ok ? { status: 'sent', code: sent.code } : { status: 'failed', code: sent.code };
}

module.exports = {
  configured,
  issueAndSendRecoveryEmail,
  sendRegistrationReceivedEmail,
  sendOperationalStaffEmail,
  serviceRpc,
};
