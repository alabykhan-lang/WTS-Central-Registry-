'use strict';

const SUPABASE_URL = process.env.WTS_SUPABASE_URL || 'https://wuftzyeajmsxdrbwaawl.supabase.co';
const SUPABASE_KEY = process.env.WTS_SUPABASE_PUBLISHABLE_KEY
  || process.env.SUPABASE_PUBLISHABLE_KEY
  || process.env.SUPABASE_ANON_KEY
  || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Ind1ZnR6eWVham1zeGRyYndhYXdsIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzM4NjczNTgsImV4cCI6MjA4OTQ0MzM1OH0.QUeDRP1IpHCjvecqAOEZAqmMalEFlCLXylZP5D5iLog';
const COOKIE_NAME = 'wts_registry_session';
const MAX_AGE = 8 * 60 * 60;
const ALLOWED_ORIGINS = new Set(['https://wts-central-registry.vercel.app']);
const CENTRAL_MANAGEMENT_PERMISSIONS = new Set([
  'central_registry.administer',
  'staff_management.administer',
  'system_administration.administer',
]);
const SSO_CLIENT_ID = 'central_registry';
const REGISTRY_ORIGIN = process.env.WTS_REGISTRY_ORIGIN || 'https://wts-central-registry.vercel.app';
const SSO_REDIRECT_URI = `${REGISTRY_ORIGIN.replace(/\\/$/, '')}/`;

function isUrlSafe(value, min, max) {
  return typeof value === 'string'
    && value.length >= min
    && value.length <= max
    && /^[A-Za-z0-9._~-]+$/.test(value);
}

function hasCentralManagementPermission(permissions) {
  return Array.isArray(permissions)
    && (permissions.includes('*') || permissions.some((permission) => CENTRAL_MANAGEMENT_PERMISSIONS.has(permission)));
}

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
  return !origin || ALLOWED_ORIGINS.has(origin) || String(process.env.WTS_REGISTRY_ALLOWED_ORIGINS || '').split(',').map((v) => v.trim()).includes(origin);
}

function cookies(req) {
  const result = {};
  String(req.headers.cookie || '').split(';').forEach((part) => {
    const index = part.indexOf('=');
    if (index < 0) return;
    result[part.slice(0, index).trim()] = decodeURIComponent(part.slice(index + 1).trim());
  });
  return result;
}

function session(req) {
  const value = cookies(req)[COOKIE_NAME] || '';
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
  for await (const chunk of req) raw += chunk;
  if (!raw) return {};
  try { return JSON.parse(raw); } catch { return null; }
}

async function rpc(name, payload) {
  const response = await fetch(`${SUPABASE_URL}/rest/v1/rpc/${name}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` },
    body: JSON.stringify(payload),
  });
  const result = await response.json().catch(() => ({ ok: false, code: 'REGISTRY_SESSION_INVALID_RESPONSE' }));
  return response.ok ? result : { ok: false, code: result.code || 'REGISTRY_SESSION_SERVICE_UNAVAILABLE' };
}

module.exports = async function registrySession(req, res) {
  if (!originAllowed(req)) return send(res, 403, { ok: false, code: 'ORIGIN_NOT_ALLOWED' }, clearCookie());
  if (req.method === 'GET') {
    const current = session(req);
    if (!current) return send(res, 401, { ok: false, code: 'REGISTRY_SESSION_REQUIRED' }, clearCookie());
    const result = await rpc('school_identity_session_context_api', {
      p_session_id: current.id, p_session_secret: current.secret, p_target_app_code: 'central_registry',
    });
    if (!result?.ok) return send(res, 401, result, clearCookie());
    if (!hasCentralManagementPermission(result.permissions)) {
      await rpc('school_identity_session_revoke', {
        p_session_id: current.id, p_session_secret: current.secret, p_reason: 'CENTRAL_MANAGEMENT_PERMISSION_REQUIRED',
      });
      return send(res, 403, { ok: false, code: 'MANAGEMENT_ACCESS_DENIED' }, clearCookie());
    }
    return send(res, 200, result);
  }
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'GET, POST');
    return send(res, 405, { ok: false, code: 'METHOD_NOT_ALLOWED' });
  }
  const input = await body(req);
  if (!input || typeof input !== 'object') return send(res, 400, { ok: false, code: 'INVALID_REQUEST' });
  if (input.action === 'sso_exchange') {
    const grantType = typeof input.grant_type === 'string' ? input.grant_type : '';
    const clientId = typeof input.client_id === 'string' ? input.client_id : '';
    const redirectUri = typeof input.redirect_uri === 'string' ? input.redirect_uri : '';
    const code = typeof input.code === 'string' ? input.code : '';
    const codeVerifier = typeof input.code_verifier === 'string' ? input.code_verifier : '';
    const state = typeof input.state === 'string' ? input.state : '';
    const nonce = typeof input.nonce === 'string' ? input.nonce : '';
    if (
      grantType !== 'authorization_code'
      || clientId !== SSO_CLIENT_ID
      || redirectUri !== SSO_REDIRECT_URI
      || !isUrlSafe(code, 43, 512)
      || !isUrlSafe(codeVerifier, 43, 128)
      || !isUrlSafe(state, 16, 512)
      || !isUrlSafe(nonce, 16, 512)
    ) {
      return send(res, 400, { ok: false, code: 'SSO_REQUEST_INVALID' }, clearCookie());
    }
    const exchanged = await rpc('school_sso_authorization_code_exchange', {
      p_code: code,
      p_client_id: clientId,
      p_redirect_uri: redirectUri,
      p_code_verifier: codeVerifier,
      p_state: state,
      p_nonce: nonce,
    });
    if (!exchanged?.ok) {
      const exchangeCode = exchanged?.code || 'CENTRAL_SSO_EXCHANGE_FAILED';
      const exchangeStatus = exchangeCode === 'CENTRAL_REGISTRY_ACCESS_NOT_GRANTED' || exchangeCode === 'MANAGEMENT_ACCESS_DENIED'
        ? 403
        : exchangeCode.startsWith('SSO_') ? 400 : 401;
      return send(res, exchangeStatus, exchanged || { ok: false, code: exchangeCode }, clearCookie());
    }
    if (!exchanged.session_id || !exchanged.session_secret) {
      return send(res, 503, { ok: false, code: 'CENTRAL_SESSION_SERVICE_UNAVAILABLE' }, clearCookie());
    }
    if (!hasCentralManagementPermission(exchanged.permissions)) {
      await rpc('school_identity_session_revoke', {
        p_session_id: exchanged.session_id,
        p_session_secret: exchanged.session_secret,
        p_reason: 'CENTRAL_MANAGEMENT_PERMISSION_REQUIRED',
      });
      return send(res, 403, { ok: false, code: 'MANAGEMENT_ACCESS_DENIED' }, clearCookie());
    }
    return send(res, 200, {
      ok: true,
      code: 'CENTRAL_SSO_SESSION_ISSUED',
      expires_at: exchanged.expires_at,
      person_id: exchanged.person_id,
      identity_account_id: exchanged.identity_account_id,
      access_role: exchanged.access_role,
      permissions: exchanged.permissions || [],
    }, sessionCookie(exchanged.session_id, exchanged.session_secret));
  }
  if (input.action === 'logout') {
    const current = session(req);
    if (current) await rpc('school_identity_session_revoke', { p_session_id: current.id, p_session_secret: current.secret, p_reason: 'CENTRAL_REGISTRY_LOGOUT' });
    return send(res, 200, { ok: true, code: 'IDENTITY_SESSION_REVOKED' }, clearCookie());
  }
  if (input.action === 'change_password') {
    const login = typeof input.login === 'string' ? input.login.trim() : '';
    const currentPassword = typeof input.current_password === 'string' ? input.current_password : '';
    const newPassword = typeof input.new_password === 'string' ? input.new_password : '';
    if (!login || !currentPassword || !newPassword || newPassword.length > 512) {
      return send(res, 400, { ok: false, code: 'PASSWORD_CHANGE_INPUT_REQUIRED' }, clearCookie());
    }
    const result = await rpc('school_identity_change_password', {
      p_login: login,
      p_current_password: currentPassword,
      p_new_password: newPassword,
    });
    if (!result?.ok) return send(res, 400, result || { ok: false, code: 'PASSWORD_CHANGE_FAILED' }, clearCookie());
    return send(res, 200, { ok: true, code: result.code || 'PASSWORD_CHANGED' }, clearCookie());
  }
  if (input.action !== 'login') return send(res, 400, { ok: false, code: 'REGISTRY_SESSION_ACTION_RETIRED' }, clearCookie());
  const login = typeof input.login === 'string' ? input.login.trim() : '';
  const password = typeof input.password === 'string' ? input.password : '';
  if (!login || !password || password.length > 512) return send(res, 400, { ok: false, code: 'LOGIN_AND_PASSWORD_REQUIRED' }, clearCookie());
  const authentication = await rpc('school_identity_portal_login', {
    p_login: login,
    p_password: password,
    p_app_code: 'central_registry',
  });
  if (!authentication?.ok) return send(res, 401, authentication || { ok: false, code: 'INVALID_LOGIN' }, clearCookie());
  if (authentication.must_change_password) {
    return send(res, 200, { ok: true, code: authentication.code || 'PASSWORD_CHANGE_REQUIRED', must_change_password: true });
  }
  if (!authentication.client_code || !authentication.client_secret) {
    return send(res, 503, { ok: false, code: 'CENTRAL_SESSION_SERVICE_UNAVAILABLE' }, clearCookie());
  }
  const result = await rpc('school_identity_session_issue_api', {
    p_client_code: authentication.client_code,
    p_client_secret: authentication.client_secret,
    p_originating_app_code: 'central_registry',
    p_target_app_code: 'central_registry',
  });
  if (!result?.ok || !result.session_id || !result.session_secret) return send(res, 401, result || { ok: false, code: 'CENTRAL_SESSION_NOT_ACTIVE' }, clearCookie());
  if (!hasCentralManagementPermission(result.permissions)) {
    await rpc('school_identity_session_revoke', {
      p_session_id: result.session_id, p_session_secret: result.session_secret, p_reason: 'CENTRAL_MANAGEMENT_PERMISSION_REQUIRED',
    });
    return send(res, 403, { ok: false, code: 'MANAGEMENT_ACCESS_DENIED' }, clearCookie());
  }
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

