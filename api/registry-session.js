'use strict';

const crypto = require('node:crypto');

const SUPABASE_URL = process.env.WTS_SUPABASE_URL || 'https://wuftzyeajmsxdrbwaawl.supabase.co';
const SUPABASE_KEY = process.env.WTS_SUPABASE_SERVER_KEY
  || process.env.SUPABASE_SERVICE_ROLE_KEY
  || process.env.WTS_SUPABASE_PUBLISHABLE_KEY
  || process.env.SUPABASE_PUBLISHABLE_KEY
  || process.env.SUPABASE_ANON_KEY
  || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Ind1ZnR6eWVham1zeGRyYndhYXdsIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzM4NjczNTgsImV4cCI6MjA4OTQ0MzM1OH0.QUeDRP1IpHCjvecqAOEZAqmMalEFlCLXylZP5D5iLog';
const COOKIE_NAME = 'wts_registry_session';
const MAX_AGE = 8 * 60 * 60;
const DEFAULT_ORIGIN = 'https://wts-central-registry.vercel.app';
const deploymentOrigins = [process.env.VERCEL_URL, process.env.VERCEL_BRANCH_URL, process.env.VERCEL_PROJECT_PRODUCTION_URL]
  .filter(Boolean)
  .map((value) => String(value).replace(/^https?:\/\//, '').replace(/\/$/, ''))
  .map((value) => `https://${value}`);
const ALLOWED_ORIGINS = new Set([DEFAULT_ORIGIN, ...deploymentOrigins]);
const SSO_CLIENT_ID = 'central_registry';
const REGISTRY_ORIGIN = process.env.WTS_REGISTRY_ORIGIN || DEFAULT_ORIGIN;
const SSO_REDIRECT_URI = `${REGISTRY_ORIGIN.replace(/\/$/, '')}/`;
const SSO_TRANSACTION_COOKIE = 'wts_registry_sso_transaction';
const SSO_TRANSACTION_MAX_AGE = 5 * 60;

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
    || String(process.env.WTS_REGISTRY_ALLOWED_ORIGINS || '').split(',').map((v) => v.trim()).includes(origin);
}

function cookies(req) {
  const output = {};
  for (const part of String(req.headers.cookie || '').split(';')) {
    const index = part.indexOf('=');
    if (index < 0) continue;
    try { output[part.slice(0, index).trim()] = decodeURIComponent(part.slice(index + 1).trim()); } catch { /* malformed cookie */ }
  }
  return output;
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

function transactionCookie(value, maxAge = SSO_TRANSACTION_MAX_AGE) {
  return `${SSO_TRANSACTION_COOKIE}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`;
}

function clearTransactionCookie() {
  return transactionCookie('', 0);
}

function readTransaction(req) {
  const value = cookies(req)[SSO_TRANSACTION_COOKIE];
  if (!value) return null;
  try {
    const parsed = JSON.parse(Buffer.from(value, 'base64url').toString('utf8'));
    if (!parsed || parsed.expires_at < Date.now()) return null;
    return parsed;
  } catch {
    return null;
  }
}

function combinedCookies(...values) {
  return values.filter(Boolean);
}

function safeToken(value, min, max) {
  return typeof value === 'string' && value.length >= min && value.length <= max && /^[A-Za-z0-9._~-]+$/.test(value);
}

async function body(req) {
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
  if (!SUPABASE_KEY) return { ok: false, code: 'REGISTRY_SERVICE_KEY_MISSING' };
  try {
    const response = await fetch(`${SUPABASE_URL}/rest/v1/rpc/${name}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` },
      body: JSON.stringify(payload),
    });
    const result = await response.json().catch(() => ({ ok: false, code: 'REGISTRY_SERVICE_INVALID_RESPONSE' }));
    return response.ok ? result : { ok: false, code: result.code || 'REGISTRY_SERVICE_UNAVAILABLE' };
  } catch {
    return { ok: false, code: 'REGISTRY_SERVICE_UNAVAILABLE' };
  }
}

// Session material is written only to the HttpOnly cookie. Never echo the
// bearer secret (or the session id) into a browser-readable JSON response.
function publicSessionResult(result) {
  if (!result || typeof result !== 'object') return result;
  const {
    session_id: _sessionId,
    session_secret: _sessionSecret,
    attendance_client_secret: _attendanceClientSecret,
    client_secret: _clientSecret,
    ...safe
  } = result;
  return safe;
}
function rpcStatus(result, fallback) {
  return ['REGISTRY_SERVICE_KEY_MISSING', 'REGISTRY_SERVICE_UNAVAILABLE', 'REGISTRY_SERVICE_INVALID_RESPONSE'].includes(result?.code) ? 503 : fallback;
}

module.exports = async function registrySession(req, res) {
  if (!originAllowed(req)) return send(res, 403, { ok: false, code: 'ORIGIN_NOT_ALLOWED' }, clearCookie());
  if (req.method === 'GET') {
    const current = session(req);
    if (!current) return send(res, 401, { ok: false, code: 'REGISTRY_SESSION_REQUIRED' }, clearCookie());
    const result = await rpc('school_registry_session_context_v2', { p_session_id: current.id, p_session_secret: current.secret });
    if (!result?.ok) return send(res, rpcStatus(result, 401), result, clearCookie());
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
    if (current) await rpc('school_identity_session_revoke', { p_session_id: current.id, p_session_secret: current.secret, p_reason: 'CENTRAL_REGISTRY_LOGOUT' });
    return send(res, 200, { ok: true, code: 'IDENTITY_SESSION_REVOKED' }, clearCookie());
  }
  if (input.action === 'change_password') {
    const login = typeof input.login === 'string' ? input.login.trim() : '';
    const currentPassword = typeof input.current_password === 'string' ? input.current_password : '';
    const newPassword = typeof input.new_password === 'string' ? input.new_password : '';
    if (!login || !currentPassword || !newPassword || newPassword.length > 512) return send(res, 400, { ok: false, code: 'PASSWORD_CHANGE_INPUT_REQUIRED' }, clearCookie());
    const result = await rpc('school_identity_change_password', { p_login: login, p_current_password: currentPassword, p_new_password: newPassword });
    return send(res, result?.ok ? 200 : rpcStatus(result, 400), result, result?.ok ? clearCookie() : undefined);
  }
  if (input.action === 'sso_begin') {
    const verifier = crypto.randomBytes(48).toString('base64url');
    const state = crypto.randomBytes(24).toString('base64url');
    const nonce = crypto.randomBytes(24).toString('base64url');
    const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
    const portalOriginInput = typeof input.portal_origin === 'string' ? input.portal_origin : '';
    const portalOrigin = /^https:\/\/(?:portal\.waytosuccessschools\.com|wts-school-platform(?:-[a-z0-9-]+)?\.vercel\.app)$/.test(portalOriginInput)
      ? portalOriginInput
      : 'https://wts-school-platform.vercel.app';
    const authorize = new URL('/api/sso/authorize', portalOrigin);
    authorize.searchParams.set('response_type', 'code');
    authorize.searchParams.set('client_id', SSO_CLIENT_ID);
    authorize.searchParams.set('redirect_uri', SSO_REDIRECT_URI);
    authorize.searchParams.set('scope', 'central_registry');
    authorize.searchParams.set('code_challenge', challenge);
    authorize.searchParams.set('code_challenge_method', 'S256');
    authorize.searchParams.set('state', state);
    authorize.searchParams.set('nonce', nonce);
    const transaction = Buffer.from(JSON.stringify({ verifier, state, nonce, expires_at: Date.now() + (SSO_TRANSACTION_MAX_AGE * 1000) })).toString('base64url');
    return send(res, 200, { ok: true, authorize_url: authorize.toString() }, transactionCookie(transaction));
  }
  if (input.action === 'sso_exchange') {
    const grantType = typeof input.grant_type === 'string' ? input.grant_type : '';
    const clientId = typeof input.client_id === 'string' ? input.client_id : '';
    const redirectUri = typeof input.redirect_uri === 'string' ? input.redirect_uri : '';
    const code = typeof input.code === 'string' ? input.code : '';
    const transaction = readTransaction(req);
    const verifier = transaction?.verifier || (typeof input.code_verifier === 'string' ? input.code_verifier : '');
    const state = typeof input.state === 'string' ? input.state : '';
    const nonce = typeof input.nonce === 'string' ? input.nonce : '';
    if (grantType !== 'authorization_code' || clientId !== SSO_CLIENT_ID || redirectUri !== SSO_REDIRECT_URI || !safeToken(code, 43, 512) || !safeToken(verifier, 43, 128) || !safeToken(state, 16, 512) || !safeToken(nonce, 16, 512) || (transaction && (state !== transaction.state || nonce !== transaction.nonce))) return send(res, 400, { ok: false, code: 'SSO_REQUEST_INVALID' }, combinedCookies(clearCookie(), clearTransactionCookie()));
    const exchanged = await rpc('school_sso_authorization_code_exchange', { p_code: code, p_client_id: clientId, p_redirect_uri: redirectUri, p_code_verifier: verifier, p_state: state, p_nonce: nonce });
    if (!exchanged?.ok || !exchanged.session_id || !exchanged.session_secret) return send(res, rpcStatus(exchanged, 401), exchanged || { ok: false, code: 'CENTRAL_SSO_EXCHANGE_FAILED' }, combinedCookies(clearCookie(), clearTransactionCookie()));
    const context = await rpc('school_registry_session_context_v2', { p_session_id: exchanged.session_id, p_session_secret: exchanged.session_secret });
    if (!context?.ok) return send(res, rpcStatus(context, 403), context, clearCookie());
    return send(res, 200, { ...publicSessionResult(exchanged), context }, combinedCookies(sessionCookie(exchanged.session_id, exchanged.session_secret), clearTransactionCookie()));
  }
  if (input.action !== 'login') return send(res, 400, { ok: false, code: 'REGISTRY_SESSION_ACTION_REQUIRED' }, clearCookie());
  const login = typeof input.login === 'string' ? input.login.trim() : '';
  const password = typeof input.password === 'string' ? input.password : '';
  if (!login || !password || password.length > 512) return send(res, 400, { ok: false, code: 'LOGIN_AND_PASSWORD_REQUIRED' }, clearCookie());
  const result = await rpc('school_registry_login_v2', { p_login: login, p_password: password });
  if (!result?.ok) return send(res, rpcStatus(result, 401), result || { ok: false, code: 'INVALID_LOGIN' }, clearCookie());
  if (result.must_change_password) return send(res, 200, { ok: true, code: 'PASSWORD_CHANGE_REQUIRED', must_change_password: true });
  if (!result.session_id || !result.session_secret) return send(res, 503, { ok: false, code: 'REGISTRY_SESSION_SERVICE_UNAVAILABLE' }, clearCookie());
  const context = await rpc('school_registry_session_context_v2', { p_session_id: result.session_id, p_session_secret: result.session_secret });
  if (!context?.ok) return send(res, rpcStatus(context, 401), context, clearCookie());
  return send(res, 200, { ...publicSessionResult(result), context }, sessionCookie(result.session_id, result.session_secret));
};
