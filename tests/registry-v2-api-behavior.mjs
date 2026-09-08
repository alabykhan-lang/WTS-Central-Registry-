import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

process.env.WTS_SUPABASE_SERVER_KEY = 'server-test-key';
const require = createRequire(import.meta.url);
const sessionHandler = require('../api/registry-session.js');
const registryHandler = require('../api/registry-v2.js');
const signatureHandler = require('../api/registry-signature.js');

function responseRecorder() {
  return {
    headers: {},
    statusCode: 0,
    setHeader(name, value) { this.headers[name.toLowerCase()] = value; },
    end(value) { this.body = JSON.parse(value); },
  };
}

const originalFetch = global.fetch;
try {
  const sessionId = '11111111-1111-4111-8111-111111111111';
  global.fetch = async (url) => ({
    ok: true,
    json: async () => String(url).includes('school_registry_login_v2')
      ? { ok: true, session_id: sessionId, session_secret: 'browser-must-not-see-this', expires_at: '2099-01-01T00:00:00Z' }
      : { ok: true, actor: { personId: '22222222-2222-4222-8222-222222222222' }, entitlements: { capabilities: ['registry.enter'] } },
  });
  const loginResponse = responseRecorder();
  await sessionHandler({
    method: 'POST',
    headers: { origin: 'https://wts-central-registry.vercel.app' },
    body: { action: 'login', login: 'WTS-001', password: 'valid-test-input' },
  }, loginResponse);
  assert.equal(loginResponse.statusCode, 200);
  assert.equal(loginResponse.body.session_id, undefined);
  assert.equal(loginResponse.body.session_secret, undefined);
  assert.match(loginResponse.headers['set-cookie'], /HttpOnly; Secure; SameSite=Lax/);
  assert.match(loginResponse.headers['set-cookie'], new RegExp(sessionId));

  let registryFetchCalled = false;
  global.fetch = async () => { registryFetchCalled = true; throw new Error('must not reach database'); };
  const originResponse = responseRecorder();
  await registryHandler({
    method: 'POST',
    headers: { origin: 'https://attacker.invalid', cookie: `wts_registry_session=${sessionId}.secret` },
    body: { kind: 'read', action: 'dashboard', payload: {} },
  }, originResponse);
  assert.equal(originResponse.statusCode, 403);
  assert.equal(originResponse.body.code, 'ORIGIN_NOT_ALLOWED');
  assert.equal(registryFetchCalled, false);

  let signatureFetches = 0;
  global.fetch = async () => {
    signatureFetches += 1;
    return { ok: true, json: async () => ({ ok: true, actor: { personId: '22222222-2222-4222-8222-222222222222' } }) };
  };
  const signatureResponse = responseRecorder();
  await signatureHandler({
    method: 'POST',
    headers: { origin: 'https://wts-central-registry.vercel.app', cookie: `wts_registry_session=${sessionId}.secret` },
    body: { dataUrl: `data:image/png;base64,${Buffer.from('not an image').toString('base64')}` },
  }, signatureResponse);
  assert.equal(signatureResponse.statusCode, 400);
  assert.equal(signatureResponse.body.code, 'SIGNATURE_IMAGE_INVALID');
  assert.equal(signatureFetches, 1);

  global.fetch = async () => ({
    ok: true,
    json: async () => ({
      ok: true,
      actor: {
        personId: '22222222-2222-4222-8222-222222222222',
        signaturePath: 'staff-signatures/33333333-3333-4333-8333-333333333333.png',
      },
    }),
  });
  const crossProfileSignatureResponse = responseRecorder();
  await signatureHandler({
    method: 'POST',
    headers: { origin: 'https://wts-central-registry.vercel.app', cookie: `wts_registry_session=${sessionId}.secret` },
    body: { operation: 'signed-url' },
  }, crossProfileSignatureResponse);
  assert.equal(crossProfileSignatureResponse.statusCode, 404);
  assert.equal(crossProfileSignatureResponse.body.code, 'SIGNATURE_PATH_INVALID');

  global.fetch = async () => ({ ok: true, json: async () => ({ ok: false, code: 'REGISTRY_ACCESS_NOT_GRANTED' }) });
  const revokedResponse = responseRecorder();
  await registryHandler({
    method: 'POST',
    headers: { origin: 'https://wts-central-registry.vercel.app', cookie: `wts_registry_session=${sessionId}.secret` },
    body: { kind: 'read', action: 'dashboard', payload: {} },
  }, revokedResponse);
  assert.equal(revokedResponse.statusCode, 403);
  assert.match(revokedResponse.headers['set-cookie'], /Max-Age=0/);
} finally {
  global.fetch = originalFetch;
}

console.log('Registry v2 API behavior and browser-boundary tests passed');
