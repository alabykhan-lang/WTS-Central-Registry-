import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const handler = require('../api/registry-session.js');
const headers = new Map();
let body = '';
const req = {
  method: 'POST',
  headers: { origin: 'https://wts-central-registry.vercel.app' },
  body: { action: 'sso_begin', portal_origin: 'https://wts-school-platform.vercel.app' },
};
const res = {
  statusCode: 0,
  setHeader(name, value) { headers.set(name.toLowerCase(), value); },
  end(value) { body = value || ''; },
};

await handler(req, res);
assert.equal(res.statusCode, 200);
const payload = JSON.parse(body);
assert.equal(payload.ok, true);
const authorize = new URL(payload.authorize_url);
assert.equal(authorize.origin, 'https://wts-school-platform.vercel.app');
assert.equal(authorize.pathname, '/api/sso/authorize');
assert.equal(authorize.searchParams.get('client_id'), 'central_registry');
assert.equal(authorize.searchParams.get('code_challenge_method'), 'S256');
const cookie = String(headers.get('set-cookie'));
assert.match(cookie, /wts_registry_sso_transaction=/);
assert.match(cookie, /HttpOnly/);
assert.match(cookie, /Secure/);
assert.match(cookie, /SameSite=Lax/);
console.log('Registry SSO begin contract passed');
