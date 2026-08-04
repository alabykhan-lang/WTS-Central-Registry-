const base = process.env.CENTRAL_REGISTRY_URL || 'https://wts-central-registry.vercel.app';

async function expect(name, url, options, status, code) {
  const response = await fetch(url, options);
  const body = await response.json().catch(() => ({}));
  if (response.status !== status || body.code !== code) {
    throw new Error(`${name} expected ${status}/${code}, received ${response.status}/${body.code || 'no-code'}`);
  }
}

await expect('missing cookie', `${base}/api/registry-management`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ operation: 'credentialWrite', action: 'issueTemporaryCredential', payload: {} }),
}, 401, 'REGISTRY_SESSION_REQUIRED');

await expect('disallowed origin', `${base}/api/registry-management`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', origin: 'https://evil.example' },
  body: JSON.stringify({ operation: 'scopeWrite', action: 'setScope', payload: {} }),
}, 403, 'ORIGIN_NOT_ALLOWED');

console.log('Central Registry management contract passed');
