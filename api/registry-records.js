'use strict';

module.exports = function retiredRegistryRecords(_req, res) {
  res.statusCode = 410;
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify({ ok: false, code: 'REGISTRY_LEGACY_ROUTE_RETIRED', replacement: '/api/registry-v2' }));
};
