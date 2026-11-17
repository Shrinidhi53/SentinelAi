const { test } = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const originalLoad = Module._load;
const reads = [], calls = [];
const files = new Map([['src/index.ts', 'export const source = true;'], ['.env', 'SECRET=never-read'], ['package-lock.json', '{"lockfileVersion":3}'], ['Dockerfile', 'FROM node:22']]);
Module._load = function(id, ...args) {
  if (id === 'vscode') return { workspace: { findFiles: async () => [...files.keys()].map(fsPath => ({ fsPath })), asRelativePath: uri => uri.fsPath, fs: { readFile: async uri => { reads.push(uri.fsPath); return Buffer.from(files.get(uri.fsPath)); } } } };
  if (id === 'axios') return { get: async (url, options) => { calls.push({ method: 'get', url, options }); return { data: url.endsWith('capabilities') ? { profiles: [], labs: [], limitations: [] } : { job: { id: 'abc', kind: 'scan', status: 'completed', events: [] } } }; }, post: async (url, body, options) => { calls.push({ method: 'post', url, body, options }); return { data: { job: { id: 'abc', kind: 'scan', status: 'queued', events: [] } } }; }, delete: async (url, options) => { calls.push({ method: 'delete', url, options }); return { data: { job: { id: 'abc', kind: 'scan', status: 'cancelled', events: [] } } }; } };
  return originalLoad.call(this, id, ...args);
};
const services = require('../out/services.js');
Module._load = originalLoad;
test('existing collector has safe workbench profile mode and maps content without reading excluded files', async () => {
  reads.length = 0;
  const source = await services.collectWorkspaceFiles({ securityProfile: 'source' });
  assert.deepEqual(source.map(f => f.path), ['src/index.ts']);
  assert.equal(reads.includes('.env'), false);
  const deps = await services.collectWorkspaceFiles({ securityProfile: 'dependencies' });
  assert.ok(deps.some(f => f.path === 'package-lock.json'));
});
test('security adapter uses bounded local requests with redirects disabled and explicit job bodies', async () => {
  assert.equal(typeof services.securityAPI, 'object', 'security API adapter must exist');
  await services.securityAPI.capabilities();
  await services.securityAPI.create({ kind: 'scan', options: { allowAdvisoryNetwork: false } });
  await services.securityAPI.get('abc');
  await services.securityAPI.cancel('abc');
  assert.deepEqual(calls.map(c => c.url), ['http://localhost:3000/security/capabilities', 'http://localhost:3000/security/jobs', 'http://localhost:3000/security/jobs/abc', 'http://localhost:3000/security/jobs/abc']);
  for (const c of calls) { assert.equal(c.options.maxRedirects, 0); assert.equal(c.options.proxy, false); assert.ok(c.options.timeout <= 30000); }
});
