'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const Module = require('node:module');
const originalLoad = Module._load;
const reads = [];
const files = [
  { fsPath: '/workspace/package-lock.json', value: Buffer.from(JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/a': { version: '1.0.0' } } })) },
  { fsPath: '/workspace/large/package-lock.json', value: Buffer.from('x'.repeat(2 * 1024 * 1024 + 1)) },
  { fsPath: '/workspace/source.ts', value: Buffer.from('const app = true;') },
  { fsPath: '/workspace/.env', value: Buffer.from('SECRET=do-not-read') },
];
Module._load = function(request, parent, isMain) {
  if (request === 'vscode') return { workspace: {
    findFiles: async () => files.map(file => ({ fsPath: file.fsPath, path: file.fsPath })),
    asRelativePath: uri => path.relative('/workspace', uri.fsPath),
    fs: { readFile: async uri => { reads.push(uri.fsPath); return files.find(file => file.fsPath === uri.fsPath).value; } },
  } };
  return originalLoad.call(this, request, parent, isMain);
};
const services = require('../out/services.js');
Module._load = originalLoad;

test('lockfiles are kept whole within the explicit size budget; oversized or incomplete JSON is skipped', async () => {
  reads.length = 0;
  const oversizedIndex = files.findIndex(file => file.fsPath.endsWith('/large/package-lock.json'));
  const [oversized] = files.splice(oversizedIndex, 1);
  const found = await services.collectWorkspaceFiles({ securityProfile: 'dependencies' });
  assert.deepEqual(found.map(file => file.path), ['package-lock.json', 'source.ts']);
  assert.equal(JSON.parse(found[0].code).packages['node_modules/a'].version, '1.0.0');
  assert.equal(reads.includes('/workspace/.env'), false);
  assert.equal(reads.includes('/workspace/source.ts'), true);
  files.push(oversized);
  await assert.rejects(services.collectWorkspaceFiles({ securityProfile: 'dependencies' }), /analysis limit.*stopped/);
});
