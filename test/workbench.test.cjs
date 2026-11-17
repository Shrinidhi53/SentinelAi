const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const modulePath = '../out/security-workbench.js';
function workbench() {
  assert.ok(fs.existsSync(require('node:path').join(__dirname, modulePath)), 'Security Workbench helpers must exist');
  return require(modulePath);
}
function harness() {
  const messages = [], requests = [], timers = new Map();
  let next = 0;
  const api = {
    capabilities: async () => ({ profiles: [{ id: 'source', label: 'Source' }, { id: 'dependencies', label: 'Dependencies' }], limitations: ['Not runtime validation'] }),
    create: async body => { requests.push(body); return { id: 'job-1', kind: body.kind, status: 'queued', events: [] }; },
    get: async () => ({ id: 'job-1', kind: 'scan', status: 'completed', events: [{ sequence: 1, stage: 'analysis', status: 'completed', description: 'Done' }], result: { findings: [], coverage: [{ id: 'source', status: 'completed' }] } }),

    cancel: async () => ({ id: 'job-1', kind: 'scan', status: 'cancelled', events: [] })
  };
  const controller = new (workbench().SecurityWorkbenchController)({ api, collect: async () => [{ path: 'index.ts', content: 'source' }], emit: message => messages.push(message), schedule: fn => { timers.set(++next, fn); return next; }, unschedule: id => timers.delete(id) });
  return { controller, api, messages, requests, timers, tick: async () => { const [id, fn] = timers.entries().next().value; timers.delete(id); await fn(); } };
}
test('controller loads capabilities, sends explicit network consent and polls real job events until terminal', async () => {
  assert.equal(typeof workbench().SecurityWorkbenchController, 'function', 'job controller must exist');
  const h = harness();
  await h.controller.loadCapabilities();
  assert.equal(h.messages.at(-1).type, 'workbenchCapabilities');
  await h.controller.start({ kind: 'scan', profile: 'source', allowAdvisoryNetwork: false });
  assert.deepEqual(h.requests[0], { kind: 'scan', profile: 'source', files: [{ path: 'index.ts', content: 'source' }], options: { allowAdvisoryNetwork: false } });
  assert.equal(h.messages.at(-1).job.status, 'queued');
  assert.equal(h.timers.size, 1);
  await h.tick();
  assert.equal(h.messages.at(-1).job.status, 'completed');
  assert.equal(h.messages.at(-1).job.events[0].description, 'Done');
  assert.equal(h.timers.size, 0);
});
test('controller rejects unavailable choices, prevents overlaps, cancels and reruns with fresh files', async () => {
  const h = harness();
  await h.controller.loadCapabilities();
  await h.controller.start({ kind: 'scan', profile: 'source', allowAdvisoryNetwork: false });
  await h.controller.start({ kind: 'scan', profile: 'dependencies', allowAdvisoryNetwork: false });
  assert.equal(h.requests.length, 1);
  await h.controller.cancel();
  assert.equal(h.messages.at(-1).job.status, 'cancelled');
  assert.equal(h.timers.size, 0);
  await h.controller.rerun();
  assert.equal(h.requests.length, 2);
  assert.equal(h.requests[1].profile, 'source');
  h.controller.dispose();
  assert.equal(h.timers.size, 0);
});
test('controller poll errors are generic, persist failure hook is called, retry without fabricated completion', async () => {
  const h = harness();
  const errors = [];
  h.controller.deps.onError = message => errors.push(message);
  await h.controller.loadCapabilities();
  await h.controller.start({ kind: 'scan', profile: 'source', allowAdvisoryNetwork: false });
  h.api.get = async () => { throw new Error('SECRET TOKEN'); };
  await h.tick();
  assert.equal(h.messages.at(-1).type, 'workbenchError');
  assert.equal(errors.length, 1);
  assert.match(errors[0], /Connection interrupted/);
  assert.equal(JSON.stringify(h.messages).includes('SECRET TOKEN'), false);
  assert.equal(h.timers.size, 1);
  h.controller.dispose();
  assert.equal(h.timers.size, 0);
});
test('workspace policy excludes secrets and includes lockfiles only for dependency profiles', () => {
  const { shouldCollectFile } = workbench();
  for (const path of ['.env', '.env.local', 'config/prod.env', 'id_rsa', 'keys/private.pem', '.aws/credentials', 'secrets.json', 'config/credentials.yaml', 'node_modules/lib/index.js']) {
    assert.equal(shouldCollectFile(path, 'comprehensive'), false, path);
  }
  assert.equal(shouldCollectFile('src/index.ts', 'source'), true);
  assert.equal(shouldCollectFile('package-lock.json', 'source'), false);
  assert.equal(shouldCollectFile('package-lock.json', 'dependencies'), true);
  assert.equal(shouldCollectFile('pnpm-lock.yaml', 'comprehensive'), true);
  assert.equal(shouldCollectFile('Dockerfile', 'infrastructure'), true);
  assert.equal(shouldCollectFile('infra/main.tf', 'infrastructure'), true);
});

test('legacy status stays incomplete when a scanner failed despite empty findings', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const extension = fs.readFileSync(path.join(__dirname, '../src/extension.ts'), 'utf8');
  assert.match(extension, /scannerComplete\s*=\s*scannerTools\.length\s*>\s*0\s*&&\s*scannerTools\.every/);
  assert.match(extension, /SentinelAI: Scan incomplete/);
  assert.doesNotMatch(extension, /SentinelAI: Clean/);
});

test('workbench renderer escapes evidence and includes coverage, verdicts, exposure and project report status', () => {
  const { getWebviewScriptWorkbench } = require('../out/webview/script-workbench.js');
  const source = getWebviewScriptWorkbench();
  for (const expected of [
    'Coverage', 'Findings', 'Observed data exposure (masked)', 'Runtime verdicts',
    'Coverage', 'sentinelai-report.json', 'workbenchProjectReportUpdated',
  ]) assert.ok(source.includes(expected), `missing renderer feature: ${expected}`);
  assert.match(source, /textContent=/, 'dynamic evidence should be rendered with textContent');
  assert.doesNotMatch(source, /innerHTML\s*=/, 'renderer should not inject findings as HTML');
});
