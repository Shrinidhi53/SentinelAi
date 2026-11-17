'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const { getWebviewScriptWorkbench } = require('../out/webview/script-workbench.js');

function createNode(tag = 'div') {
  return {
    tag, children: [], textContent: '', value: '', disabled: false, className: '',
    listeners: {}, appendChild(child) { this.children.push(child); return child; },
    append(...children) { this.children.push(...children); },
    replaceChildren(...children) { this.children = children; },
    addEventListener(name, fn) { this.listeners[name] = fn; },
    click() { this.listeners.click?.({ target: this }); },
  };
}
function collectText(node) {
  return [node.textContent || '', ...(node.children || []).map(collectText)].join('\n');
}
test('webview workbench renders live coverage, findings, masked exposure, verdict, provenance, and export control', () => {
  const ids = ['workbench-profile','workbench-lab','workbench-lab-start','workbench-lab-status','workbench-lab-output','workbench-status','workbench-output','workbench-runtime-status','workbench-runtime-output','workbench-runtime','workbench-runtime-consent','workbench-start','workbench-cancel','workbench-save-report','workbench-save-status','workbench-network','workbench-limitations','workbench-project-state'];
  const nodes = Object.fromEntries(ids.map(id => [id, createNode()]));
  const messages = [];
  const listeners = {};
  const document = { getElementById: id => nodes[id], createElement: tag => createNode(tag), addEventListener() {} };
  const window = { addEventListener: (name, fn) => { listeners[name] = fn; } };
  vm.runInNewContext(getWebviewScriptWorkbench(), { document, window, vscode: { postMessage: msg => messages.push(msg) }, Blob: class {}, URL: { createObjectURL: () => 'blob:test', revokeObjectURL() {} } });
  assert.equal(messages[0].type, 'workbenchReady');
  listeners.message({ data: { type: 'workbenchCapabilities', capabilities: {
    profiles: [{ id: 'source', name: 'Source', checks: [{ id: 'secrets', available: true }] }],
    labs: [{ id: 'sql-injection', title: 'SQL injection', supported: true }], limitations: ['Not a certification'],
  } } });
  listeners.message({ data: { type: 'workbenchJob', job: {
    id: 'job-1', status: 'completed', events: [{ stage: 'scan', description: 'Finished', status: 'completed' }],
    result: {
      provenance: { mode: 'workspace-source-analysis', synthetic: false },
      coverage: [{ check: 'source', status: 'tested', filesScanned: 2, reason: '2 files', tools: { semgrep: { status: 'complete', exitCode: 0 }, bandit: { status: 'complete', exitCode: 0 } } }],
      findings: [{ severity: 'HIGH', type: 'SQL injection candidate', file: 'src/app.js', line: 7, explanation: 'Unsafe query construction' }],
      attacks: [{ sensitiveData: [{ dataType: 'Email Address', fieldPath: '$.user.email', maskedValue: 'us*****st', valueLength: 18 }] }],
      validations: [{ result: 'observed_exposure', attackName: 'Sensitive data', rationale: 'New response field' }],
    },
  } } });
  const rendered = collectText(nodes['workbench-output']);
  for (const value of ['Coverage','Findings','SQL injection candidate','Observed data exposure (masked)','$.user.email','us*****st','Runtime verdicts','OBSERVED EXPOSURE','workspace report']) {
    assert.ok(rendered.includes(value), `UI should show ${value}`);
  }
  assert.ok(!rendered.includes('user@example.test'), 'UI contains only the masked value');
  assert.ok(rendered.includes('Check') && rendered.includes('Scope / count'));
});

test('empty findings and incomplete coverage are never presented as a clean bill of health', () => {
  const ids = ['workbench-profile','workbench-lab','workbench-lab-start','workbench-lab-status','workbench-lab-output','workbench-status','workbench-output','workbench-runtime-status','workbench-runtime-output','workbench-runtime','workbench-runtime-consent','workbench-start','workbench-cancel','workbench-save-report','workbench-save-status','workbench-network','workbench-limitations','workbench-project-state'];
  const nodes = Object.fromEntries(ids.map(id => [id, createNode()]));
  const listeners = {};
  const document = { getElementById: id => nodes[id], createElement: tag => createNode(tag), addEventListener() {} };
  const window = { addEventListener: (name, fn) => { listeners[name] = fn; } };
  vm.runInNewContext(getWebviewScriptWorkbench(), { document, window, vscode: { postMessage() {} }, Blob: class {}, URL: { createObjectURL: () => 'blob:test', revokeObjectURL() {} } });
  listeners.message({ data: { type: 'workbenchJob', job: { id: 'job-2', status: 'completed', events: [], result: {
    findings: [], coverage: [
      { check: 'source', status: 'tested' },
      { check: 'dependencies', status: 'skipped', reason: 'Offline' },
      { check: 'authentication', status: 'unsupported', reason: 'No identity context' },
    ],
  } } } });
  const rendered = collectText(nodes['workbench-output']);
  assert.ok(rendered.includes('No findings among the checks actually run'));
  assert.ok(rendered.includes('not a security certification'));
  assert.ok(rendered.includes('dependencies'));
  assert.ok(rendered.includes('Offline'));
  assert.ok(rendered.includes('authentication'));
  assert.ok(rendered.includes('No identity context'));
});

test('legacy empty result plus failed scanner is marked incomplete and names the failed tool', () => {
  const { getWebviewScriptCore } = require('../out/webview/script-core.js');
  const source = getWebviewScriptCore();
  assert.match(source, /Static scanner coverage incomplete/);
  assert.match(source, /failedTools/);
  assert.match(source, /exitCode/);
  const extension = require('node:fs').readFileSync(require('node:path').join(__dirname, '../src/extension.ts'), 'utf8');
  assert.match(extension, /Scan incomplete — review coverage/);
  assert.doesNotMatch(extension, /SentinelAI: Clean/);
});

test('missing coverage is explicitly reported as unavailable rather than implying complete scan', () => {
  const ids = ['workbench-profile','workbench-lab','workbench-lab-start','workbench-lab-status','workbench-lab-output','workbench-status','workbench-output','workbench-runtime-status','workbench-runtime-output','workbench-runtime','workbench-runtime-consent','workbench-start','workbench-cancel','workbench-save-report','workbench-save-status','workbench-network','workbench-limitations','workbench-project-state'];
  const nodes = Object.fromEntries(ids.map(id => [id, createNode()]));
  const listeners = {};
  const document = { getElementById: id => nodes[id], createElement: tag => createNode(tag), addEventListener() {} };
  const window = { addEventListener: (name, fn) => { listeners[name] = fn; } };
  vm.runInNewContext(getWebviewScriptWorkbench(), { document, window, vscode: { postMessage() {} }, Blob: class {}, URL: { createObjectURL: () => 'blob:test', revokeObjectURL() {} } });
  listeners.message({ data: { type: 'workbenchJob', job: { id: 'job-3', status: 'completed', events: [], result: { findings: [] } } } });
  const rendered = collectText(nodes['workbench-output']);
  assert.ok(rendered.includes('Coverage unavailable: the backend did not report which checks ran. Treat this result as incomplete.'));
  assert.ok(rendered.includes('No findings among the checks actually run'));
});

test('failed scanner tool status and exit code remain visible in Workbench coverage table', () => {
  const ids = ['workbench-profile','workbench-lab','workbench-lab-start','workbench-lab-status','workbench-lab-output','workbench-status','workbench-output','workbench-runtime-status','workbench-runtime-output','workbench-runtime','workbench-runtime-consent','workbench-start','workbench-cancel','workbench-save-report','workbench-save-status','workbench-network','workbench-limitations','workbench-project-state'];
  const nodes = Object.fromEntries(ids.map(id => [id, createNode()]));
  const listeners = {};
  const document = { getElementById: id => nodes[id], createElement: tag => createNode(tag), addEventListener() {} };
  const window = { addEventListener: (name, fn) => { listeners[name] = fn; } };
  vm.runInNewContext(getWebviewScriptWorkbench(), { document, window, vscode: { postMessage() {} }, Blob: class {}, URL: { createObjectURL: () => 'blob:test', revokeObjectURL() {} } });
  listeners.message({ data: { type: 'workbenchJob', job: { id: 'job-scanner-status', status: 'completed', events: [], result: {
    findings: [], coverage: [{ check: 'source', status: 'inconclusive', filesScanned: 2, tools: {
      semgrep: { status: 'failed', exitCode: 2 }, bandit: { status: 'complete', exitCode: 0 },
    } }],
  } } } });
  const rendered = collectText(nodes['workbench-output']);
  assert.ok(rendered.includes('semgrep'));
  assert.ok(rendered.includes('failed · exit 2'));
  assert.ok(rendered.includes('bandit'));
  assert.ok(rendered.includes('complete · exit 0'));
  assert.ok(rendered.includes('Scanner failed; coverage incomplete.'));
});

test('sandbox report renderer displays exact planned/executed/skipped counts without a clean-result claim', () => {
  const { getWebviewScriptSandbox } = require('../out/webview/script-sandbox.js');
  const source = getWebviewScriptSandbox();
  assert.match(source, /VALIDATION PARTIAL/);
  assert.match(source, /Skipped/);
  assert.match(source, /notApplicable/);
  assert.match(source, /Probes Executed/);
  assert.match(source, /not a security certification/);
});

test('primary workbench separates workspace scans from runtime validation and omits the removed diagnostic lab', () => {
  const { getWebviewBody } = require('../out/webview/body.js');
  const body = getWebviewBody();
  assert.match(body, /Run workspace scan/i);
  assert.match(body, /Validate local project/i);
  assert.doesNotMatch(body, /Safe Simulation/);
  assert.doesNotMatch(body, /workbench-lab|diagnostic self-test/i);
  assert.match(body, /sentinelai-report\.json and sentinelai-report\.md/);
  assert.doesNotMatch(body, /id="btn-scan"/);
});

test('workbench reports that completed results are automatically persisted in the project', () => {
  const ids = ['workbench-profile','workbench-status','workbench-output','workbench-runtime-status','workbench-runtime-output','workbench-runtime','workbench-runtime-consent','workbench-start','workbench-cancel','workbench-save-status','workbench-network','workbench-limitations','workbench-project-state'];
  const nodes = Object.fromEntries(ids.map(id => [id, createNode()]));
  const messages = [], listeners = {};
  const document = { getElementById: id => nodes[id], createElement: tag => createNode(tag), addEventListener() {} };
  const window = { addEventListener: (name, fn) => { listeners[name] = fn; } };
  vm.runInNewContext(getWebviewScriptWorkbench(), { document, window, vscode: { postMessage: msg => messages.push(msg) }, Date });
  assert.equal(messages[0].type, 'workbenchReady');
  listeners.message({ data: { type: 'workbenchProjectReportUpdated', path: 'sentinelai-report.json', updatedAt: '2026-10-18T00:00:00.000Z' } });
  assert.match(nodes['workbench-save-status'].textContent, /sentinelai-report\.json/);
});
