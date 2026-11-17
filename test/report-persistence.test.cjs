const { test } = require('node:test');
const assert = require('node:assert/strict');
const { persistUnifiedReport } = require('../out/report-persistence.js');
const { renderProjectReportMarkdown } = require('../out/project-report.js');
function adapter(seed = {}) {
  const files = new Map(Object.entries(seed).map(([key, value]) => [key, Buffer.from(value)]));
  return { files, api: {
    read: async path => { if (!files.has(path)) throw Object.assign(new Error('missing'), { code: 'FileNotFound' }); return files.get(path); },
    write: async (path, data) => { files.set(path, Buffer.from(data)); }, delete: async path => { files.delete(path); },
  } };
}
test('every workflow updates one shared four-section report; LLM skipped is explicit', async () => {
  const fs = adapter();
  await persistUnifiedReport(fs.api, 'report.json', 'report.md', 'staticAnalysis', { findings: [{ type: 'SQLi' }] }, '2026-01-01T00:00:00Z');
  let json = JSON.parse(fs.files.get('report.json').toString());
  assert.deepEqual(Object.keys(json.sections).sort(), ['llmAnalysis', 'projectValidation', 'safeSimulation', 'staticAnalysis']);
  assert.equal(json.sections.staticAnalysis.status, 'completed');
  assert.equal(json.sections.llmAnalysis.status, 'skipped');
  assert.match(fs.files.get('report.md').toString(), /## LLM analysis[\s\S]*disabled/i);
  await persistUnifiedReport(fs.api, 'report.json', 'report.md', 'safeSimulation', { mode: 'simulation', projectVulnerabilityConfirmed: false }, '2026-01-01T00:01:00Z');
  json = JSON.parse(fs.files.get('report.json').toString());
  assert.equal(json.sections.staticAnalysis.result.findings[0].type, 'SQLi');
  assert.equal(json.sections.safeSimulation.status, 'completed');
  assert.match(fs.files.get('report.md').toString(), /not test or establish vulnerabilities in this workspace/i);
});
test('failed Markdown write restores both files; foreign reports are not overwritten', async () => {
  const fs = adapter({ 'report.json': '{"owner":"user"}', 'report.md': 'existing markdown' });
  await assert.rejects(persistUnifiedReport(fs.api, 'report.json', 'report.md', 'staticAnalysis', {}), /not a SentinelAI report/);
  assert.equal(fs.files.get('report.md').toString(), 'existing markdown');
  const second = adapter();
  second.api.write = async (path, data) => { if (path === 'report.md') throw new Error('disk full'); second.files.set(path, Buffer.from(data)); };
  await assert.rejects(persistUnifiedReport(second.api, 'report.json', 'report.md', 'staticAnalysis', {}), /disk full/);
  assert.equal(second.files.has('report.json'), false);
  assert.equal(second.files.has('report.md'), false);
});

test('a foreign Markdown report is protected even when the JSON report is absent', async () => {
  const fs = adapter({ 'report.md': '# My Project Notes\nkeep me' });
  await assert.rejects(persistUnifiedReport(fs.api, 'report.json', 'report.md', 'staticAnalysis', {}), /Markdown report is not a SentinelAI report/);
  assert.equal(fs.files.has('report.json'), false);
  assert.equal(fs.files.get('report.md').toString(), '# My Project Notes\nkeep me');
});

test('runtime report persistence removes raw body and secret sentinels but preserves masked exposure context', async () => {
  const fs = adapter();
  const report = await persistUnifiedReport(fs.api, 'report.json', 'report.md', 'projectValidation', {
    attacks: [{ response: { statusCode: 200, body: 'RAW_BODY_SENTINEL', bodyPreview: 'RAW_PREVIEW_SENTINEL' }, request: { headers: { Authorization: 'TOKEN_SENTINEL', Accept: 'text/html' } }, evidence: [{ type: 'response', content: 'RAW_EVIDENCE_SENTINEL' }], sensitiveData: [{ dataType: 'Email', maskedValue: 'a***@x', fieldPath: '$.email' }] }],
  });
  const json = fs.files.get('report.json').toString();
  assert.doesNotMatch(json, /RAW_BODY_SENTINEL|RAW_PREVIEW_SENTINEL|TOKEN_SENTINEL|RAW_EVIDENCE_SENTINEL/);
  assert.match(json, /\[REDACTED 17 chars\]/);
  assert.match(json, /a\*\*\*@x/);
  assert.doesNotMatch(renderProjectReportMarkdown(report), /RAW_BODY_SENTINEL|RAW_EVIDENCE_SENTINEL/);
});

test('running LLM checkpoints preserve completed static findings in JSON and Markdown', async () => {
  const fs = adapter();
  await persistUnifiedReport(fs.api, 'report.json', 'report.md', 'staticAnalysis', { findings: [{ type: 'static finding' }] });
  await persistUnifiedReport(fs.api, 'report.json', 'report.md', 'llmAnalysis', {
    status: 'running', reason: 'Local model is reviewing source.', findings: [],
    coverage: [{ check: 'llm', status: 'running' }],
  });
  const report = JSON.parse(fs.files.get('report.json').toString());
  assert.equal(report.sections.staticAnalysis.status, 'completed');
  assert.equal(report.sections.staticAnalysis.result.findings[0].type, 'static finding');
  assert.equal(report.sections.llmAnalysis.status, 'running');
  assert.match(fs.files.get('report.md').toString(), /Status: \*\*RUNNING\*\*/);
  assert.match(fs.files.get('report.md').toString(), /Analysis is in progress/);
});

test('legacy report migrates and extension host integration persists static, LLM, and Project Validation sections', async () => {
  const Module = require('node:module');
  const originalLoad = Module._load;
  const writes = new Map();
  const folder = { fsPath: '/workspace', path: '/workspace' };
  const job = { id: 'report-test-job', kind: 'scan', status: 'completed', events: [], result: {
    findings: [{ id: 'llm-1', source: 'ai', type: 'LLM finding' }], llmFindings: [{ id: 'llm-1', source: 'ai', type: 'LLM finding' }],
    staticFindings: [], filesScanned: 1, profile: 'source', llmUsed: true, llmEnabled: true, llmReason: 'Local model ran.',
    coverage: [{ check: 'source', status: 'tested' }], provenance: { mode: 'test' },
  } };
  const vscode = {
    workspace: {
      workspaceFolders: [{ uri: folder }], registerTextDocumentContentProvider: () => ({ dispose() {} }),
      fs: { readFile: async uri => { if (!writes.has(uri.fsPath)) throw Object.assign(new Error('missing'), { code: 'FileNotFound' }); return writes.get(uri.fsPath); },
        writeFile: async (uri, data) => writes.set(uri.fsPath, Buffer.from(data)), delete: async uri => writes.delete(uri.fsPath) },
      asRelativePath: uri => uri.fsPath.replace('/workspace/', ''),
    },
    Uri: { joinPath: (base, name) => ({ fsPath: `${base.fsPath}/${name}` }) },
    StatusBarAlignment: { Left: 1 }, window: { createStatusBarItem: () => ({ show() {}, text: '', tooltip: '', command: '' }), showWarningMessage() {} },
    commands: { registerCommand() { return { dispose() {} }; } },
  };
  const axios = {
    get: async () => ({ data: { job } }),
    post: async url => ({ data: url.endsWith('/sandbox/run') ? { mode: 'project-validation', attacks: [], validations: [], events: [], summary: {}, target: { url: 'http://127.0.0.1:3000' } } : { job } }),
    delete: async () => ({ data: { job } }),
  };
  Module._load = function(id, ...args) { return id === 'vscode' ? vscode : id === 'axios' ? axios : originalLoad.call(this, id, ...args); };
  process.env.SENTINELAI_HOST_TEST = '1';
  try {
    const extension = require('../out/extension.js');
    const result = await extension.activate({ subscriptions: [] });
    await result.runWorkbenchIntegration('http://127.0.0.1:3000', [{ path: 'app.js', content: 'const safe = true;' }]);
    const json = JSON.parse(writes.get('/workspace/sentinelai-report.json').toString());
    assert.equal(json.schemaVersion, 2);
    assert.equal(json.sections.staticAnalysis.status, 'completed');
    assert.equal(json.sections.llmAnalysis.status, 'completed');
    assert.equal(json.sections.llmAnalysis.result.findings[0].type, 'LLM finding');
    assert.equal(json.sections.projectValidation.status, 'completed');
    assert.match(writes.get('/workspace/sentinelai-report.md').toString(), /## Project Validation/);
  } finally { delete process.env.SENTINELAI_HOST_TEST; Module._load = originalLoad; }
});

test('failed validation is recorded without replacing previous successful static results', async () => {
  const { recordReportFailure, completeProjectReport, mergeProjectReport } = require('../out/project-report.js');
  const { persistUnifiedReport } = require('../out/report-persistence.js');
  const fs = adapter();
  await persistUnifiedReport(fs.api, 'report.json', 'report.md', 'staticAnalysis', { findings: [{ type: 'kept finding' }] });
  const old = JSON.parse(fs.files.get('report.json').toString());
  const failed = recordReportFailure(old, 'projectValidation', 'target unavailable');
  await fs.api.write('report.json', Buffer.from(JSON.stringify(failed)));
  await fs.api.write('report.md', Buffer.from(require('../out/project-report.js').renderProjectReportMarkdown(failed)));
  const report = JSON.parse(fs.files.get('report.json').toString());
  assert.equal(report.sections.staticAnalysis.status, 'completed');
  assert.equal(report.sections.staticAnalysis.result.findings[0].type, 'kept finding');
  assert.equal(report.sections.projectValidation.status, 'skipped');
  assert.match(report.sections.projectValidation.reason, /target unavailable/);
  assert.match(fs.files.get('report.md').toString(), /Not completed: target unavailable/);
  assert.equal(completeProjectReport(mergeProjectReport(report, 'staticAnalysis', { findings: [] })).sections.projectValidation.status, 'skipped');
});
