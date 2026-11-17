'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createRuntimeReport } = require('../out/webview/runtime-report.js');

test('runtime coverage derives per-type planned/executed/skipped/failed/unknown counts', () => {
  const report = createRuntimeReport({ target: { url: 'http://127.0.0.1:8080/' }, attacks: [
    { id: 'a1', attackType: 'security_headers', status: 'success', executed: true, response: { statusCode: 200 } },
    { id: 'a2', attackType: 'security_headers', status: 'not_applicable', execution: 'skipped', executed: false },
    { id: 'b1', attackType: 'idor', status: 'failed' },
    { id: 'c1', attackType: 'ssrf' },
  ], validations: [
    { attackId: 'a1', attackType: 'security_headers', result: 'observed_exposure' },
    { attackId: 'a2', attackType: 'security_headers', result: 'not_applicable' },
    { attackId: 'b1', attackType: 'idor', result: 'failed' },
  ] });
  assert.deepEqual(report.coverage.slice(-3), [
    { check: 'attack type: security_headers', status: 'tested', count: 1, planned: 2, executed: 1, skipped: 1, failed: 0, unknown: 0, notApplicable: 1,
      reason: 'Counts are per recorded probe; unlisted application routes/behaviors were not assessed.' },
    { check: 'attack type: idor', status: 'failed', count: 0, planned: 1, executed: 0, skipped: 0, failed: 1, unknown: 0, notApplicable: 0,
      reason: 'Counts are per recorded probe; unlisted application routes/behaviors were not assessed.' },
    { check: 'attack type: ssrf', status: 'inconclusive', count: 0, planned: 1, executed: 0, skipped: 0, failed: 0, unknown: 1, notApplicable: 0,
      reason: 'Counts are per recorded probe; unlisted application routes/behaviors were not assessed.' },
  ]);
});

test('runtime adapter removes response/evidence body and secret header values while preserving exposure indicators', () => {
  const report = createRuntimeReport({ target: { url: 'http://127.0.0.1:8080/' }, attacks: [{
    id: 'a', attackType: 'security_headers', status: 'success', executed: true,
    request: { method: 'GET', url: 'http://127.0.0.1/', headers: { Authorization: 'TOKEN_SENTINEL', Accept: 'text/html' } },
    response: { statusCode: 200, body: 'RAW_BODY_SENTINEL', bodyPreview: 'RAW_PREVIEW_SENTINEL' },
    evidence: [{ type: 'response', content: 'RAW_EVIDENCE_SENTINEL' }],
    sensitiveData: [{ dataType: 'Email', maskedValue: 'a***@x', fieldPath: '$.email' }],
  }], validations: [] });
  const serialized = JSON.stringify(report);
  for (const secret of ['TOKEN_SENTINEL', 'RAW_BODY_SENTINEL', 'RAW_PREVIEW_SENTINEL', 'RAW_EVIDENCE_SENTINEL']) assert.equal(serialized.includes(secret), false);
  assert.match(serialized, /a\*\*\*@x/);
  assert.match(serialized, /statusCode/);
});

test('runtime adapter classifies failed probes before counting their response as executed', () => {
  const report = createRuntimeReport({ target: { url: 'http://127.0.0.1:8080/' }, attacks: [
    { id: 'failed-response', attackType: 'sqli', status: 'failed', execution: 'failed', executed: true, response: { statusCode: 500 } },
  ], validations: [{ attackId: 'failed-response', attackType: 'sqli', result: 'failed' }] });
  assert.equal(report.summary.runtimeFailed, 1);
  assert.equal(report.summary.runtimeTests, 0);
  assert.deepEqual(report.coverage.at(-1), {
    check: 'attack type: sqli', status: 'failed', count: 0, planned: 1, executed: 0, skipped: 0,
    failed: 1, unknown: 0, notApplicable: 0,
    reason: 'Counts are per recorded probe; unlisted application routes/behaviors were not assessed.',
  });
});
