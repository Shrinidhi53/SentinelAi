const { test } = require('node:test');
const assert = require('node:assert/strict');
const { mergeProjectReport, completeProjectReport, recordReportFailure, renderProjectReportMarkdown } = require('../out/project-report.js');

test('single workflow creates all four sections with skipped reasons; static and simulation produce one JSON/Markdown report', () => {
  const report = completeProjectReport(mergeProjectReport(null, 'staticAnalysis', {
    findings: [{ severity: 'HIGH', type: 'SQL injection candidate', file: 'src/db.js', line: '4' }],
    coverage: [{ check: 'source', status: 'tested', reason: 'Semgrep ran' }],
    provenance: { mode: 'workspace-source-analysis' },
  }, '2026-10-18T01:00:00.000Z'), '2026-10-18T01:00:00.000Z');
  assert.equal(report.schemaVersion, 2);
  assert.deepEqual(Object.keys(report.sections).sort(), ['llmAnalysis', 'projectValidation', 'safeSimulation', 'staticAnalysis']);
  assert.equal(report.sections.staticAnalysis.status, 'completed');
  assert.equal(report.sections.llmAnalysis.status, 'skipped');
  assert.equal(report.sections.projectValidation.status, 'skipped');
  assert.equal(report.sections.safeSimulation.status, 'skipped');
  const markdown = renderProjectReportMarkdown(report);
  for (const title of ['## Static analysis', '## LLM analysis', '## Safe Simulation', '## Project Validation']) assert.ok(markdown.includes(title));
  assert.ok(markdown.includes('SQL injection candidate'));
  assert.ok(markdown.includes('LLM analysis was disabled'));
  assert.ok(markdown.includes('No findings: this workflow was skipped'));
});

test('LLM skipped status and individual sections survive replacement; Markdown covers both outputs', () => {
  let report = completeProjectReport(mergeProjectReport(null, 'staticAnalysis', { findings: [], llmUsed: false }));
  report = mergeProjectReport(report, 'llmAnalysis', { status: 'skipped', reason: 'LLM disabled.' });
  report = mergeProjectReport(report, 'safeSimulation', { passed: true, projectVulnerabilityConfirmed: false });
  report = mergeProjectReport(report, 'projectValidation', { findings: [], coverage: [{ check: 'probes', status: 'skipped' }] });
  assert.equal(report.sections.llmAnalysis.status, 'skipped');
  assert.equal(report.sections.safeSimulation.status, 'completed');
  assert.equal(report.sections.projectValidation.status, 'completed');
  assert.deepEqual(report.sections.staticAnalysis.result.findings, []);
  const md = renderProjectReportMarkdown(report);
  assert.match(md, /LLM disabled/);
  assert.match(md, /synthetic fixtures|synthetic/i);
  assert.match(md, /Project Validation/);
  const repeat = mergeProjectReport(report, 'staticAnalysis', { findings: [{ id: 'new' }] });
  assert.equal(repeat.sections.staticAnalysis.result.findings[0].id, 'new');
  assert.equal(repeat.sections.safeSimulation.result.passed, true);
});

test('Safe Simulation and Project Validation render detailed aligned coverage and masked exposure tables', () => {
  const report = completeProjectReport(mergeProjectReport(null, 'safeSimulation', {
    mode: 'simulation', provenance: { mode: 'simulation', synthetic: true },
    summary: { findings: 0, syntheticConfirmed: 42, observedExposures: 2, plannedProbes: 44, runtimeTests: 44, skippedProbes: 0, runtimeFailed: 0 },
    attacks: [{ attackName: 'SQL Injection', attackType: 'sqli', execution: 'executed', runtimeVerdict: 'confirmed', sensitiveData: [{ category: 'personal_data', dataType: 'Email Address', maskedValue: 'admi********ocal', fieldPath: '$.email' }] }],
    validations: [{ attackId: 'a', result: 'confirmed', rationale: 'Fixture signal detected.' }],
    exposures: [{ category: 'personal_data', dataType: 'Email Address', maskedValue: 'admi********ocal', fieldPath: '$.email' }],
  }));
  const sim = renderProjectReportMarkdown(report);
  assert.match(sim, /Synthetic signals reproduced \| 42/);
  assert.match(sim, /SQL Injection/);
  assert.match(sim, /admi\*+ocal/);
  assert.match(sim, /not project findings/i);
  const runtime = mergeProjectReport(report, 'projectValidation', {
    mode: 'project-validation',
    summary: { findings: 11, confirmed: 0, observedExposures: 1, inconclusive: 5, notReproduced: 5, notApplicable: 35, runtimeTests: 7, runtimeFailed: 0, plannedProbes: 38, skippedProbes: 31, unknownProbes: 0 },
    coverage: [{ check: 'attack type: cors', planned: 1, executed: 1, skipped: 0, notApplicable: 0, failed: 0, unknown: 0 }],
    attacks: [{ attackName: 'CORS Misconfiguration', attackType: 'cors', execution: 'executed', response: { statusCode: 200, bodyPreview: 'SECRET_BODY_MARKER' }, rationale: 'Observed missing CORS response policy.' }],
    validations: [{ attackId: 'cors', result: 'observed_exposure', rationale: 'Missing recommended CORS response policy.' }],
    exposures: [{ category: 'security-configuration', dataType: 'CORS policy', fieldPath: 'Access-Control-Allow-Origin', maskedValue: 'not present' }],
  });
  const md = renderProjectReportMarkdown(runtime);
  assert.match(md, /Planned \/ executed \/ skipped \| 38 \/ 7 \/ 31/);
  assert.match(md, /Not applicable \/ failed \/ unknown \| 35 \/ 0 \/ 0/);
  assert.match(md, /CORS Misconfiguration/);
  assert.match(md, /Observed data exposure \(masked\)/);
  assert.doesNotMatch(md, /SECRET_BODY_MARKER/);
});

test('existing foreign JSON report remains protected; legacy schema migrates to four sections', () => {
  assert.throws(() => mergeProjectReport({ owner: 'project' }, 'staticAnalysis', {}), /left unchanged/);
  const legacy = { format: 'sentinelai-project-report', schemaVersion: 1, createdAt: 'old', updatedAt: 'old', runs: {
    workspaceScan: { updatedAt: 'a', result: { findings: [] } },
    safeSimulation: { updatedAt: 'b', result: { passed: true } },
  } };
  const migrated = completeProjectReport(mergeProjectReport(legacy, 'projectValidation', { findings: [] }));
  assert.equal(migrated.schemaVersion, 2);
  assert.equal(migrated.sections.staticAnalysis.status, 'completed');
  assert.equal(migrated.sections.safeSimulation.status, 'completed');
  assert.equal(migrated.sections.llmAnalysis.status, 'skipped');
  assert.equal(migrated.sections.projectValidation.status, 'completed');
  const failed = recordReportFailure(migrated, 'projectValidation', 'Target unavailable');
  assert.equal(failed.sections.projectValidation.status, 'completed');
  assert.equal(failed.sections.staticAnalysis.status, 'completed');
  assert.equal(failed.sections.projectValidation.result.lastAttempt.status, 'failed');
  const retryFailure = recordReportFailure(migrated, 'safeSimulation', 'interrupted');
  assert.equal(retryFailure.sections.safeSimulation.status, 'completed');
  assert.equal(retryFailure.sections.safeSimulation.result.lastAttempt.status, 'failed');
  assert.match(renderProjectReportMarkdown(retryFailure), /Latest attempt failed: interrupted/);
});
