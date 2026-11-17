export function getWebviewScriptWorkbench(): string {
  return `/* Security Workbench */
(() => {
  const profileSelect = document.getElementById('workbench-profile');
  const projectState = document.getElementById('workbench-project-state');

  const status = document.getElementById('workbench-status');
  const runtimeStatus = document.getElementById('workbench-runtime-status');
  const runtimeOutput = document.getElementById('workbench-runtime-output');
  const output = document.getElementById('workbench-output');
  const start = document.getElementById('workbench-start');
  const cancel = document.getElementById('workbench-cancel');
  const saveStatus = document.getElementById('workbench-save-status');
  const runtimeButton = document.getElementById('workbench-runtime');
  const runtimeConsent = document.getElementById('workbench-runtime-consent');
  let projectReady = false;
  let lastResult = null;
  const reportStatus = document.getElementById('workbench-save-status');
  function send(type, detail) { vscode.postMessage({ type, ...detail }); }
  function option(select, value, label, disabled) {
    const item = document.createElement('option');
    item.value = value; item.textContent = label; item.disabled = !!disabled; select.appendChild(item);
  }

  start.addEventListener('click', () => {
    if (!projectReady) { status.textContent = projectState.textContent || 'Open a project workspace with supported files before scanning.'; return; }
    start.disabled = true;
    status.textContent = 'Preparing workspace scan…';
    send('workbenchStart', { kind: 'scan', jobKey: 'scan', profile: profileSelect.value,
      allowAdvisoryNetwork: document.getElementById('workbench-network').checked });
  });

  runtimeConsent.addEventListener('change', () => { runtimeButton.disabled = !runtimeConsent.checked || !projectReady; });
  runtimeButton.addEventListener('click', () => {
    if (!runtimeConsent.checked || !projectReady) return;
    send('workbenchRuntime', {});
  });
  cancel.addEventListener('click', () => send('workbenchCancel', {}));

  window.addEventListener('message', event => {
    const message = event.data;
    if (message.type === 'workbenchWorkspaceState') {
      projectReady = message.workspace?.ready === true;
      projectState.textContent = projectReady
        ? message.workspace.projectFiles + ' source file(s) ready.'
        : (message.workspace?.reason || 'Select a supported project source file in the editor.');
      start.disabled = !projectReady;
      runtimeButton.disabled = !projectReady || !runtimeConsent.checked;
    }
    if (message.type === 'workbenchCapabilities') {
      profileSelect.replaceChildren();
      for (const item of message.capabilities.profiles || []) option(profileSelect, item.id, item.name || item.label || item.id, item.supported === false);

      projectReady = message.workspace?.ready === true;
      projectState.textContent = projectReady
        ? message.workspace.projectFiles + ' source file(s) ready.'
        : (message.workspace?.reason || 'Open a VS Code project folder with supported source files before scanning.');

      start.disabled = !projectReady;
      runtimeButton.disabled = !projectReady || !runtimeConsent.checked;
      status.textContent = 'Local backend connected. Files are collected only after you start a scan.';
      const source = (message.capabilities.profiles || []).find(item => item.id === profileSelect.value);
      const unsupported = (source?.checks || []).filter(check => check.available === false).map(check => check.id + ': unsupported');
      const staticCheck = (source?.checks || []).find(check => check.id === 'source');
      document.getElementById('workbench-limitations').textContent = staticCheck?.explanation || unsupported.join(' · ') || '';
    } else if (message.type === 'workbenchPreparing') {
      status.textContent = message.message; start.disabled = true;

    } else if (message.type === 'workbenchJob') {
      const job = message.job;
      status.textContent = 'Workspace scan: ' + job.status;
      cancel.disabled = !['queued', 'running'].includes(job.status);
      start.disabled = job.kind !== 'scan' || ['queued', 'running'].includes(job.status);
      const destination = output;
      destination.replaceChildren();
      if (job.error) { const error = document.createElement('p'); error.className='workbench-error'; error.textContent = job.error; destination.appendChild(error); }
      if (job.result) {
        lastResult = job.result;
        renderResult(job.result, 'scan');
      }
      if (['failed','cancelled','completed'].includes(job.status)) { start.disabled = false; cancel.disabled = true; }


    } else if (message.type === 'workbenchRuntime') {
      runtimeStatus.textContent = 'Local Project Validation ' + (message.status || 'completed') + '. Review executed, skipped and not-applicable probes below.';
      if (message.report) {
        lastResult = message.report;
        renderResult(message.report, 'runtime');
      }
    } else if (message.type === 'workbenchRuntimeRequest') {
      send('workbenchRuntime', { scanResult: message.scanResult, profile: message.profile });
    } else if (message.type === 'workbenchRuntimeError') {
      runtimeStatus.textContent = 'Project Validation could not run: ' + message.message;
    } else if (message.type === 'workbenchProjectReportUpdated') {
      reportStatus.textContent = (message.status === 'skipped' ? 'Workflow skipped in report: ' : 'Unified project report updated: ') + message.path + (message.reason ? ' · ' + message.reason : '');
    } else if (message.type === 'workbenchProjectReportError') {
      reportStatus.textContent = 'Report was not updated: ' + message.message;
    } else if (message.type === 'workbenchError') {
      status.textContent = message.message; start.disabled = !!message.active;

    }
  });

  function renderResult(result, kind = 'scan') {
    const destination = kind === 'runtime' ? runtimeOutput : output;
    destination.replaceChildren();
    const banner = document.createElement('div'); banner.className = 'workbench-banner';
    const provenance = result.provenance || { mode: result.mode || 'unknown', synthetic: result.projectVulnerabilityConfirmed === false };
    banner.textContent = kind === 'runtime' ? 'LOCAL PROJECT RUNTIME VALIDATION · Provenance: ' + (provenance.mode || 'unknown')
      : 'WORKSPACE SCAN RESULTS · Provenance: ' + (provenance.mode || 'unknown');
    destination.appendChild(banner);
    const summary = result.summary || {};
    const reportCoverage = Array.isArray(result.coverage)
      ? result.coverage
      : result.coverage && typeof result.coverage === 'object'
        ? [{ check: 'source', ...result.coverage, tools: result.coverage.tools }]
        : [{ check: 'source', status: 'unknown', reason: 'Scanner coverage is not available.' }];
    const coverageAvailable = reportCoverage.length > 0 && reportCoverage.some(item => item.status !== 'unknown');
    const coverage = [
      ...reportCoverage.map(item => ({
        check: item.check || item.id || 'source',
        status: item.status || 'unknown',
        filesTested: item.filesScanned ?? item.filesSubmitted,
        reason: item.reason || item.status || 'No detail supplied.',
        planned: item.planned, executed: item.executed, skipped: item.skipped,
        notApplicable: item.notApplicable, failed: item.failed, unknown: item.unknown,
        tools: item.tools,
      })),
      ...(Array.isArray(result.unsupportedChecks) ? result.unsupportedChecks.map(item => ({ check: item.check || item.id, status: 'unsupported', reason: item.reason, tools: item.tools })) : []),
    ];
    const coverageSection = document.createElement('section'); coverageSection.className='workbench-section';
    const coverageTitle=document.createElement('h3'); coverageTitle.textContent='Coverage'; coverageSection.appendChild(coverageTitle);
    const coverageTable = document.createElement('table'); coverageTable.className='report-table';
    const coverageHead = document.createElement('thead'); const coverageHeadRow=document.createElement('tr');
    for (const label of ['Check','Status','Scope / count','Details']) { const th=document.createElement('th'); th.textContent=label; coverageHeadRow.appendChild(th); }
    coverageHead.appendChild(coverageHeadRow); coverageTable.appendChild(coverageHead);
    const coverageBody=document.createElement('tbody');
    for (const item of coverage) {
      const row=document.createElement('tr');
      const checkCell=document.createElement('td'); checkCell.textContent=item.check || 'check'; row.appendChild(checkCell);
      const statusCell=document.createElement('td'); const badge=document.createElement('span'); badge.className='report-status-badge'; badge.textContent=item.status || 'unknown'; statusCell.appendChild(badge); row.appendChild(statusCell);
      const countCell=document.createElement('td');
      const probeCounts = item.planned !== undefined ? ['planned '+(item.planned ?? 0),'executed '+(item.executed ?? 0),'skipped '+(item.skipped ?? 0),'N/A '+(item.notApplicable ?? 0),'failed '+(item.failed ?? 0),'unknown '+(item.unknown ?? 0)].join(' · ') : (item.filesTested !== undefined ? item.filesTested+' files' : '—');
      countCell.textContent=probeCounts; row.appendChild(countCell);
      const detailCell=document.createElement('td'); detailCell.textContent=item.reason || item.status || 'No detail supplied.'; row.appendChild(detailCell);
      coverageBody.appendChild(row);
      if (item.tools && typeof item.tools === 'object') for (const [name, tool] of Object.entries(item.tools)) {
        const toolRow=document.createElement('tr');
        for (const value of [name, (tool.status||'unknown')+(tool.exitCode!==undefined?' · exit '+tool.exitCode:''), '—', tool.diagnostics || (tool.status === 'failed' ? 'Scanner failed; coverage incomplete.' : 'No diagnostics')]) { const cell=document.createElement('td'); cell.textContent=value; toolRow.appendChild(cell); }
        coverageBody.appendChild(toolRow);
      }
    }
    coverageTable.appendChild(coverageBody); const coverageWrap=document.createElement('div'); coverageWrap.className='report-table-wrap'; coverageWrap.appendChild(coverageTable); coverageSection.appendChild(coverageWrap);
    if (!coverageAvailable || coverage.some(item => !['tested','complete','completed'].includes(item.status))) {
      const scope=document.createElement('p'); scope.className='workbench-error';
      scope.textContent=coverageAvailable
        ? 'Coverage is incomplete or includes checks that were not run. No claim is made about those areas.'
        : 'Coverage unavailable: the backend did not report which checks ran. Treat this result as incomplete.';
      coverageSection.appendChild(scope);
    }
    destination.appendChild(coverageSection);
    if (summary.findings !== undefined || summary.confirmed !== undefined || result.findings || result.validations) {
      const metrics=document.createElement('section'); metrics.className='workbench-section';
      const title=document.createElement('h3'); title.textContent=kind === 'runtime' ? 'Runtime validation summary' : 'Workspace scan summary'; metrics.appendChild(title);
      const grid=document.createElement('div'); grid.className='workbench-grid';
      const values=kind === 'runtime'
        ? [['Executed', summary.runtimeTests ?? result.coverage?.find(item => item.check === 'executed probes')?.count ?? 0], ['Confirmed', summary.confirmed ?? 0], ['Exposures', summary.observedExposures ?? 0], ['Skipped', summary.skippedProbes ?? result.coverage?.find(item => item.check === 'skipped probes')?.count ?? 0]]
        : [['Findings', summary.findings ?? (result.findings || []).length], ['Files scanned', result.filesScanned ?? result.coverage?.[0]?.filesScanned ?? 0]];
      for (const [label,value] of values) { const card=document.createElement('article'); card.className='workbench-metric'; const strong=document.createElement('strong'); strong.textContent=String(value); const small=document.createElement('span'); small.textContent=label; card.append(strong,small); grid.appendChild(card); }
      metrics.appendChild(grid); destination.appendChild(metrics);
    }
    const findings = result.findings || result.staticFindings || [];
    if (findings.length) {
      const section=document.createElement('section'); section.className='workbench-section'; const title=document.createElement('h3'); title.textContent='Findings'; section.appendChild(title);
      for (const finding of findings) { const row=document.createElement('article'); row.className='workbench-finding';
        const heading=document.createElement('strong'); heading.textContent=(finding.severity || 'Unrated') + ' · ' + (finding.type || finding.rule || 'Security finding'); row.appendChild(heading);
        const location=document.createElement('p'); location.textContent=(finding.file || 'workspace') + (finding.line ? ':' + finding.line : ''); row.appendChild(location);
        const explanation=document.createElement('p'); explanation.textContent=finding.explanation || finding.message || ''; row.appendChild(explanation);
        if (finding.fix) { const fix=document.createElement('p'); fix.textContent='Suggested fix: ' + finding.fix; row.appendChild(fix); }
        section.appendChild(row);
      }
      destination.appendChild(section);
    } else {
      const section=document.createElement('section'); section.className='workbench-section';
      const title=document.createElement('h3'); title.textContent='Findings'; section.appendChild(title);
      const note=document.createElement('p'); note.textContent='No findings among the checks actually run. This does not imply untested areas are safe and is not a security certification.'; section.appendChild(note);
      destination.appendChild(section);
    }
    const attacks=result.attacks || [];
    const exposures=(result.exposures || []).concat(...attacks.map(attack => attack.sensitiveData || []));
    if (exposures.length) {
      const section=document.createElement('section'); section.className='workbench-section'; const title=document.createElement('h3'); title.textContent='Observed data exposure (masked)'; section.appendChild(title);
      for (const exposure of exposures) { const row=document.createElement('article'); row.className='workbench-exposure';
        const heading=document.createElement('strong'); heading.textContent=exposure.dataType || 'Sensitive data'; row.appendChild(heading);
        const details=document.createElement('p'); details.textContent=[exposure.fieldPath || exposure.location || 'response', exposure.maskedValue || '[REDACTED]', exposure.valueLength ? String(exposure.valueLength) + ' chars' : ''].filter(Boolean).join(' · '); row.appendChild(details); section.appendChild(row);
      }
      destination.appendChild(section);
    }
    const validations=result.validations || [];
    if (validations.length) {
      const section=document.createElement('section'); section.className='workbench-section'; const title=document.createElement('h3'); title.textContent='Runtime verdicts'; section.appendChild(title);
      for (const validation of validations) { const row=document.createElement('article'); row.className='workbench-finding';
        const heading=document.createElement('strong'); heading.textContent=(validation.result || 'inconclusive').replace(/_/g,' ').toUpperCase() + ' · ' + (validation.attackName || validation.attackType || 'Probe'); row.appendChild(heading);
        const reason=document.createElement('p'); reason.textContent=validation.rationale || ''; row.appendChild(reason);
        const evidence=validation.evidence || []; for (const item of evidence) { const detail=document.createElement('p'); detail.textContent=(item.type || 'evidence') + ': ' + (item.contentLength ? '[body omitted · '+item.contentLength+' chars]' : item.content || ''); row.appendChild(detail); }
        section.appendChild(row);
      }
      destination.appendChild(section);
    }
    const saved = document.createElement('p'); saved.className='workbench-help';
    saved.textContent = 'This result is added to the sentinelai-report.json workspace report when the workflow completes.';
    destination.appendChild(saved);
  }

  send('workbenchReady', {});
})();`;
}
