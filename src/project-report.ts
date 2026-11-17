export type ProjectReportSection = 'staticAnalysis' | 'llmAnalysis' | 'safeSimulation' | 'projectValidation';

export interface ProjectReportRun {
  status: 'completed' | 'skipped' | 'running';
  updatedAt: string;
  reason?: string;
  result?: Record<string, unknown>;
}

type ReportSectionRun = Omit<ProjectReportRun, 'status'> & { status: 'completed' | 'skipped' | 'running' };

export interface ProjectReport {
  format: 'sentinelai-project-report';
  schemaVersion: 2;
  createdAt: string;
  updatedAt: string;
  sections: Record<ProjectReportSection, ProjectReportRun>;
}

const SECTION_NAMES: ProjectReportSection[] = ['staticAnalysis', 'llmAnalysis', 'safeSimulation', 'projectValidation'];

function emptySections(updatedAt: string): Record<ProjectReportSection, ProjectReportRun> {
  return Object.fromEntries(SECTION_NAMES.map(section => [section, {
    status: 'skipped', updatedAt, reason: section === 'llmAnalysis'
      ? 'LLM analysis was disabled or produced no separate result.'
      : section === 'staticAnalysis' ? 'Static analysis has not been run yet.' : 'This workflow has not been run yet.',
  }])) as Record<ProjectReportSection, ProjectReportRun>;
}

function fromLegacy(existing: Record<string, unknown>, updatedAt: string): ProjectReport {
  const report: ProjectReport = {
    format: 'sentinelai-project-report', schemaVersion: 2,
    createdAt: typeof existing.createdAt === 'string' ? existing.createdAt : updatedAt,
    updatedAt: typeof existing.updatedAt === 'string' ? existing.updatedAt : updatedAt,
    sections: emptySections(updatedAt),
  };
  const runs = existing.runs && typeof existing.runs === 'object' ? existing.runs as Record<string, unknown> : {};
  const copy = (target: ProjectReportSection, source: string) => {
    const legacy = runs[source] as { updatedAt?: string; result?: Record<string, unknown> } | undefined;
    if (!legacy?.result || typeof legacy.result !== 'object') return;
    report.sections[target] = { status: 'completed', updatedAt: legacy.updatedAt || updatedAt, result: legacy.result };
  };
  copy('staticAnalysis', 'workspaceScan');
  copy('safeSimulation', 'safeSimulation');
  copy('projectValidation', 'projectValidation');
  const scan = report.sections.staticAnalysis.result;
  if (scan) {
    const llm = scan.llm && typeof scan.llm === 'object' ? scan.llm as Record<string, unknown> : {};
    const hasLlM = scan.llmUsed === true || llm.used === true || scan.modelUsed === true;
    if (hasLlM) report.sections.llmAnalysis = { status: 'completed', updatedAt: report.sections.staticAnalysis.updatedAt, result: scan };
  }
  return report;
}

export function renderProjectReportMarkdown(report: ProjectReport): string {
  const cell = (value: unknown): string => String(value ?? '—').replace(/\r?\n/g, ' ').replace(/\|/g, '\\|').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const table = (headers: string[], rows: unknown[][]): string[] => [
    `| ${headers.map(cell).join(' | ')} |`,
    `| ${headers.map(() => '---').join(' | ')} |`,
    ...rows.map(row => `| ${headers.map((_, index) => cell(row[index])).join(' | ')} |`),
    '',
  ];
  const records = (value: unknown): Record<string, any>[] => Array.isArray(value) ? value.filter(item => item && typeof item === 'object') as Record<string, any>[] : [];
  const countVerdict = (items: Record<string, any>[], verdicts: string[]) => items.filter(item => verdicts.includes(String(item.result || item.verdict || item.runtimeVerdict || ''))).length;
  const compactReason = (value: unknown, limit = 200) => {
    const text = String(value || 'No rationale was recorded.').replace(/\s+/g, ' ').trim();
    return text.length > limit ? `${text.slice(0, limit - 1)}…` : text;
  };
  const lines = [
    '# SentinelAI Security Report', '',
    `- Schema: ${report.schemaVersion}`,
    `- Created: ${report.createdAt}`,
    `- Updated: ${report.updatedAt}`,
    '',
    '> Findings are best-effort indicators, not a security certification. A section marked skipped was not assessed.', '',
  ];
  const titles: Record<ProjectReportSection, string> = {
    staticAnalysis: 'Static analysis', llmAnalysis: 'LLM analysis',
    safeSimulation: 'Safe Simulation', projectValidation: 'Project Validation',
  };
  for (const section of SECTION_NAMES) {
    const run = report.sections[section];
    lines.push(`## ${titles[section]}`, '', `Status: **${run.status.toUpperCase()}**${run.updatedAt ? ` · ${run.updatedAt}` : ''}`, '');
    const result = run.result || {};
    if (run.reason) lines.push(run.status === 'skipped' && run.reason !== 'This workflow has not been run yet.' ? `Not completed: ${run.reason}` : run.reason, '');
    if ((run as ReportSectionRun).status === 'running') {
      lines.push('Analysis is in progress. This checkpoint may contain partial results.', '');
    }
    if ((run as ReportSectionRun).status === 'skipped') {
      const findings = Array.isArray(result.findings) ? result.findings : [];
      if (findings.length) lines.push('### Findings', '', ...findings.map((item: unknown) => `- ${String((item as Record<string, unknown>)?.type || (item as Record<string, unknown>)?.title || 'Finding')}`), '');
      else lines.push('### Findings', '', 'No findings: this workflow was skipped, so no checks ran.', '');
      continue;
    }
    const lastAttempt = result.lastAttempt && typeof result.lastAttempt === 'object' ? result.lastAttempt as Record<string, unknown> : undefined;
    if (lastAttempt?.status === 'failed') lines.push(`Latest attempt failed: ${String(lastAttempt.reason || 'No details provided.')}`, '');
    const provenance = result.provenance && typeof result.provenance === 'object' ? result.provenance as Record<string, unknown> : {};
    lines.push(`Provenance: ${String(provenance.mode || result.mode || 'not reported')}`, '');
    const coverage = Array.isArray(result.coverage) ? result.coverage as Record<string, unknown>[] : [];
    if (coverage.length) {
      const perType = coverage.filter((check: Record<string, unknown>) => String(check.check || '').startsWith('attack type:'));
      const summaryChecks = coverage.filter((check: Record<string, unknown>) => !String(check.check || '').startsWith('attack type:'));
      lines.push('### Coverage', '');
      if (summaryChecks.length) lines.push(...table(['Measure', 'Count', 'Interpretation'], summaryChecks.map(check => [check.check, check.count ?? check.executed ?? '—', check.reason || check.status || '—'])));
      if (perType.length) lines.push('#### Probe coverage by type', '', ...table(['Probe type', 'Planned', 'Executed', 'Skipped', 'N/A', 'Failed', 'Unknown'], perType.map(check => [String(check.check).replace(/^attack type:\s*/, ''), check.planned ?? 0, check.executed ?? check.count ?? 0, check.skipped ?? 0, check.notApplicable ?? 0, check.failed ?? 0, check.unknown ?? 0])));
    }
    if (section === 'safeSimulation' || section === 'projectValidation') {
      const attacks = records(result.attacks);
      const validations = records(result.validations);
      const summary = result.summary && typeof result.summary === 'object' ? result.summary as Record<string, unknown> : {};
      const title = section === 'safeSimulation' ? 'Simulation summary' : 'Validation summary';
      lines.push(`### ${title}`, '');
      const findings = records(result.findings);
      const exposures = records(result.exposures);
      const leakItems = [...exposures, ...attacks.flatMap(attack => records(attack.sensitiveData))];
      const uniqueLeaks = [...new Map(leakItems.map(item => [`${item.dataType || item.category}|${item.fieldPath || item.location}`, item])).values()];
      const confirmed = countVerdict(validations, ['confirmed']);
      const coverageRows = records(result.coverage);
      const findCoverage = (label: string): number | undefined => {
        const row = coverageRows.find(item => String(item.check || '').toLowerCase() === label);
        return typeof row?.count === 'number' ? row.count : undefined;
      };
      const planned = Number(summary.plannedProbes ?? findCoverage('planned probes') ?? attacks.length);
      const executed = Number(summary.runtimeTests ?? findCoverage('executed probes') ?? attacks.filter(a => a.executed === true || a.execution === 'executed' || Number.isInteger(a.response?.statusCode)).length);
      const skipped = Number(summary.skippedProbes ?? findCoverage('skipped probes') ?? attacks.filter(a => a.execution === 'skipped' || a.executed === false).length);
      const notApplicable = Number(summary.notApplicable ?? findCoverage('not applicable') ?? countVerdict(validations, ['not_applicable']));
      const failed = Number(summary.runtimeFailed ?? findCoverage('failed probes') ?? attacks.filter(a => a.execution === 'failed' || a.status === 'failed').length);
      const unknown = Number(summary.unknownProbes ?? findCoverage('unknown execution') ?? attacks.filter(a => a.execution === 'unknown').length);
      lines.push(...table(['Signal', 'Value', 'Meaning'], [
        ['Findings recorded', findings.length || summary.findings || 0, section === 'safeSimulation' ? 'Synthetic fixture observations are separate; they are not project findings.' : 'Findings passed to this validation run.'],
        [section === 'safeSimulation' ? 'Synthetic signals reproduced' : 'Runtime vulnerabilities confirmed', section === 'safeSimulation' ? summary.syntheticConfirmed ?? confirmed : summary.confirmed ?? confirmed, section === 'safeSimulation' ? 'Controlled fixture detections; not project findings.' : 'Confirmed only when runtime evidence met the verdict criteria.'],
        ['Observed exposure locations', uniqueLeaks.length || summary.observedExposures || 0, uniqueLeaks.length ? 'Categories and masked indicators shown below; raw response bodies are not included.' : 'No exposure records were included in this result.'],
        ['Planned / executed / skipped', `${planned} / ${executed} / ${skipped}`, 'Execution is distinct from verdict. Skipped and inapplicable probes are not negative results.'],
        ['Inconclusive / not reproduced', `${summary.inconclusive ?? countVerdict(validations, ['inconclusive'])} / ${summary.notReproduced ?? countVerdict(validations, ['not_reproduced'])}`, 'A non-reproduced check does not establish absence.'],
        ['Not applicable / failed / unknown', `${notApplicable} / ${failed} / ${unknown}`, 'These states reduce effective coverage and are not successes.'],
      ]));
      if (attacks.length) {
        const groups = new Map<string, { planned: number; executed: number; skipped: number; notApplicable: number; failed: number; unknown: number; confirmed: number; observed: number; inconclusive: number; rationale: string }>();
          for (const attack of attacks) {
            const key = String(attack.attackName || attack.attackType || attack.tool || 'unknown');
          const group = groups.get(key) || { planned: 0, executed: 0, skipped: 0, notApplicable: 0, failed: 0, unknown: 0, confirmed: 0, observed: 0, inconclusive: 0, rationale: '' };
            group.planned++;
          const validation = validations.find(item => item.attackId === attack.id) || {};
          const verdict = String(validation.result || validation.verdict || attack.runtimeVerdict || 'inconclusive');
          const state = String(attack.execution || (verdict === 'not_applicable' ? 'not_applicable' : attack.executed === false ? 'skipped' : attack.status === 'failed' ? 'failed' : (attack.status === 'success' || Number.isInteger(attack.response?.statusCode) || attack.evidence?.length) ? 'executed' : 'unknown'));
          if (state === 'executed' || state === 'success') group.executed++;
          else if (state === 'skipped') group.skipped++;
          else if (state === 'not_applicable') group.notApplicable++;
            else if (state === 'failed') group.failed++;
            else group.unknown++;
          if (verdict === 'confirmed') group.confirmed++;
            if (verdict === 'observed_exposure') group.observed++;
            if (verdict === 'inconclusive' || verdict === 'not_applicable') group.inconclusive++;
            if (!group.rationale) group.rationale = compactReason(validation.rationale || attack.rationale || attack.status);
            groups.set(key, group);
          }
        const coverageByType = coverage.filter(row => String(row.check || '').startsWith('attack type:'));
        for (const row of coverageByType) {
          const name = String(row.check).replace(/^attack type:\s*/, '');
          if (!groups.has(name)) groups.set(name, { planned: Number(row.planned || 0), executed: Number(row.executed || row.count || 0), skipped: Number(row.skipped || 0), notApplicable: Number(row.notApplicable || 0), failed: Number(row.failed || 0), unknown: Number(row.unknown || 0), confirmed: 0, observed: 0, inconclusive: 0, rationale: compactReason(row.reason || row.status) });
        }
        lines.push('#### Results by probe type', '', ...table(['Probe / fixture', 'Planned', 'Executed', 'Skipped', 'Not applicable', 'Failed', 'Unknown', 'Confirmed', 'Exposure', 'Notes'], [...groups.entries()].map(([name, g]) => [name, g.planned, g.executed, g.skipped, g.notApplicable, g.failed, g.unknown, section === 'safeSimulation' ? '—' : g.confirmed, g.observed, g.rationale])));
      }
      if (uniqueLeaks.length) {
        lines.push('#### Observed data exposure (masked)', '', ...table(['Category', 'Data type', 'Location', 'Masked sample', 'Occurrences'], uniqueLeaks.map(item => [item.category || 'sensitive data', item.dataType || 'unspecified', item.fieldPath || item.location || 'response', item.maskedValue || '[value withheld]', leakItems.filter(other => other.dataType === item.dataType && (other.fieldPath || other.location) === (item.fieldPath || item.location)).length])));
      }
      if (section === 'safeSimulation') lines.push('**Interpretation:** fixtures deliberately contain synthetic vulnerable behavior and test SentinelAI’s detection pipeline. They do not test or establish vulnerabilities in this workspace.', '');
      else lines.push('**Interpretation:** validation is limited to the explicitly executed probes and discovered routes. “Not reproduced” is not proof of safety; skipped, inapplicable, failed, and unknown checks are not negative results.', '');
    }
    const findings = Array.isArray(result.findings) ? result.findings as Record<string, unknown>[] : [];
    lines.push('### Findings', '');
    if (!findings.length) lines.push(run.status === 'skipped' ? 'No findings: this workflow was skipped, so no checks ran.' : 'No findings among the checks actually run. Untested areas remain unknown.', '');
    else {
      lines.push(...table(['Severity', 'Finding', 'Location', 'Evidence / explanation'], findings.map(finding => [finding.severity || 'UNKNOWN', finding.type || finding.title || 'Finding', finding.file ? `${finding.file}${finding.line ? `:${finding.line}` : ''}` : finding.endpoint || finding.attackType || '—', compactReason(finding.explanation || finding.message || finding.rationale)])));
    }
    lines.push('');

  }
  return `${lines.join('\n').trimEnd()}\n`;
}

export function completeProjectReport(report: ProjectReport, updatedAt = new Date().toISOString()): ProjectReport {
  for (const section of SECTION_NAMES) {
    const current = report.sections[section];
    if (current && (current.status === 'completed' || current.status === 'running' || current.reason !== 'This workflow has not been run yet.')) continue;
    report.sections[section] = { status: 'skipped', updatedAt,
      reason: section === 'llmAnalysis' ? 'LLM analysis was disabled or produced no separate result.' : section === 'staticAnalysis' ? 'Static analysis has not been run yet.' : 'This workflow has not been run yet.' };
  }
  return report;
}

export function recordReportFailure(report: ProjectReport, section: ProjectReportSection, reason: string, updatedAt = new Date().toISOString()): ProjectReport {
  if (report.sections[section].status === 'completed') {
    const previous = report.sections[section];
    report.sections[section] = { status: 'completed', updatedAt,
      result: { ...(previous.result || {}), lastAttempt: { status: 'failed', reason, updatedAt } } };
    report.updatedAt = updatedAt;
    return report;
  }
  report.sections[section] = { status: 'skipped', updatedAt, reason: `Not completed: ${reason}`, result: { status: 'skipped', reason } };
  if (section === 'projectValidation') {
    report.sections[section] = { status: 'skipped', updatedAt, reason: `Not completed: ${reason}`, result: { status: 'skipped', reason } };
  }
  report.updatedAt = updatedAt;
  return report;
}

export function mergeProjectReport(existing: unknown, section: ProjectReportSection, result: Record<string, unknown>, updatedAt = new Date().toISOString()): ProjectReport {
  let report: ProjectReport;
  if (existing === null || existing === undefined) {
    report = { format: 'sentinelai-project-report', schemaVersion: 2, createdAt: updatedAt, updatedAt, sections: emptySections(updatedAt) };
  } else {
    const candidate = existing as Record<string, unknown>;
    if (typeof candidate !== 'object' || candidate.format !== 'sentinelai-project-report' || ![1, 2].includes(candidate.schemaVersion as number)) {
      throw new Error('The existing sentinelai-report.json is not a supported SentinelAI report; it was left unchanged.');
    }
    if (candidate.schemaVersion === 1) report = fromLegacy(candidate, updatedAt);
    else {
      const sections = candidate.sections as Record<string, ProjectReportRun> | undefined;
      if (!sections || !SECTION_NAMES.every(name => sections[name] && ['completed', 'skipped', 'running'].includes(sections[name].status))) {
        throw new Error('The existing SentinelAI report has invalid workflow sections; it was left unchanged.');
      }
      report = candidate as unknown as ProjectReport;
    }
  }
  const skipped = result.status === 'skipped';
  const running = result.status === 'running';
  report.sections[section] = running
    ? { status: 'running', updatedAt, reason: typeof result.reason === 'string' ? result.reason : 'Analysis is in progress.', result }
    : skipped
    ? { status: 'skipped', updatedAt, reason: typeof result.reason === 'string' ? result.reason : 'This workflow was not run.', result }
    : { status: 'completed', updatedAt, result };
  report.updatedAt = updatedAt;
  return report;
}
