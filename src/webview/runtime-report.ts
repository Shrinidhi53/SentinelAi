import { SandboxReport, AttackResult, ValidationResult } from '../types';

/** Adapt legacy project-validation records to explicit Workbench coverage. */
export function createRuntimeReport(report: SandboxReport): Record<string, unknown> {
  const raw = report as SandboxReport & { coverage?: Record<string, number>; findings?: unknown[]; provenance?: Record<string, unknown> };
  const attacks = Array.isArray(report.attacks) ? report.attacks : [];
  const validations = Array.isArray(report.validations) ? report.validations : [];
  const state = (attack: AttackResult): 'executed' | 'skipped' | 'failed' | 'unknown' => {
    const item = attack as AttackResult & { execution?: string; executed?: boolean };
    if (item.execution === 'failed' || item.status === 'failed') return 'failed';
    if (item.execution === 'skipped' || item.executed === false) return 'skipped';
    if (item.execution === 'executed' || Number.isInteger(item.response?.statusCode)) return 'executed';
    return 'unknown';
  };
  const counts = { total: attacks.length, planned: attacks.length, executed: 0, skipped: 0, failed: 0, unknown: 0, notApplicable: 0, scope: 'recorded-probes' };
  const byAttackType = new Map<string, { attackType: string; planned: number; executed: number; skipped: number; failed: number; unknown: number; notApplicable: number }>();
  for (const attack of attacks) {
    const execution = state(attack);
    counts[execution]++;
    const attackType = String(attack.attackType || 'unknown');
    const row = byAttackType.get(attackType) || { attackType, planned: 0, executed: 0, skipped: 0, failed: 0, unknown: 0, notApplicable: 0 };
    row.planned++;
    row[execution]++;
    byAttackType.set(attackType, row);
  }
  const verdict = (item: ValidationResult) => String(item.result);
  counts.notApplicable = validations.filter(item => verdict(item) === 'not_applicable').length;
  for (const item of validations as (ValidationResult & { attackId?: string; findingId?: string; attackType?: string; notApplicable?: boolean })[]) {
    const attack = attacks.find(candidate => candidate.id === item.attackId || candidate.findingId === item.findingId);
    const type = String(item.attackType || attack?.attackType || 'unknown');
    const row = byAttackType.get(type) || { attackType: type, planned: 1, executed: 0, skipped: 0, failed: 0, unknown: 1, notApplicable: 0 };
    if (!byAttackType.has(type)) byAttackType.set(type, row);
    if (verdict(item) === 'not_applicable' || item.notApplicable === true) {
      row.notApplicable++;
      if (!attack) { row.unknown = Math.max(0, row.unknown - 1); row.skipped++; }
    }
  }
  const coverage = [
    { check: 'planned probes', status: 'planned', count: counts.planned, reason: 'Probe plans in this report; this is not the number executed.' },
    { check: 'executed probes', status: counts.executed ? 'tested' : 'skipped', count: counts.executed, reason: 'Requests with a recorded HTTP response.' },
    { check: 'skipped probes', status: counts.skipped ? 'skipped' : 'tested', count: counts.skipped, reason: 'No request was executed for these probes.' },
    { check: 'not applicable', status: counts.notApplicable ? 'not_applicable' : 'tested', count: counts.notApplicable, reason: 'Probe could not apply to discovered routes or supplied context.' },
    { check: 'failed probes', status: counts.failed ? 'failed' : 'tested', count: counts.failed, reason: 'Probe execution failed.' },
    { check: 'unknown execution', status: counts.unknown ? 'inconclusive' : 'tested', count: counts.unknown, reason: 'Execution state could not be established.' },
    ...[...byAttackType.values()].map(values => ({ check: `attack type: ${values.attackType}`, status: values.executed ? 'tested' : values.skipped ? 'skipped' : values.failed ? 'failed' : 'inconclusive', count: values.executed, planned: values.planned, executed: values.executed, skipped: values.skipped, failed: values.failed, unknown: values.unknown, notApplicable: values.notApplicable, reason: 'Counts are per recorded probe; unlisted application routes/behaviors were not assessed.' })),
  ];
  const summary = report.summary || {};
  const safeAttacks = attacks.map(attack => sanitizeRuntimeEvidence(attack));
  const safeValidations = validations.map(item => sanitizeRuntimeEvidence(item));
  return {
    mode: 'project-validation',
    provenance: { ...(raw.provenance || {}), mode: 'project-validation', synthetic: false, target: report.target?.url || null },
    coverage,
    summary: {
      findings: summary.findings ?? raw.findings?.length ?? 0,
      confirmed: summary.confirmed ?? 0,
      observedExposures: validations.filter(item => verdict(item) === 'observed_exposure').length,
      inconclusive: validations.filter(item => verdict(item) === 'inconclusive').length,
      notReproduced: validations.filter(item => verdict(item) === 'not_reproduced').length,
      notApplicable: validations.filter(item => verdict(item) === 'not_applicable').length,
      runtimeTests: counts.executed,
      runtimeFailed: counts.failed,
      plannedProbes: counts.planned,
      skippedProbes: counts.skipped,
      unknownProbes: counts.unknown,
    },
    findings: sanitizeRuntimeEvidence(raw.findings || []), attacks: safeAttacks, validations: safeValidations, events: sanitizeRuntimeEvidence(report.events || []), target: sanitizeRuntimeEvidence(report.target),
  };
}

const SENSITIVE_KEY = /(?:authorization|cookie|token|secret|password|passwd|api[-_]?key|credential|session|private[-_]?key)/i;

function sanitizeRuntimeEvidence<T>(value: T, key = ''): T {
  if (Array.isArray(value)) return value.map(item => sanitizeRuntimeEvidence(item)) as T;
  if (!value || typeof value !== 'object') {
    if (typeof value === 'string' && SENSITIVE_KEY.test(key)) return '[REDACTED]' as T;
    return value;
  }
  const record = value as Record<string, unknown>;
  const safe: Record<string, unknown> = {};
  for (const [name, item] of Object.entries(record)) {
    if (name === 'headers' && Array.isArray(item)) {
      safe[name] = item.map(header => typeof header === 'string' && SENSITIVE_KEY.test(header) ? `${header}: [REDACTED]` : header);
      continue;
    }
    if (['body', 'bodyPreview', 'evidenceSnippet', 'payload', 'content'].includes(name)) {
      if (name === 'body' || name === 'bodyPreview' || name === 'content' || name === 'evidenceSnippet') safe[`${name}Length`] = typeof item === 'string' ? item.length : 0;
      safe[name] = typeof item === 'string' ? `[REDACTED ${item.length} chars]` : item;
      continue;
    }
    if ((name === 'headers' || name === 'requestHeaders') && item && typeof item === 'object') {
      const headers = item as Record<string, unknown>;
      safe[name] = Object.fromEntries(Object.entries(headers).map(([header, headerValue]) => [header, SENSITIVE_KEY.test(header) ? '[REDACTED]' : headerValue]));
      continue;
    }
    if (SENSITIVE_KEY.test(name) && typeof item === 'string') {
      safe[name] = '[REDACTED]';
      continue;
    }
    safe[name] = sanitizeRuntimeEvidence(item, name);
  }
  return safe as T;
}
