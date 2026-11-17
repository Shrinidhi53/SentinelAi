import {
  mergeProjectReport,
  completeProjectReport,
  renderProjectReportMarkdown,
  ProjectReportSection,
  ProjectReport,
} from './project-report';

export interface ReportFileAdapter {
  read(path: string): PromiseLike<Uint8Array>;
  write(path: string, data: Uint8Array): PromiseLike<void>;
  delete(path: string): PromiseLike<void>;
}

function notFound(error: unknown): boolean {
  const code = (error as { code?: string })?.code;
  return code === 'FileNotFound' || code === 'EntryNotFound' || code === 'ENOENT';
}

export async function persistUnifiedReport(
  files: ReportFileAdapter,
  jsonPath: string,
  markdownPath: string,
  section: ProjectReportSection,
  result: Record<string, unknown>,
  updatedAt = new Date().toISOString(),
): Promise<ProjectReport> {
  result = sanitizeReportData(result);
  let previousJson: Uint8Array | undefined;
  let existing: unknown = null;
  try {
    previousJson = await files.read(jsonPath);
    try { existing = JSON.parse(Buffer.from(previousJson).toString('utf8')); }
    catch { throw new Error('Could not parse the existing SentinelAI JSON report; neither report was changed.'); }
  } catch (error) {
    if (!notFound(error)) throw error;
  }
  let previousMarkdown: Uint8Array | undefined;
  try {
    previousMarkdown = await files.read(markdownPath);
    if (!Buffer.from(previousMarkdown).toString('utf8').startsWith('# SentinelAI Security Report\n')) {
      throw new Error('The existing Markdown report is not a SentinelAI report; neither report was changed.');
    }
  } catch (error) { if (!notFound(error)) throw error; }

  const report = completeProjectReport(mergeProjectReport(existing, section, result, updatedAt), updatedAt);
  const json = Buffer.from(JSON.stringify(report, null, 2) + '\n', 'utf8');
  const markdown = Buffer.from(renderProjectReportMarkdown(report), 'utf8');
  let jsonWritten = false;
  try {
    await files.write(jsonPath, json);
    jsonWritten = true;
    await files.write(markdownPath, markdown);
  } catch (error) {
    if (jsonWritten) {
      if (previousJson) await files.write(jsonPath, previousJson);
      else { try { await files.delete(jsonPath); } catch { /* retain original write failure */ } }
    }
    if (previousMarkdown) await files.write(markdownPath, previousMarkdown);
    else { try { await files.delete(markdownPath); } catch { /* retain original write failure */ } }
    throw error;
  }
  return report;
}

const SENSITIVE_REPORT_KEY = /(?:authorization|cookie|token|secret|password|passwd|api[-_]?key|credential|session|private[-_]?key)/i;

function sanitizeReportData<T>(value: T, key = ''): T {
  if (Array.isArray(value)) return value.map(item => sanitizeReportData(item)) as T;
  if (!value || typeof value !== 'object') {
    if (typeof value === 'string' && SENSITIVE_REPORT_KEY.test(key)) return '[REDACTED]' as T;
    return value;
  }
  const output: Record<string, unknown> = {};
  for (const [name, item] of Object.entries(value as Record<string, unknown>)) {
    if (['body', 'bodyPreview', 'evidenceSnippet', 'payload', 'content'].includes(name)) {
      if (['body', 'bodyPreview', 'evidenceSnippet', 'content'].includes(name)) output[`${name}Length`] = typeof item === 'string' ? item.length : 0;
      output[name] = typeof item === 'string' ? `[REDACTED ${item.length} chars]` : item;
      continue;
    }
    if ((name === 'headers' || name === 'requestHeaders') && item && typeof item === 'object') {
      output[name] = Object.fromEntries(Object.entries(item as Record<string, unknown>).map(([header, headerValue]) => [header, SENSITIVE_REPORT_KEY.test(header) ? '[REDACTED]' : headerValue]));
      continue;
    }
    if (SENSITIVE_REPORT_KEY.test(name) && typeof item === 'string') {
      output[name] = '[REDACTED]';
      continue;
    }
    output[name] = sanitizeReportData(item, name);
  }
  return output as T;
}
