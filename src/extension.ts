import * as vscode from 'vscode';

import {
  analyzeProject,
  checkBackend,
  securityAPI,
  checkSandbox,
  collectWorkspaceFiles,
  isSupportedDocument,
  runSandbox,
  stopSandbox,
  discoverRuntimes,
  checkRuntime,
  RuntimeInfo,
} from './services';
import { SecurityWorkbenchController, SecurityProfile } from './security-workbench';

import {
  Finding,
  SandboxMode,
  SandboxReport,
} from './types';
import { createRuntimeReport } from './webview/runtime-report';
import { mergeProjectReport, ProjectReportSection, completeProjectReport, recordReportFailure, renderProjectReportMarkdown } from './project-report';
import { persistUnifiedReport } from './report-persistence';

import {
  getWebviewHtml,
} from './webview';

let scanDebounceTimer:
  | ReturnType<typeof setTimeout>
  | null = null;

const DEBOUNCE_MS = 1500;

let cachedResults: {
  findings: Finding[];
  filesScanned: number;
  fileNames: string[];
} | null = null;

let cachedSandboxReport:
  | SandboxReport
  | null = null;
let lastWorkbenchResult: Record<string, unknown> | undefined;
let lastWorkbenchKind: 'scan' | 'runtime' = 'scan';
let lastWorkbenchSection: ProjectReportSection = 'staticAnalysis';

async function persistProjectReport(section: ProjectReportSection, result: Record<string, unknown>): Promise<string | undefined> {
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) throw new Error('Open a workspace folder to save the SentinelAI project report.');
  const jsonUri = vscode.Uri.joinPath(folder.uri, 'sentinelai-report.json');
  const markdownUri = vscode.Uri.joinPath(folder.uri, 'sentinelai-report.md');
  await persistUnifiedReport({
    read: async path => await vscode.workspace.fs.readFile(vscode.Uri.joinPath(folder.uri, path)),
    write: async (path, data) => { await vscode.workspace.fs.writeFile(vscode.Uri.joinPath(folder.uri, path), data); },
    delete: async path => { await vscode.workspace.fs.delete(vscode.Uri.joinPath(folder.uri, path)); },
  }, 'sentinelai-report.json', 'sentinelai-report.md', section, result);
  return `${vscode.workspace.asRelativePath(jsonUri)} and ${vscode.workspace.asRelativePath(markdownUri)}`;
}

async function persistLegacyReport(section: ProjectReportSection, result: Record<string, unknown>): Promise<void> {
  try {
    const path = await persistProjectReport(section, result);
    vscode.window.setStatusBarMessage(`SentinelAI report updated: ${path}`, 5000);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    vscode.window.showWarningMessage(`SentinelAI report was not updated: ${message}`);
  }
}

async function persistResult(section: ProjectReportSection, result: Record<string, unknown>, panel?: vscode.WebviewPanel): Promise<void> {
  try {
    const path = await persistProjectReport(section, result);
    const message = { type: 'workbenchProjectReportUpdated', path, section, status: result.status, reason: result.reason, updatedAt: new Date().toISOString() };
    if (panel) panel.webview.postMessage(message);
    else vscode.window.setStatusBarMessage(`SentinelAI report updated: ${path}`, 5000);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (panel) panel.webview.postMessage({ type: 'workbenchProjectReportError', message });
    else vscode.window.showWarningMessage(`SentinelAI report was not updated: ${message}`);
  }
}

async function persistReportFailure(section: ProjectReportSection, reason: string, panel?: vscode.WebviewPanel): Promise<void> {
  try {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) return;
    const uri = vscode.Uri.joinPath(folder.uri, 'sentinelai-report.json');
    let existing: unknown = null;
    try { existing = JSON.parse(Buffer.from(await vscode.workspace.fs.readFile(uri)).toString('utf8')); }
    catch (error) { const code = (error as { code?: string }).code; if (code !== 'FileNotFound' && code !== 'EntryNotFound') return; }
    const report = completeProjectReport(mergeProjectReport(existing, section, { status: 'skipped', reason }));
    const base = JSON.parse(JSON.stringify(report)) as ReturnType<typeof completeProjectReport>;
    await persistReportSnapshot(recordReportFailure(base, section, reason));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (panel) panel.webview.postMessage({ type: 'workbenchProjectReportError', message });
  }
}

async function persistReportSnapshot(report: ReturnType<typeof completeProjectReport>): Promise<void> {
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) throw new Error('Open a workspace folder to save the SentinelAI project report.');
  const jsonUri = vscode.Uri.joinPath(folder.uri, 'sentinelai-report.json');
  const markdownUri = vscode.Uri.joinPath(folder.uri, 'sentinelai-report.md');
  const previousJson = await readOptionalFile(jsonUri);
  const previousMarkdown = await readOptionalFile(markdownUri);
  await vscode.workspace.fs.writeFile(jsonUri, Buffer.from(JSON.stringify(report, null, 2) + '\n', 'utf8'));
  try { await vscode.workspace.fs.writeFile(markdownUri, Buffer.from(renderProjectReportMarkdown(report), 'utf8')); }
  catch (error) {
    if (previousJson) await vscode.workspace.fs.writeFile(jsonUri, previousJson);
    else { try { await vscode.workspace.fs.delete(jsonUri); } catch { /* preserve the original markdown-write error */ } }
    if (previousMarkdown) await vscode.workspace.fs.writeFile(markdownUri, previousMarkdown);
    throw error;
  }
}

async function readOptionalFile(uri: vscode.Uri): Promise<Uint8Array | undefined> {
  try { return await vscode.workspace.fs.readFile(uri); }
  catch (error) {
    const code = (error as { code?: string }).code;
    if (code === 'FileNotFound' || code === 'EntryNotFound') return undefined;
    throw error;
  }
}

async function persistCompletedResult(section: ProjectReportSection, result: Record<string, unknown>, panel?: vscode.WebviewPanel): Promise<void> {
  return persistResult(section, result, panel);
}

async function persistRunningResult(section: ProjectReportSection, result: Record<string, unknown>, panel?: vscode.WebviewPanel): Promise<void> {
  await persistResult(section, { ...result, status: 'running' }, panel);
}

/*
 * Stores the runtime detected by the backend.
 *
 * IMPORTANT:
 * The framework is NOT hard-coded here.
 * The backend runtime detector determines whether
 * the project is Flask, Django, Express, Vite, etc.
 */
let selectedRuntime:
  | RuntimeInfo
  | undefined;

async function hostIntegrationHook(url: string, files: { path: string; content: string }[], profile: SecurityProfile = 'source') {
  const target = new URL(url);
  if (process.env.SENTINELAI_HOST_TEST !== '1' || target.protocol !== 'http:' || !['127.0.0.1', 'localhost'].includes(target.hostname)) throw new Error('Host integration is test-only and only accepts loopback HTTP.');
  if (!['source', 'dependencies', 'secrets', 'infrastructure', 'comprehensive'].includes(profile)) throw new Error('Host integration profile is not allowlisted.');
  const dependencyProfile = profile === 'dependencies' || profile === 'comprehensive';
  const submittedFiles = files.filter(file => {
    const name = file.path.replace(/\\/g, '/').split('/').pop()?.toLowerCase() || '';
    const source = /\.(?:js|mjs|cjs|ts|py|go|php|java|rb|cs|cpp|c|rs|html|css|jsx|tsx|vue|svelte|sql|sh)$/.test(name);
    const dependency = /^(?:package\.json|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|requirements[^/]*\.txt|pyproject\.toml|pipfile|pipfile\.lock|cargo\.toml|cargo\.lock|composer\.json|composer\.lock|gemfile|gemfile\.lock|go\.mod|go\.sum)$/.test(name);
    const infra = /^(?:dockerfile(?:[.-].*)?|docker-compose.*\.ya?ml|compose\.ya?ml)$/.test(name) || /\.(?:tf|tfvars|ya?ml)$/.test(name);
    return source || dependencyProfile && dependency || (profile === 'infrastructure' || profile === 'comprehensive') && infra;
  });
  if (!submittedFiles.length || !submittedFiles.some(file => /\.(?:js|mjs|cjs|ts|py|go|php|java|rb|cs|cpp|c|rs|html|css|jsx|tsx|vue|svelte|sql|sh)$/.test(file.path.toLowerCase()))) throw new Error('The selected project has no supported source file for the host scan.');
  const body: Record<string, unknown> = { kind: 'scan', profile, options: { allowAdvisoryNetwork: false }, files: submittedFiles };
  if (dependencyProfile) body.expectedLockfiles = submittedFiles.map(file => file.path.replace(/\\/g, '/')).filter(path => /(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml)$/i.test(path));
  const created = await securityAPI.create(body);
  let job = created;
  const deadline = Date.now() + 240_000;
  let staticCheckpointSaved = false;
  let lastResultKey = '';
  while (['queued', 'running'].includes(job.status) && Date.now() < deadline) {
    if (job.result && typeof job.result === 'object') {
      const checkpoint = job.result as Record<string, unknown>;
      const checkpointFindings = Array.isArray(checkpoint.findings) ? checkpoint.findings : [];
      const checkpointCoverage = Array.isArray(checkpoint.coverage) ? checkpoint.coverage : [];
      const checkpointLlMRunning = checkpoint.llmEnabled === true && checkpoint.llmReason === 'Local LLM analysis is running.';
      const checkpointKey = JSON.stringify([checkpointFindings.length, checkpointCoverage.length, checkpoint.llmReason, checkpoint.llmUsed]);
      if (checkpointKey !== lastResultKey) {
        lastResultKey = checkpointKey;
        const staticResult = checkpoint.staticFindings && typeof checkpoint.staticFindings === 'object'
          ? { findings: checkpoint.staticFindings, coverage: checkpoint.coverage, provenance: checkpoint.provenance, profile: checkpoint.profile }
          : checkpoint;
        await persistCompletedResult('staticAnalysis', staticResult);
        staticCheckpointSaved = true;
        if (checkpointLlMRunning) await persistRunningResult('llmAnalysis', { findings: [], coverage: [{ check: 'llm', status: 'running', reason: 'Local LLM analysis is running.' }], provenance: { mode: 'local-llm-analysis', synthetic: false }, model: process.env.MODEL || 'qwen2.5:3b' });
        else if (checkpoint.llmReason && checkpoint.llmReason !== 'Local LLM analysis has not completed.') {
          if (checkpoint.llmUsed === true) await persistCompletedResult('llmAnalysis', { findings: checkpoint.llmFindings || [], coverage: [{ check: 'llm', status: 'tested', reason: checkpoint.llmReason }], provenance: { mode: 'local-llm-analysis', synthetic: false } });
          else if (checkpoint.llmEnabled === true) await persistResult('llmAnalysis', { status: 'skipped', reason: checkpoint.llmReason });
        }
      }
    }
    await new Promise(resolve => setTimeout(resolve, 200));
    job = await securityAPI.get(job.id);
  }
  if (job.status !== 'completed' && job.result && typeof job.result === 'object' && !staticCheckpointSaved) {
    const checkpoint = job.result as Record<string, unknown>;
    const staticResult = checkpoint.staticFindings && typeof checkpoint.staticFindings === 'object'
      ? { findings: checkpoint.staticFindings, coverage: checkpoint.coverage, provenance: checkpoint.provenance, profile: checkpoint.profile }
      : checkpoint;
    await persistCompletedResult('staticAnalysis', staticResult);
  }
  if (job.status !== 'completed') throw new Error(`Workbench scan did not complete: ${job.status}`);
  const scanResult = job.result || {};
  const staticResult = scanResult.staticFindings && typeof scanResult.staticFindings === 'object'
    ? { findings: scanResult.staticFindings, coverage: scanResult.coverage, provenance: scanResult.provenance, profile: scanResult.profile }
    : scanResult;
  const llmUsed = scanResult.llmUsed === true || scanResult.llmEnabled === true || scanResult.modelUsed === true ||
    (Array.isArray(scanResult.findings) && Array.isArray(scanResult.staticFindings) &&
      scanResult.findings.some((finding: unknown) => finding && typeof finding === 'object' && (finding as Record<string, unknown>).source === 'ai'));
  await persistCompletedResult('staticAnalysis', staticResult);
  if (llmUsed) await persistCompletedResult('llmAnalysis', { findings: Array.isArray(scanResult.llmFindings) ? scanResult.llmFindings : [], coverage: [{ check: 'llm', status: 'tested', reason: scanResult.llmReason || 'LLM returned a result.' }], provenance: { mode: 'local-llm-analysis', synthetic: false } });
  else await persistResult('llmAnalysis', { status: 'skipped', reason: 'LLM analysis was not enabled or no LLM result was returned.' });
  const findings = Array.isArray(job.result?.findings) ? job.result.findings as Finding[] : [];
  const runtime = await runSandbox(findings, 'project-validation', target.toString());
  const runtimeResult = createRuntimeReport(runtime);
  await persistCompletedResult('projectValidation', runtimeResult);
  return { status: 'completed', scanJobId: job.id, scan: job.result, runtime: runtimeResult };
}

let fixDocCounter = 0;

const fixContentStore =
  new Map<string, string>();

const fixContentProvider:
  vscode.TextDocumentContentProvider = {
    provideTextDocumentContent(
      uri: vscode.Uri
    ): string {
      return (
        fixContentStore.get(
          uri.path
        ) || ''
      );
    },
  };

function createFixUri(
  label: string,
  content: string
): vscode.Uri {
  const key =
    `/fix-${++fixDocCounter}-${label.replace(
      /[^a-zA-Z0-9._-]/g,
      '_'
    )}`;

  fixContentStore.set(
    key,
    content
  );

  return vscode.Uri.parse(
    `sentinelai-fix:${key}`
  );
}

/*
 * Detect the actual project runtime.
 *
 * No framework is preferred or hard-coded here.
 * discoverRuntimes() performs the actual detection.
 */
async function resolveProjectRuntime(): Promise<RuntimeInfo> {
  const runtimes =
    await discoverRuntimes();

  if (!runtimes.length) {
    throw new Error(
      'No local HTTP application was detected. Start your project development server first.'
    );
  }

  /*
   * discoverRuntimes() is responsible for detection
   * and ranking. We simply use its first detected
   * runtime.
   */
  const runtime =
    runtimes[0];

  const checked =
    await checkRuntime(
      runtime.url
    );

  if (!checked.reachable) {
    throw new Error(
      `Detected runtime is not reachable: ${runtime.url}`
    );
  }

  selectedRuntime = {
    ...runtime,
    reachable: true,
    statusCode:
      checked.statusCode,
  };

  return selectedRuntime;
}

async function openProjectRuntime(): Promise<void> {
  const runtime =
    selectedRuntime ||
    await resolveProjectRuntime();

  await vscode.env.openExternal(
    vscode.Uri.parse(
      runtime.url
    )
  );
}

export async function activate(
  context: vscode.ExtensionContext
): Promise<{ runWorkbenchIntegration: typeof hostIntegrationHook } | void> {
  const hostTestEnabled = process.env.SENTINELAI_HOST_TEST === '1';
  let panel: vscode.WebviewPanel | null = null;
  let workbench: SecurityWorkbenchController | undefined;
  let workspaceProjectReady = false;

  const statusBar =
    vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Left,
      100
    );

  statusBar.text =
    '$(shield) SentinelAI';

  statusBar.tooltip =
    'Click to open security report';

  statusBar.command =
    'sentinelai.openPanel';

  statusBar.show();

  context.subscriptions.push(
    statusBar
  );

  context.subscriptions.push(
    vscode.workspace.registerTextDocumentContentProvider(
      'sentinelai-fix',
      fixContentProvider
    )
  );

  function getPanel(): vscode.WebviewPanel {
    if (!panel) {
      panel =
        vscode.window.createWebviewPanel(
          'sentinelai',
          'SentinelAI — Security Report',
          vscode.ViewColumn.Beside,
          {
            enableScripts: true,
            retainContextWhenHidden: true,
          }
        );

      panel.webview.html =
        getWebviewHtml();

      workbench = new SecurityWorkbenchController({
        api: securityAPI,
        collect: async profile => (await collectWorkspaceFiles({ securityProfile: profile }))
          .map(file => ({ path: file.path, content: file.code })),
        emit: message => panel?.webview.postMessage(message),
        onCompleted: async job => {
          const result = job.result || {};

          const staticResult = result.staticFindings && typeof result.staticFindings === 'object'
            ? { findings: result.staticFindings, coverage: result.coverage, provenance: result.provenance, profile: result.profile }
            : result;
          const llmUsed = result.llmUsed === true;
          lastWorkbenchSection = 'staticAnalysis';
          lastWorkbenchResult = result;
          await persistCompletedResult('staticAnalysis', staticResult, panel || undefined);
          if (llmUsed) await persistCompletedResult('llmAnalysis', { findings: Array.isArray(result.llmFindings) ? result.llmFindings : [],
            coverage: [{ check: 'llm', status: 'tested', reason: result.llmReason || 'Local LLM analysis ran.' }],
            provenance: { mode: 'local-llm-analysis', synthetic: false }, model: result.model }, panel || undefined);
          else await persistResult('llmAnalysis', { status: 'skipped', reason: 'LLM analysis was not enabled or no LLM result was returned.' }, panel || undefined);
        },
        onCheckpoint: async job => {
          const result = job.result || {};
          const staticResult = result.staticFindings && typeof result.staticFindings === 'object'
            ? { findings: result.staticFindings, coverage: result.coverage, provenance: result.provenance, profile: result.profile }
            : result;
          lastWorkbenchSection = 'staticAnalysis';
          lastWorkbenchResult = result;
          await persistCompletedResult('staticAnalysis', staticResult, panel || undefined);
          if (result.llmEnabled === true && result.llmReason === 'Local LLM analysis is running.') {
            await persistRunningResult('llmAnalysis', { findings: [], coverage: [{ check: 'llm', status: 'running', reason: 'Local LLM analysis is running.' }], provenance: { mode: 'local-llm-analysis', synthetic: false }, model: process.env.MODEL || 'qwen2.5:3b' }, panel || undefined);
          } else if (result.llmReason && result.llmReason !== 'Local LLM analysis has not completed.') {
            if (result.llmUsed === true) await persistCompletedResult('llmAnalysis', { findings: result.llmFindings || [], coverage: [{ check: 'llm', status: 'tested', reason: result.llmReason }], provenance: { mode: 'local-llm-analysis', synthetic: false } }, panel || undefined);
            else if (result.llmEnabled === true) await persistResult('llmAnalysis', { status: 'skipped', reason: result.llmReason }, panel || undefined);
          }
        },
        onError: async message => {
          if (message === 'No files') await persistReportFailure('staticAnalysis', 'No supported source files were found in the open workspace.', panel || undefined);
          else if (/Could not start job/.test(message)) await persistReportFailure('staticAnalysis', 'The scan could not start. Confirm the backend is available and the workspace contains supported source files.', panel || undefined);
        },
        schedule: (callback, delay) => setTimeout(() => { void callback(); }, delay),
        unschedule: timer => clearTimeout(timer as ReturnType<typeof setTimeout>),
      });
      context.subscriptions.push({ dispose: () => workbench?.dispose() });

      panel.onDidDispose(() => {
        workbench?.dispose();
        workbench = undefined;
        panel = null;
      });

      panel.webview.onDidReceiveMessage(
        async message => {
          if (!panel) {
            return;
          }

          /*
           * Webview is ready.
           */
          if (
            message.type ===
            'ready'
          ) {
            if (cachedResults) {
              panel.webview.postMessage({
                type: 'results',
                ...cachedResults,
              });
            }

            if (
              cachedSandboxReport
            ) {
              panel.webview.postMessage({
                type:
                  'sandboxResults',
                report:
                  cachedSandboxReport,
              });
            }

            /*
             * If a runtime was already detected,
             * restore it when the Webview reloads.
             */
            if (
              selectedRuntime
            ) {
              panel.webview.postMessage({
                type:
                  'runtimeSelected',
                targetUrl:
                  selectedRuntime.url,
                runtime:
                  selectedRuntime.runtime,
                port:
                  selectedRuntime.port,
                statusCode:
                  selectedRuntime.statusCode,
                reachable:
                  selectedRuntime.reachable,
              });
            }
          }

          if (message.type === 'workbenchReady') {
            let workspace = { open: false, projectFiles: 0, selectedProjectFile: false, selectedFile: '', ready: false, reason: 'Open a VS Code project folder.' };
            const folder = vscode.workspace.workspaceFolders?.[0];
            if (folder) {
              try {
                const files = await collectWorkspaceFiles({ securityProfile: 'source' });
                const count = files.length;
                workspaceProjectReady = count > 0;
                workspace = { open: true, projectFiles: count, selectedProjectFile: workspaceProjectReady, selectedFile: '',
                  ready: workspaceProjectReady,
                  reason: workspaceProjectReady ? '' : 'This workspace contains no supported project source files. Open a source-code project before scanning.' };
              } catch {
                workspace = { open: true, projectFiles: 0, selectedProjectFile: false, selectedFile: '', ready: false, reason: 'Could not inspect project files. Check workspace permissions.' };
              }
            }
            await workbench?.loadCapabilities(workspace);
            panel?.webview.postMessage({ type: 'workbenchWorkspaceState', workspace });
          }
          if (message.type === 'workbenchStart' && !workspaceProjectReady) {
            panel.webview.postMessage({ type: 'workbenchError', message: 'Open a project folder containing supported source files before scanning.' });
            return;
          }
          if (message.type === 'workbenchProjectFileSelected') {
            const files = await collectWorkspaceFiles({ securityProfile: 'source' }).catch(() => []);
            workspaceProjectReady = files.length > 0;
            panel.webview.postMessage({ type: 'workbenchWorkspaceState', workspace: {
              open: !!vscode.workspace.workspaceFolders?.length, projectFiles: files.length,
              selectedProjectFile: workspaceProjectReady, selectedFile: '', ready: workspaceProjectReady,
              reason: workspaceProjectReady ? '' : 'This workspace contains no supported project source files. Open a source-code project before scanning.',
            } });
          }
          if (message.type === 'workbenchStart') {
            await workbench?.start({
              kind: message.kind,
              profile: message.profile as SecurityProfile | undefined,
              allowAdvisoryNetwork: message.allowAdvisoryNetwork === true,
            });
          }

          if (message.type === 'workbenchRuntimeRequest') {
            await workbench?.startRuntimeValidation();
          }
          if (message.type === 'workbenchHostTest') {
            if (process.env.SENTINELAI_HOST_TEST !== '1') return;
            try {
              const endpoint = new URL(String(message.url || ''));
              if (endpoint.protocol !== 'http:' || !['127.0.0.1', 'localhost'].includes(endpoint.hostname)) {
                throw new Error('Extension-host test target must be loopback HTTP.');
              }
              const scan = await securityAPI.create({ kind: 'scan', profile: 'source', options: { allowAdvisoryNetwork: false }, files: [{ path: 'src/host-fixture.js', content: 'const safe = true;' }] });
              let job = scan;
              const deadline = Date.now() + 60000;
              while (['queued', 'running'].includes(job.status) && Date.now() < deadline) {
                await new Promise(resolve => setTimeout(resolve, 250));
                job = await securityAPI.get(job.id);
              }
              if (job.status !== 'completed') throw new Error('Workbench integration scan did not complete.');
              const report = await runSandbox(Array.isArray(job.result?.findings) ? job.result.findings as Finding[] : [], 'project-validation', endpoint.toString());
              panel?.webview.postMessage({ type: 'workbenchHostTestResult', status: 'completed', scan: job.result, runtime: createRuntimeReport(report) });
            } catch (error) {
              panel?.webview.postMessage({ type: 'workbenchHostTestResult', status: 'failed', error: error instanceof Error ? error.message : String(error) });
            }
          }
          if (message.type === 'workbenchRuntime') {
            try {
              const scanResult = message.scanResult;
              const scanFindings = Array.isArray(scanResult?.findings)
                ? scanResult.findings
                : cachedResults?.findings;
              if (!scanFindings) throw new Error('Complete a workspace scan before runtime validation.');
              const runtime = await resolveProjectRuntime();
              const report = await runSandbox(scanFindings, 'project-validation', runtime.url);
              lastWorkbenchResult = createRuntimeReport(report);
              lastWorkbenchKind = 'runtime';
              lastWorkbenchSection = 'projectValidation';
              await persistCompletedResult('projectValidation', lastWorkbenchResult, panel || undefined);
              panel?.webview.postMessage({ type: 'workbenchRuntime', status: 'completed', report: lastWorkbenchResult });
            } catch (error) {
              const message = error instanceof Error ? error.message : String(error);
              await persistReportFailure('projectValidation', message, panel || undefined);
              panel?.webview.postMessage({ type: 'workbenchRuntimeError', message });
            }
          }

          if (message.type === 'workbenchCancel') {
            await workbench?.cancel();
          }
          if (message.type === 'workbenchCaptureResult' && message.result && typeof message.result === 'object') {
            lastWorkbenchResult = message.result as Record<string, unknown>;
            lastWorkbenchKind = message.kind === 'runtime' ? 'runtime' : 'scan';
            lastWorkbenchSection = lastWorkbenchKind === 'runtime' ? 'projectValidation' : 'staticAnalysis';
          }

          /*
           * Scan workspace.
           */
          if (
            message.type ===
            'requestScan'
          ) {
            await scanWorkspace(
              panel,
              statusBar
            );
          }

          /*
           * Open vulnerable/fixed diff.
           */
          if (
            message.type ===
            'openDiff'
          ) {
            const finding:
              Finding =
                message.finding;

            if (
              finding &&
              finding.fixedCode
            ) {
              try {
                const fileName =
                  finding.file ||
                  'file';

                const leftUri =
                  createFixUri(
                    `vulnerable-${fileName}`,
                    finding.vulnerableCode ||
                      '// Original code not available'
                  );

                const rightUri =
                  createFixUri(
                    `fixed-${fileName}`,
                    finding.fixedCode
                  );

                await vscode.commands.executeCommand(
                  'vscode.diff',
                  leftUri,
                  rightUri,
                  `🛡️ ${finding.type} — ${fileName} (Vulnerable ↔ Fixed)`
                );
              } catch (error) {
                const errorMessage =
                  error instanceof Error
                    ? error.message
                    : String(error);

                vscode.window.showErrorMessage(
                  `SentinelAI: Could not open diff view — ${errorMessage}`
                );
              }
            } else {
              vscode.window.showWarningMessage(
                'SentinelAI: No fixed code available for this finding.'
              );
            }
          }

          /*
           * Apply single fix.
           */
          if (
            message.type ===
            'applyFix'
          ) {
            const finding:
              Finding =
                message.finding;

            if (
              finding &&
              finding.vulnerableCode &&
              finding.fixedCode &&
              finding.file
            ) {
              const workspaceFiles =
                await vscode.workspace.findFiles(
                  `**/${finding.file}`,
                  '**/node_modules/**',
                  1
                );

              if (
                workspaceFiles.length >
                0
              ) {
                const doc =
                  await vscode.workspace.openTextDocument(
                    workspaceFiles[0]
                  );

                const text =
                  doc.getText();

                const vulnerable =
                  finding.vulnerableCode.trim();

                const index =
                  text.indexOf(
                    vulnerable
                  );

                if (
                  index !== -1
                ) {
                  const edit =
                    new vscode.WorkspaceEdit();

                  const start =
                    doc.positionAt(
                      index
                    );

                  const end =
                    doc.positionAt(
                      index +
                        vulnerable.length
                    );

                  edit.replace(
                    workspaceFiles[0],
                    new vscode.Range(
                      start,
                      end
                    ),
                    finding.fixedCode
                  );

                  await vscode.workspace.applyEdit(
                    edit
                  );

                  await doc.save();

                  vscode.window.showInformationMessage(
                    `🛡️ SentinelAI: Fix applied to ${finding.file}`
                  );

                  panel.webview.postMessage({
                    type:
                      'fixApplied',
                    findingId:
                      finding.id,
                  });
                } else {
                  vscode.window.showWarningMessage(
                    `🛡️ SentinelAI: Could not locate vulnerable code in ${finding.file}.`
                  );

                  panel.webview.postMessage({
                    type:
                      'fixFailed',
                    findingId:
                      finding.id,
                    message:
                      'Vulnerable code pattern not found in file.',
                  });
                }
              }
            }
          }

          /*
           * Apply all fixes.
           */
          if (
            message.type ===
            'applyAllFixes'
          ) {
            const findings:
              Finding[] =
                message.findings ||
                [];

            const fixable =
              findings.filter(
                finding =>
                  finding.vulnerableCode &&
                  finding.fixedCode &&
                  finding.file &&
                  !finding.applied
              );

            if (
              fixable.length ===
              0
            ) {
              vscode.window.showInformationMessage(
                'SentinelAI: No applicable fixes found.'
              );

              return;
            }

            let applied = 0;
            let failed = 0;

            for (
              const finding of fixable
            ) {
              try {
                const files =
                  await vscode.workspace.findFiles(
                    `**/${finding.file}`,
                    '**/node_modules/**',
                    1
                  );

                if (
                  files.length ===
                  0
                ) {
                  failed++;
                  continue;
                }

                const doc =
                  await vscode.workspace.openTextDocument(
                    files[0]
                  );

                const text =
                  doc.getText();

                const vulnerable =
                  finding.vulnerableCode!
                    .trim();

                const index =
                  text.indexOf(
                    vulnerable
                  );

                if (
                  index === -1
                ) {
                  failed++;
                  continue;
                }

                const edit =
                  new vscode.WorkspaceEdit();

                edit.replace(
                  files[0],
                  new vscode.Range(
                    doc.positionAt(
                      index
                    ),
                    doc.positionAt(
                      index +
                        vulnerable.length
                    )
                  ),
                  finding.fixedCode!
                );

                await vscode.workspace.applyEdit(
                  edit
                );

                await doc.save();

                applied++;

                panel.webview.postMessage({
                  type:
                    'fixApplied',
                  findingId:
                    finding.id,
                });
              } catch {
                failed++;
              }
            }

            vscode.window.showInformationMessage(
              `🛡️ SentinelAI: Applied ${applied} fix(es)` +
                (
                  failed > 0
                    ? `, ${failed} could not be applied`
                    : ''
                )
            );
          }

          /*
           * Run sandbox validation.
           */
            if (
              message.type ===
              'runSandbox'
            ) {
              const sandboxMode:
                SandboxMode =
                  message.mode ===
                  'project-validation'
                    ? 'project-validation'
                    : 'simulation';
              const findings:
                Finding[] =
                  Array.isArray(
                    message.findings
                  )
                    ? message.findings
                    : [];
              await runSandboxAttack(
                panel,
                statusBar,
                findings,
                sandboxMode
              );
            }

          /* * Stop sandbox */

          if (
            message.type ===
            'stopSandbox'
          ) {
            try {
              await stopSandbox();
            } catch {
              // Preserve silent stop behavior.
            }
          }

          /*
           * Detect project runtime.
           *
           * The backend determines the framework.
           * Nothing is hard-coded here.
           */
          if (
            message.type ===
            'detectRuntime'
          ) {
            try {
              const runtime =
                await resolveProjectRuntime();

              panel.webview.postMessage({
                type:
                  'runtimeSelected',
                targetUrl:
                  runtime.url,
                runtime:
                  runtime.runtime,
                port:
                  runtime.port,
                statusCode:
                  runtime.statusCode,
                reachable:
                  runtime.reachable,
              });

              vscode.window.showInformationMessage(
                `SentinelAI runtime detected: ${runtime.runtime} on port ${runtime.port}`
              );
            } catch (error) {
              vscode.window.showErrorMessage(
                error instanceof Error
                  ? error.message
                  : String(error)
              );
            }
          }

          /*
           * Open detected runtime.
           */
          if (
            message.type ===
            'openRuntime'
          ) {
            try {
              await openProjectRuntime();
            } catch (error) {
              vscode.window.showErrorMessage(
                error instanceof Error
                  ? error.message
                  : String(error)
              );
            }
          }
        }
      );
    } else {
      panel.reveal(
        vscode.ViewColumn.Beside
      );

      if (cachedResults) {
        panel.webview.postMessage({
          type: 'results',
          ...cachedResults,
        });
      }

      if (cachedSandboxReport) {
        panel.webview.postMessage({
          type:
            'sandboxResults',
          report:
            cachedSandboxReport,
        });
      }

      /*
       * Restore detected runtime.
       */
      if (selectedRuntime) {
        panel.webview.postMessage({
          type:
            'runtimeSelected',
          targetUrl:
            selectedRuntime.url,
          runtime:
            selectedRuntime.runtime,
          port:
            selectedRuntime.port,
          statusCode:
            selectedRuntime.statusCode,
          reachable:
            selectedRuntime.reachable,
        });
      }
    }

    return panel;
  }

  /*
   * Open SentinelAI panel.
   */
  context.subscriptions.push(
    vscode.commands.registerCommand(
      'sentinelai.openPanel',
      () => {
        getPanel();
      }
    )
  );

  if (hostTestEnabled) {
    return { runWorkbenchIntegration: hostIntegrationHook };
  }

  context.subscriptions.push(vscode.workspace.onDidChangeWorkspaceFolders(async () => {
    if (!panel) return;
    const files = vscode.workspace.workspaceFolders?.length ? await collectWorkspaceFiles({ securityProfile: 'source' }).catch(() => []) : [];
    workspaceProjectReady = files.length > 0;
    panel.webview.postMessage({ type: 'workbenchWorkspaceState', workspace: {
      open: !!vscode.workspace.workspaceFolders?.length,
      projectFiles: files.length,
      selectedProjectFile: workspaceProjectReady,
      selectedFile: '',
      ready: workspaceProjectReady,
      reason: workspaceProjectReady ? '' : 'This workspace contains no supported project source files. Open a source-code project before scanning.',
    } });
  }));

  /*
   * Scan command.
   */
  context.subscriptions.push(
    vscode.commands.registerCommand(
      'sentinelai.scan',
      async () => {
        await scanWorkspace(
          getPanel(),
          statusBar
        );
      }
    )
  );

  /*
   * Sandbox command.
   */
  context.subscriptions.push(
    vscode.commands.registerCommand(
      'sentinelai.sandbox',
      () => {
        getPanel().webview.postMessage({
          type:
            'showConsent',
        });
      }
    )
  );

  /*
   * Runtime detection command.
   */
  context.subscriptions.push(
    vscode.commands.registerCommand(
      'sentinelai.detectRuntime',
      async () => {
        try {
          const runtime =
            await resolveProjectRuntime();

          vscode.window.showInformationMessage(
            `SentinelAI runtime detected: ${runtime.runtime} on port ${runtime.port}`
          );
        } catch (error) {
          vscode.window.showErrorMessage(
            error instanceof Error
              ? error.message
              : String(error)
          );
        }
      }
    )
  );

  /*
   * Open runtime command.
   */
  context.subscriptions.push(
    vscode.commands.registerCommand(
      'sentinelai.openRuntime',
      async () => {
        try {
          await openProjectRuntime();
        } catch (error) {
          vscode.window.showErrorMessage(
            error instanceof Error
              ? error.message
              : String(error)
          );
        }
      }
    )
  );

  /*
   * Auto-rescan on save.
   */
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(
      document => {
        if (
          !isSupportedDocument(
            document
          )
        ) {
          return;
        }

        if (scanDebounceTimer) {
          clearTimeout(
            scanDebounceTimer
          );
        }

        scanDebounceTimer =
          setTimeout(
            async () => {
              scanDebounceTimer =
                null;

              await scanWorkspace(
                getPanel(),
                statusBar
              );
            },
            DEBOUNCE_MS
          );
      }
    )
  );

}

async function scanWorkspace(
  panel: vscode.WebviewPanel,
  statusBar: vscode.StatusBarItem
): Promise<void> {
  if (!vscode.workspace.workspaceFolders?.length) {
    const message = 'Open a VS Code project folder before scanning.';
    statusBar.text = '$(shield) SentinelAI';
    panel.webview.postMessage({ type: 'error', message });
    vscode.window.showWarningMessage(message);
    return;
  }
  statusBar.text =
    '$(sync~spin) SentinelAI: Scanning...';

  panel.webview.postMessage({
    type: 'scanning',
  });

  try {
    await checkBackend();
  } catch {
    statusBar.text =
      '$(shield) SentinelAI';

    panel.webview.postMessage({
      type: 'error',
      message:
        'Backend not running. Start the SentinelAI backend first.',
    });

    return;
  }

  panel.webview.postMessage({
    type: 'scanStage',
    stage: 1,
    message:
      'Collecting workspace files & running static analysis...',
  });

  let files;

  try {
    files =
      await collectWorkspaceFiles();
  } catch (error) {
    statusBar.text =
      '$(shield) SentinelAI';

    panel.webview.postMessage({
      type: 'error',
      message:
        `Could not read workspace files: ${
          error instanceof Error
            ? error.message
            : String(error)
        }`,
    });

    return;
  }

  if (
    files.length ===
    0
  ) {
    statusBar.text =
      '$(shield) SentinelAI';

    panel.webview.postMessage({
      type: 'noFiles',
    });

    return;
  }

  if (files.length === 0) {
    statusBar.text = '$(shield) SentinelAI';
    panel.webview.postMessage({ type: 'noFiles' });
    return;
  }

  panel.webview.postMessage({
    type: 'scanStage',
    stage: 2,
    message:
      'Running AI security analysis & vulnerability modeling...',
  });

  try {
    const response =
      await analyzeProject(
        files
      );

    const {
      findings,
      filesScanned,
    } = response;

    const fileNames =
      files.map(
        file => file.path
      );

    const legacyScannerCoverage = response.scannerCoverage || { status: 'unknown', reason: 'Static scanner coverage was not reported.' };
    if (legacyScannerCoverage.status !== 'complete') {
      const details = Object.entries(legacyScannerCoverage.tools || {}).map(([name, tool]) => name + ': ' + (tool.status || 'unknown') + (tool.exitCode !== undefined ? ' (exit ' + tool.exitCode + ')' : ''));
      findings.push({ id: 'scanner-coverage-incomplete', type: 'Static scanner coverage incomplete', severity: 'Medium', file: 'workspace', line: '',
        explanation: [legacyScannerCoverage.reason || 'One or more scanners failed or did not report completion.', ...details].join(' · '), attackStory: [],
        fix: 'Resolve the failed scanner and rerun before interpreting an empty result.' });
    }
    cachedResults = {
      findings,
      filesScanned,
      fileNames,
    };
    lastWorkbenchResult = { kind: 'scan', provenance: { mode: 'legacy-workspace-analysis', synthetic: false }, findings, filesScanned,
      coverage: [{ check: 'source', status: legacyScannerCoverage.status === 'complete' ? 'tested' : 'inconclusive', filesTested: legacyScannerCoverage.filesScanned ?? filesScanned,
        tools: legacyScannerCoverage.tools || null,
        reason: legacyScannerCoverage.reason || (legacyScannerCoverage.status === 'complete' ? 'Configured static scanners completed.' : 'Static scanner did not report complete per-tool coverage.') }] };
    lastWorkbenchKind = 'scan';
    lastWorkbenchSection = 'staticAnalysis';
    await persistLegacyReport('staticAnalysis', lastWorkbenchResult);

    panel.webview.postMessage({
      type: 'scanStage',
      stage: 3,
      message:
        'Generating exploit commands & remediation report...',
    });

    const staticCoverage = Array.isArray(lastWorkbenchResult.coverage)
      ? lastWorkbenchResult.coverage.find(item => item.check === 'source')
      : undefined;
    const scannerTools = staticCoverage?.tools && typeof staticCoverage.tools === 'object'
      ? Object.entries(staticCoverage.tools as Record<string, { status?: string }>) : [];
    const scannerComplete = scannerTools.length > 0 && scannerTools.every(([, tool]) => tool.status === 'complete');
    statusBar.text = findings.length > 0
      ? `$(warning) SentinelAI: ${findings.length} candidate finding${findings.length === 1 ? '' : 's'}`
      : scannerComplete
        ? '$(check) SentinelAI: No findings in completed scanners'
        : '$(warning) SentinelAI: Scan incomplete — review coverage';
    panel.webview.postMessage({ type: 'scannerCoverage', coverage: staticCoverage });

    panel.webview.postMessage({
      type: 'results',
      findings,
      filesScanned,
      fileNames,
      coverage: lastWorkbenchResult.coverage,
    });
  } catch (error) {
    statusBar.text =
      '$(shield) SentinelAI';

    panel.webview.postMessage({
      type: 'error',
      message:
        `Analysis failed: ${
          error instanceof Error
            ? error.message
            : String(error)
        }`,
    });
  }
}

async function runSandboxAttack(
  panel: vscode.WebviewPanel,
  statusBar: vscode.StatusBarItem,
  findings: Finding[],
  mode: SandboxMode = 'simulation'
): Promise<void> {
  if (!vscode.workspace.workspaceFolders?.length) {
    panel.webview.postMessage({ type: 'sandboxError', message: 'Open the project folder in this VS Code window before starting runtime checks.' });
    return;
  }
  try {
    await checkSandbox();
  } catch (error: any) {
    panel.webview.postMessage({
      type:
        'sandboxError',
      message:
        error.response?.data?.error ||
        'Docker is unavailable. Ensure Docker is running.',
    });

    return;
  }



  statusBar.text =
    '$(debug-alt) SentinelAI: Validation running...';

  panel.webview.postMessage({
    type:
      'sandboxStarted',
  });

  try {
    let targetUrl:
      | string
      | undefined;

    /*
     * Project validation uses the ACTUAL
     * detected local project runtime.
     */
    if (
      mode ===
      'project-validation'
    ) {
      const runtime =
        selectedRuntime ||
        await resolveProjectRuntime();

      targetUrl =
        runtime.url;

      panel.webview.postMessage({
        type:
          'runtimeSelected',
        targetUrl:
          runtime.url,
        runtime:
          runtime.runtime,
        port:
          runtime.port,
        statusCode:
          runtime.statusCode,
        reachable:
          runtime.reachable,
      });
    }

    const report =
      await runSandbox(
        findings,
        mode,
        targetUrl
      );

    cachedSandboxReport =
      report;

    if (mode === 'simulation') {
      lastWorkbenchResult = report as unknown as Record<string, unknown>;
      lastWorkbenchKind = 'runtime';
      lastWorkbenchSection = 'safeSimulation';
      await persistCompletedResult('safeSimulation', lastWorkbenchResult, panel);
    } else {
      lastWorkbenchResult = createRuntimeReport(report);
      lastWorkbenchKind = 'runtime';
      lastWorkbenchSection = 'projectValidation';
      await persistCompletedResult('projectValidation', lastWorkbenchResult, panel);
    }

    statusBar.text =
      `$(warning) SentinelAI: ${findings.length} issues`;

    panel.webview.postMessage({
      type:
        'sandboxResults',
      report,
    });
  } catch (error: any) {
    statusBar.text =
      `$(warning) SentinelAI: ${findings.length} issues`;

    panel.webview.postMessage({
      type:
        'sandboxError',
      message:
        `Runtime validation failed: ${
          error.message
        }`,
    });
  }
}

export function deactivate(): void {}