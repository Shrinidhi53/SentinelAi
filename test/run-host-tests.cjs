const path = require('node:path');
const fs = require('node:fs');
const { runTests } = require('@vscode/test-electron');
const { spawn } = require('node:child_process');

const hostSuite = path.join(__dirname, 'host-suite');
const hostSuiteMain = path.join(hostSuite, 'index.cjs');
const hostSuiteEntry = path.join(hostSuite, 'index.js');
const hostWorkspace = path.join(__dirname, 'host-workspace');
const backendRoot = path.resolve(__dirname, '../../backend');
const projectTarget = process.env.SENTINELAI_HOST_TARGET_URL;
const projectRoot = process.env.SENTINELAI_HOST_PROJECT_ROOT;
const backend = spawn(process.execPath, ['server.js'], { cwd: backendRoot, env: { ...process.env, LLM_ENABLED: process.env.SENTINELAI_HOST_LLM === '1' ? 'true' : 'false' }, stdio: 'inherit' });
backend.on('error', error => { console.error('Could not start test backend:', error.message); process.exitCode = 1; });
async function waitForBackend() {
  for (let i = 0; i < 60; i++) {
    try { const response = await fetch('http://127.0.0.1:3000/health'); if (response.ok) return; } catch {}
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  throw new Error('Backend did not become ready at loopback port 3000.');
}
async function main() {
  fs.mkdirSync(hostWorkspace, { recursive: true });
  fs.copyFileSync(hostSuiteMain, hostSuiteEntry);
  await waitForBackend();
  await runTests({
    extensionDevelopmentPath: path.resolve(__dirname, '..'),
    extensionTestsPath: hostSuiteEntry,
    launchArgs: ['--disable-extensions', '--disable-workspace-trust', hostWorkspace],
    ...(process.env.SENTINELAI_VSCODE_EXECUTABLE
      ? { vscodeExecutablePath: process.env.SENTINELAI_VSCODE_EXECUTABLE }
      : { version: 'stable' }),
    extensionTestsEnv: { ...process.env, SENTINELAI_HOST_TEST: '1', SENTINELAI_HOST_PROJECT_ROOT: projectRoot || path.join(hostWorkspace, 'accepted-project'), ...(projectTarget ? { SENTINELAI_HOST_TARGET_URL: projectTarget } : {}) },
  });
}
main().catch(error => { console.error('VS Code extension-host tests failed:', error.message); process.exitCode = 1; })
  .finally(() => { backend.kill('SIGTERM'); fs.rmSync(hostSuiteEntry, { force: true }); });
