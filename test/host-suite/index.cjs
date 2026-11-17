const assert = require('node:assert/strict');
const http = require('node:http');
const vscode = require('vscode');


exports.run = async () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const target = http.createServer((_req, res) => { res.writeHead(200, { 'Content-Type': 'text/plain' }); res.end('temporary synthetic host fixture'); });
  await new Promise(resolve => target.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${target.address().port}`;
  try {
    const extension = vscode.extensions.all.find(item => item.packageJSON?.name === 'sentinelai');
    assert.ok(extension, 'extension should be discoverable in the development host');
    const extensionApi = await vscode.extensions.getExtension(extension.id).activate();
    assert.equal(typeof extensionApi?.runWorkbenchIntegration, 'function', 'test-only integration hook should be returned from activation');
    const commands = await vscode.commands.getCommands(true);
    assert.ok(commands.includes('sentinelai.openPanel'), 'open-panel command is registered even in test mode');

    const backend = await fetch('http://127.0.0.1:3000/health');
    assert.equal(backend.status, 200, 'backend fixture must be running');
    const capabilitiesResponse = await fetch('http://127.0.0.1:3000/security/capabilities');
    assert.equal(capabilitiesResponse.status, 200);
    const capabilities = await capabilitiesResponse.json();
    assert.ok(capabilities.profiles.some(profile => profile.id === 'source' && profile.supported));

    const workspaceRoot = path.join(__dirname, '..', 'host-workspace');
    const projectRoot = process.env.SENTINELAI_HOST_PROJECT_ROOT || path.join(workspaceRoot, 'accepted-project');
    fs.mkdirSync(projectRoot, { recursive: true });
    if (!process.env.SENTINELAI_HOST_PROJECT_ROOT) fs.writeFileSync(path.join(projectRoot, 'app.py'), 'from flask import Flask\napp = Flask(__name__)\n@app.get("/")\ndef home():\n    return "local host test"\n');
    if (!process.env.SENTINELAI_HOST_PROJECT_ROOT) {
      await vscode.workspace.updateWorkspaceFolders(0, vscode.workspace.workspaceFolders.length, { uri: vscode.Uri.file(projectRoot), name: 'SentinelAI acceptance project' });
    }
    const fixtureFile = path.join(projectRoot, 'app.py');
    assert.ok(fs.existsSync(fixtureFile), 'selected acceptance project must contain app.py');
    const document = await vscode.workspace.openTextDocument(vscode.Uri.file(fixtureFile));
    await vscode.window.showTextDocument(document);
    await vscode.commands.executeCommand('sentinelai.openPanel');
    assert.equal(extension.isActive, true);
    const targetUrl = process.env.SENTINELAI_HOST_TARGET_URL || url;
    const excluded = /(?:^|\/)(?:\.git|venv|\.venv|__pycache__|node_modules|build|dist|coverage|\.tox|\.pytest_cache)(?:\/|$)/i;
    const sensitive = /(?:^|\/)(?:\.env(?:\..*)?|credentials?(?:\..*)?|secrets?(?:\..*)?|id_rsa|id_ed25519|.*\.(?:pem|key|p12|pfx))$/i;
    const collected = [];
    const walk = (dir, prefix = '') => { for (const entry of fs.readdirSync(dir, { withFileTypes: true })) { const relative = prefix ? `${prefix}/${entry.name}` : entry.name; if (excluded.test(relative) || sensitive.test(relative)) continue; if (entry.isDirectory()) walk(path.join(dir, entry.name), relative); else if (entry.isFile()) collected.push(relative); } };
    walk(projectRoot);
    const sourceFiles = collected.filter(path => /\.(?:py|js|ts|go|php|java|rb|cs|cpp|c|rs|html|css|jsx|tsx|vue|svelte|sql|sh)$/i.test(path));
    const dependencyFiles = collected.filter(path => /(?:^|\/)(?:requirements[^/]*\.txt|pyproject\.toml|pipfile|pipfile\.lock|cargo\.toml|cargo\.lock|composer\.json|composer\.lock|gemfile|gemfile\.lock|go\.mod|go\.sum|package\.json|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml)$/.test(path.toLowerCase()));
    const infraFiles = collected.filter(relativePath => /(?:^|\/)(?:dockerfile(?:[.-].*)?|docker-compose.*\.ya?ml|compose\.ya?ml)$/.test(relativePath.toLowerCase()) || /\.(?:tf|tfvars|ya?ml)$/i.test(relativePath));
    const selectedFiles = [...new Set([...sourceFiles, ...dependencyFiles, ...infraFiles])].slice(0, 200);
    assert.ok(selectedFiles.includes('app.py'), 'selected app.py must be in the scan input');
    const files = selectedFiles.map(relativePath => ({ path: relativePath, content: fs.readFileSync(path.join(projectRoot, relativePath), 'utf8') }));
    const integration = await extensionApi.runWorkbenchIntegration(targetUrl, files, 'comprehensive');
    assert.equal(integration.status, 'completed');
    assert.ok(integration.scanJobId);
    assert.equal(integration.runtime.provenance.synthetic, false);
    assert.equal(integration.runtime.target.url.replace(/\/$/, ''), targetUrl.replace(/\/$/, ''));
    assert.ok(integration.runtime.coverage.some(check => check.check === 'attack type: security_headers'));
    assert.ok(integration.runtime.coverage.some(check => check.check === 'attack type: idor'));
    assert.ok(integration.runtime.coverage.some(check => check.status === 'skipped' || check.status === 'inconclusive'));

    const reportPath = path.join(workspaceRoot, 'sentinelai-report.json');
    const markdownPath = path.join(workspaceRoot, 'sentinelai-report.md');
    const saved = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
    assert.equal(saved.schemaVersion, 2);
    assert.equal(saved.sections.staticAnalysis.status, 'completed');
    assert.equal(saved.sections.projectValidation.status, 'completed');
    assert.ok(['completed', 'skipped'].includes(saved.sections.llmAnalysis.status));
    assert.ok(fs.existsSync(markdownPath), 'Markdown report is written alongside JSON');
    assert.match(fs.readFileSync(markdownPath, 'utf8'), /## Project Validation/);
    const filesBeforeRerun = fs.readdirSync(workspaceRoot).filter(name => name.startsWith('sentinelai-report.')).sort();
    const rerun = await extensionApi.runWorkbenchIntegration(targetUrl, files, 'comprehensive');
    assert.equal(rerun.status, 'completed');
    const updated = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
    assert.equal(updated.sections.projectValidation.status, 'completed');
    assert.deepEqual(fs.readdirSync(workspaceRoot).filter(name => name.startsWith('sentinelai-report.')).sort(), filesBeforeRerun, 'reruns update the same JSON and Markdown files');
    const response = await fetch(url);
    assert.equal(response.status, 200);
    const projectResponse = await fetch(targetUrl);
    assert.equal(projectResponse.status, 200, 'authorized selected local project responds');
    if (projectResponse.headers.get('content-type')?.includes('text/html')) assert.match(await projectResponse.text(), /Professional Vulnerability Scanner/);
    await vscode.commands.executeCommand('workbench.action.closeAllEditors');
  } finally {
    await new Promise(resolve => target.close(resolve));
    fs.rmSync(path.join(__dirname, '..', 'host-workspace'), { recursive: true, force: true });
  }
};
