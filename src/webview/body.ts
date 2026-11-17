export function getWebviewBody(): string {
  return `<div class="header-bar">
  <div class="header-title">
    <h1>SentinelAI</h1>
    <p class="sub">Local workspace security scan</p>
  </div>
  <div class="header-actions">
    <button class="btn btn-outline" id="btn-theme" title="Switch light/dark theme">🌙 Dark</button>
  </div>
</div>
<div id="root">
</div>
<section class="workbench-card" aria-label="Security Workbench">
  <div class="workbench-heading">
    <div><h2>Workspace scan</h2></div>
    <span class="workbench-local-badge">Local</span>
  </div>
  <div id="workbench-project-state" class="workbench-status" role="status" aria-live="polite">Open a project folder to scan.</div>
  <label class="workbench-profile-label" for="workbench-profile">What should SentinelAI check?</label>
  <select id="workbench-profile"><option value="source">Source code</option></select>
  <label class="workbench-consent"><input type="checkbox" id="workbench-network"> Check dependencies online (sends package names and versions)</label>
  <div class="workbench-actions">
    <button class="btn btn-primary" id="workbench-start" disabled>Run workspace scan</button>
    <button class="btn btn-outline" id="workbench-cancel" disabled>Cancel job</button>
  </div>
  <div id="workbench-status" class="workbench-status" role="status">Loading local capabilities…</div>
  <div id="workbench-limitations" class="workbench-limitations" aria-live="polite"></div>
  <div id="workbench-output"></div>
</section>
<section class="workbench-card runtime-card-workbench" aria-label="Runtime validation">
  <div class="workbench-heading"><div><h2>Project validation</h2></div></div>
  <label class="workbench-runtime-consent"><input id="workbench-runtime-consent" type="checkbox"> I own or am authorized to test this local application.</label>
  <button class="btn btn-outline" id="workbench-runtime" disabled>Validate local project</button>
  <div id="workbench-runtime-status" role="status" aria-live="polite"></div>
  <div id="workbench-runtime-output"></div>
</section>
<div class="workbench-export"><strong>Project report</strong><span id="workbench-save-status" role="status" aria-live="polite">Results are saved to sentinelai-report.json and sentinelai-report.md.</span></div>
<div id="sandbox-root"></div>`;
}
