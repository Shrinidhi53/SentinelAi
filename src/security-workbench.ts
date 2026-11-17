export type SecurityProfile = 'source' | 'dependencies' | 'secrets' | 'infrastructure' | 'comprehensive';
export interface WorkbenchSetup { kind: 'scan'; profile?: SecurityProfile; allowAdvisoryNetwork: boolean; jobKey?: 'scan'; }
export interface SecurityJob { id: string; kind: 'scan'; status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'; events: unknown[]; result?: Record<string, unknown>; error?: string; }
export interface Capabilities { profiles: { id: string; name?: string; label?: string; description?: string; supported?: boolean; checks?: { id: string; available?: boolean; explanation?: string }[] }[]; limitations: string[]; }
export interface SecurityAPI {
  capabilities(): Promise<Capabilities>;
  create(body: Record<string, unknown>): Promise<SecurityJob>;
  get(id: string): Promise<SecurityJob>;

  cancel(id: string): Promise<SecurityJob>;
}
interface ControllerDependencies {
  api: SecurityAPI;
  collect(profile: SecurityProfile): Promise<{ path: string; content: string }[]>;
  emit(message: Record<string, unknown>): void;
  schedule(callback: () => Promise<void>, delay: number): unknown;
  unschedule(timer: unknown): void;
  onCompleted?(job: SecurityJob): Promise<void> | void;
  onCheckpoint?(job: SecurityJob): Promise<void> | void;
  onError?(message: string): Promise<void> | void;
}
export class SecurityWorkbenchController {
  private capabilities?: Capabilities;
  private job?: SecurityJob;

  private timer?: unknown;
  private disposed = false;
  private busy = false;
  private generation = 0;
  private setup?: WorkbenchSetup;
  private completedScan?: SecurityJob;
  private lastCheckpointKey = '';

  constructor(private readonly deps: ControllerDependencies) {}
  private emit(message: Record<string, unknown>): void { if (!this.disposed) { this.deps.emit(message); } }
  private error(message: string): void { void this.deps.onError?.(message); this.emit({ type: 'workbenchError', message, active: this.busy || this.active() }); }
  private active(): boolean { return this.job?.status === 'queued' || this.job?.status === 'running'; }
  private clearTimer(): void { if (this.timer !== undefined) { this.deps.unschedule(this.timer); this.timer = undefined; } }
  async loadCapabilities(workspace?: { open: boolean; projectFiles: number; ready: boolean; reason: string }): Promise<void> {
    try {
      this.capabilities = await this.deps.api.capabilities();
      this.emit({ type: 'workbenchCapabilities', capabilities: this.capabilities, ...(workspace ? { workspace } : {}) });
    } catch { this.error('Could not load Security Workbench capabilities. Check the local backend and retry.'); }
  }
  async start(setup: WorkbenchSetup): Promise<void> {
    if (this.disposed || this.busy || this.active()) { return; }
    const valid = setup && setup.kind === 'scan' && securityProfiles.includes(setup.profile!) &&
      this.capabilities?.profiles.some(p => p.id === setup.profile && p.supported !== false);
    if (!valid) { this.error('Select a supported capability before starting.'); return; }
    this.busy = true;
    const generation = ++this.generation;
    this.emit({ type: 'workbenchPreparing', kind: setup.kind, message: 'Collecting workspace files locally…' });
    try {
      const body: Record<string, unknown> = { kind: 'scan', options: { allowAdvisoryNetwork: setup.allowAdvisoryNetwork === true } };
      body.profile = setup.profile;
      const files = await this.deps.collect(setup.profile!);
      if (!files.length) { throw new Error('No files'); }
      body.files = files;
      if (setup.profile === 'dependencies' || setup.profile === 'comprehensive') {
        body.expectedLockfiles = files.map(file => file.path.replace(/\\/g, '/'))
          .filter(path => /(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml)$/i.test(path));
      }
      if (this.disposed) { return; }
      const job = await this.deps.api.create(body);
      this.setup = { kind: 'scan', profile: setup.profile, allowAdvisoryNetwork: setup.allowAdvisoryNetwork === true };
      this.busy = false;
      if (!this.disposed && generation === this.generation) { this.accept(job); }
    } catch {
      this.busy = false;
      this.error('Could not start job. Ensure supported workspace files exist and the local backend is available. No result was replaced.');
    } finally { this.busy = false; }
  }
  async rerun(): Promise<void> { if (this.setup) { await this.start({ ...this.setup }); } }

  async startRuntimeValidation(): Promise<void> {
    if (this.disposed) return;
    if (!this.completedScan || this.completedScan.status !== 'completed') {
      this.emit({ type: 'workbenchRuntimeError', message: 'Complete a Workbench scan before runtime validation.' });
      return;
    }
    this.emit({ type: 'workbenchRuntimeRequest', scanResult: this.completedScan.result, profile: this.completedScan.result?.profile });
  }

  async cancel(): Promise<void> {
    const current = this.job?.status === 'queued' || this.job?.status === 'running' ? this.job : undefined;
    if (this.disposed || this.busy || !current) { return; }
    this.busy = true;
    this.clearTimer();
    const generation = ++this.generation;
    try {
      const job = await this.deps.api.cancel(current.id);
      if (!this.disposed && generation === this.generation) { this.accept(job); }
    } catch {
      this.error('Cancellation could not be confirmed. Polling continues; the job may still be running.');
      this.schedulePoll(3000);
    } finally { this.busy = false; }
  }
  private accept(job: SecurityJob): void {
    if (this.disposed) { return; }
    this.clearTimer();
    this.job = job;
    if (job.result && typeof job.result === 'object') {
      this.completedScan = job;
      const result = job.result;
      const findings = Array.isArray(result.findings) ? result.findings.length : 0;
      const key = JSON.stringify([result.llmUsed, result.llmReason, result.llmEnabled, findings]);
      if (key !== this.lastCheckpointKey) {
        this.lastCheckpointKey = key;
        void this.deps.onCheckpoint?.(job);
      }
    }
    if (job.status === 'completed' && job.result) {
      void this.deps.onCompleted?.(job);
      if (job.kind === 'scan') this.completedScan = job;
    }
    this.emit({ type: 'workbenchJob', job });
    this.schedulePoll(1000);
  }
  private schedulePoll(delay: number): void {
    const current = this.job;
    if (this.disposed || !current || !['queued', 'running'].includes(current.status)) { return; }
    const id = current.id;
    const generation = this.generation;
    this.clearTimer();
    this.timer = this.deps.schedule(async () => {
      this.timer = undefined;
      try {
        const job = await this.deps.api.get(id);
        if (!this.disposed && generation === this.generation) { this.accept(job); }
      } catch {
        if (!this.disposed && generation === this.generation) {
          this.error('Connection interrupted. Last known job state shown; retrying in 3 seconds.');
          this.schedulePoll(3000);
        }
      }
    }, delay);
  }
  dispose(): void { this.disposed = true; this.generation++; this.clearTimer(); }
}
export const securityProfiles: SecurityProfile[] = ['source', 'dependencies', 'secrets', 'infrastructure', 'comprehensive'];
const lockfiles = new Set(['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'poetry.lock', 'pipfile.lock', 'cargo.lock', 'composer.lock', 'gemfile.lock', 'go.sum', 'uv.lock']);

/** Workbench collection is opt-in, separate from the legacy scan policy. */
export function shouldCollectFile(path: string, profile: SecurityProfile): boolean {
  const normalized = path.replace(/\\/g, '/').toLowerCase();
  const parts = normalized.split('/');
  const name = parts.at(-1) || '';
  if (parts.some(part => ['node_modules', 'dist', 'out', '.git', 'build', 'vendor', 'coverage', '.next', '.venv', 'venv', '.aws', '.ssh', '.secrets', 'secrets'].includes(part))) { return false; }
  if (/(^|[._-])(env|secrets?|credentials?)([._-]|$)/.test(name) || /\.(pem|key|p12|pfx|keystore)$/.test(name) || /^id_(rsa|dsa|ecdsa|ed25519)/.test(name) || ['.npmrc', '.pypirc', '.netrc'].includes(name)) { return false; }
  const dependencies = profile === 'dependencies' || profile === 'comprehensive';
  if (lockfiles.has(name)) { return dependencies; }
  if (/\.(js|mjs|cjs|ts|py|go|php|java|rb|cs|cpp|c|rs|html|css|jsx|tsx|vue|svelte|sql|sh)$/.test(name)) { return true; }
  if (dependencies && /^(package\.json|requirements[^/]*\.txt|pyproject\.toml|pipfile|cargo\.toml|composer\.json|gemfile|go\.mod|pom\.xml|build\.gradle)$/.test(name)) { return true; }
  return (profile === 'infrastructure' || profile === 'comprehensive') && (/^(dockerfile([.-].*)?|docker-compose.*\.ya?ml|compose\.ya?ml)$/.test(name) || /\.(tf|tfvars|ya?ml)$/.test(name));
}
