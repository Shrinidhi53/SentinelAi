import * as vscode from 'vscode';
import axios from 'axios';
import { SecurityAPI, SecurityProfile, SecurityJob, shouldCollectFile } from './security-workbench';

import {
  Finding,
  ProjectAnalysisResponse,
  ProjectFile,
  SandboxReport,
  SandboxMode,
} from './types';

const SERVER_URL = 'http://localhost:3000';

const CODE_EXTENSIONS = [
  '.js',
  '.ts',
  '.py',
  '.go',
  '.java',
  '.php',
  '.rb',
  '.cs',
  '.cpp',
  '.c',
  '.rs',
  '.html',
  '.css',
  '.jsx',
  '.tsx',
  '.vue',
  '.svelte',
  '.sql',
  '.sh',
  '.env',
];

const MAX_CHARS_PER_FILE = 8_000;
const MAX_LOCKFILE_BYTES = 2 * 1024 * 1024;
const MAX_FILES = 200;

const FILE_GLOB =
  '**/*.{js,ts,py,go,php,java,rb,cs,cpp,c,rs,html,css,jsx,tsx,vue,svelte,sql,sh,env}';

const EXCLUDE_GLOB =
  '**/{node_modules,dist,out,.git,build,vendor,coverage,.next}/**';

function getExtension(
  filePath: string
): string {
  const lastDot =
    filePath.lastIndexOf('.');

  if (lastDot === -1) {
    return '';
  }

  return filePath
    .slice(lastDot)
    .toLowerCase();
}

export function isSupportedDocument(
  document: vscode.TextDocument
): boolean {
  return CODE_EXTENSIONS.includes(
    getExtension(
      document.fileName
    )
  );
}

export async function checkBackend(): Promise<void> {
  await axios.get(
    `${SERVER_URL}/health`,
    {
      timeout: 10_000,
    }
  );
}

const securityRequestOptions = { timeout: 30_000, maxRedirects: 0, proxy: false as const };
export const securityAPI: SecurityAPI = {
  async capabilities() {
    const response = await axios.get(`${SERVER_URL}/security/capabilities`, securityRequestOptions);
    return response.data;
  },
  async create(body) {
    const response = await axios.post(`${SERVER_URL}/security/jobs`, body, securityRequestOptions);
    return response.data.job;
  },
  async get(id) {
    const response = await axios.get(`${SERVER_URL}/security/jobs/${encodeURIComponent(id)}`, securityRequestOptions);
    return response.data.job;
  },
  async cancel(id) {
    const response = await axios.delete(`${SERVER_URL}/security/jobs/${encodeURIComponent(id)}`, securityRequestOptions);
    return response.data.job;
  },
};

export async function collectWorkspaceFiles(options: { securityProfile?: SecurityProfile } = {}): Promise<ProjectFile[]> {
  const uris =
    await vscode.workspace.findFiles(
      options.securityProfile ? '**/*' : FILE_GLOB,
      EXCLUDE_GLOB
    );

  if (['dependencies', 'comprehensive'].includes(options.securityProfile || '')) {
    const priority = (uri: vscode.Uri): number => {
      const name = vscode.workspace.asRelativePath(uri).replace(/\\/g, '/').split('/').pop()?.toLowerCase() || '';
      if (/^(?:package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml)$/.test(name)) return 0;
      if (/^(?:package\.json|requirements[^/]*\.txt|pyproject\.toml|pipfile|cargo\.toml|composer\.json|gemfile|go\.mod)$/.test(name)) return 1;
      return 2;
    };
    uris.sort((left, right) => priority(left) - priority(right));
  }

  const files: ProjectFile[] = [];

  for (const uri of uris) {
    if (
      files.length >= MAX_FILES
    ) {
      break;
    }

    const path = vscode.workspace.asRelativePath(uri).replace(/\\/g, '/');
    const dependencyProfile = ['dependencies', 'comprehensive'].includes(options.securityProfile || '');
    const dependencyManifest = /(?:^|\/)(?:package\.json|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|requirements[^/]*\.txt|pyproject\.toml|pipfile|pipfile\.lock|cargo\.toml|cargo\.lock|composer\.json|composer\.lock|gemfile|gemfile\.lock|go\.mod|go\.sum|pom\.xml|build\.gradle)$/.test(path.toLowerCase());
    const infrastructureProfile = ['infrastructure', 'comprehensive'].includes(options.securityProfile || '');
    const infrastructureFile = /(?:^|\/)(?:dockerfile(?:[.-].*)?|docker-compose.*\.ya?ml|compose\.ya?ml)$/.test(path.toLowerCase()) || /\.(?:tf|tfvars)$/.test(path.toLowerCase()) || (infrastructureProfile && /\.ya?ml$/i.test(path));
    const sourceFile = CODE_EXTENSIONS.includes(getExtension(path)) && !['.env'].includes(getExtension(path));
    if (options.securityProfile
      ? !shouldCollectFile(path, options.securityProfile)
      : !CODE_EXTENSIONS.includes(getExtension(uri.fsPath))) {
      continue;
    }
    if (options.securityProfile && dependencyManifest && !dependencyProfile) continue;
    if (options.securityProfile && infrastructureFile && !infrastructureProfile) continue;
    if (options.securityProfile === 'dependencies' && !dependencyManifest && !/\.(?:js|mjs|cjs|ts|py|go|php|java|rb|cs|cpp|c|rs|html|css|jsx|tsx|vue|svelte|sql|sh)$/i.test(path)) continue;
    if (options.securityProfile === 'source' && !sourceFile) continue;
    if (options.securityProfile === 'secrets' && !sourceFile) continue;

    if (options.securityProfile === 'infrastructure' && !infrastructureFile) continue;

    try {
      const bytes =
        await vscode.workspace.fs.readFile(
          uri
        );

      const lockfile = dependencyProfile
        ? /(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml)$/.test(path)
        : false;
      if (lockfile && bytes.byteLength > MAX_LOCKFILE_BYTES) {
        throw new Error(`Lockfile exceeds the ${MAX_LOCKFILE_BYTES}-byte analysis limit; dependency scan stopped rather than truncating dependency data.`);
      }
      const code = Buffer.from(bytes)
        .toString('utf8')
        .slice(0, lockfile ? MAX_LOCKFILE_BYTES : MAX_CHARS_PER_FILE);
      if (lockfile && path.toLowerCase().endsWith('.json')) {
        try { JSON.parse(code); }
        catch { throw new Error('Lockfile is invalid or incomplete; dependency scan stopped rather than partially analyzing it.'); }
      }

      if (!options.securityProfile && code.trim().length <= 30) {
        continue;
      }

      files.push({
        path,
        code,
      });
    } catch (error) {
      if (typeof error === 'object' && error !== null &&
          'message' in error && /^(?:Lockfile exceeds the \d+-byte analysis limit; dependency scan stopped rather than truncating dependency data\.|Lockfile is invalid or incomplete; dependency scan stopped rather than partially analyzing it\.)$/.test(String((error as Error).message))) {
        throw error;
      }
      console.error(
        `[SentinelAI] Failed to read ${uri.fsPath}:`,
        error
      );
    }
  }

  return files;
}

export interface RuntimeInfo {
  reachable: boolean;
  protocol: string;
  port: number;
  statusCode?: number;
  url: string;
  runtime: string;
}

export async function discoverRuntimes(): Promise<RuntimeInfo[]> {
  const response =
    await axios.get(
      `${SERVER_URL}/runtime/discover`,
      {
        timeout: 15_000,
      }
    );

  if (
    !response.data ||
    response.data.ok !== true
  ) {
    throw new Error(
      response.data?.error ||
        'Runtime discovery failed.'
    );
  }

  return response.data.runtimes || [];
}

export async function checkRuntime(
  targetUrl: string
): Promise<RuntimeInfo> {
  const response =
    await axios.post(
      `${SERVER_URL}/runtime/check`,
      {
        targetUrl,
      },
      {
        timeout: 10_000,
      }
    );

  if (
    !response.data ||
    response.data.ok !== true
  ) {
    throw new Error(
      response.data?.error ||
        'Runtime check failed.'
    );
  }

  return response.data;
}

export async function analyzeProject(
  files: ProjectFile[]
): Promise<ProjectAnalysisResponse> {
  const response =
    await axios.post<ProjectAnalysisResponse>(
      `${SERVER_URL}/analyze-project`,
      { files },
      {
        timeout: 660_000,
      }
    );

  if (
    !Array.isArray(
      response.data.findings
    )
  ) {
    throw new Error(
      'The backend returned an invalid findings response.'
    );
  }

  return response.data;
}

export async function checkSandbox(): Promise<void> {
  await axios.get(
    `${SERVER_URL}/sandbox/check`,
    {
      timeout: 15_000,
    }
  );
}

export async function runSandbox(
  findings: Finding[],
  mode: SandboxMode = 'simulation',
  targetUrl?: string
): Promise<SandboxReport> {
  const response = await axios.post(
    `${SERVER_URL}/sandbox/run`,
    {
      findings,
      mode,
      ...(targetUrl ? { targetUrl } : {}),
    },
    {
      timeout: 10 * 60 * 1000,
    }
  );

  return response.data;
}

export async function stopSandbox(): Promise<void> {
  await axios.post(
    `${SERVER_URL}/sandbox/stop`,
    {},
    {
      timeout: 30_000,
    }
  );
}