import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  type ApprovalPolicyMode,
  type AuthorizedDeviceNode,
  type AuthorizedShare,
  type CacheMode,
  failSandbox,
  isValidIdentifier,
  type NetworkMode,
  parseIpv4Cidr,
  type SandboxMode,
  validateDeviceNode,
  validateShareEntry,
  validateWorkspaceRoot,
} from '../../core/src/index.ts';

export interface AdvancedSandboxConfig {
  /** Single-directory shares mounted under `/shares/<alias>`, OFF by default, `ro` default. */
  readonly shares: readonly AuthorizedShare[];
  /** Single-device passthrough nodes (`/dev/ttyUSB0`, `/dev/ttyACM0`, etc.), OFF by default. */
  readonly deviceNodes: readonly AuthorizedDeviceNode[];
  /** Explicit local lab IPv4 CIDRs allowed through UDS proxy (SSRF-safe default: empty). */
  readonly localLabCidrs: readonly string[];
  /** Explicit local lab ports on localhost allowed through UDS proxy (default: empty). */
  readonly localLabPorts: readonly number[];
  /** Additional user-approved outbound domains. */
  readonly customAllowedDomains: readonly string[];
}

export interface WslSandboxConfig {
  readonly revision: string;
  readonly enabled: boolean;
  readonly transportMode: 'wsl' | 'local-linux';
  readonly distro: string;
  readonly username?: string;
  readonly workspaceRoot: string;
  readonly runnerPath: string;
  readonly sandboxMode: SandboxMode;
  readonly approvalPolicyMode: ApprovalPolicyMode;
  readonly networkMode: NetworkMode;
  readonly upstreamProxy: string;
  readonly mirrorCn: boolean;
  readonly cacheMode: CacheMode;
  readonly approvalTimeoutMs: number;
  readonly enablePwshGuard: boolean;
  readonly enablePromptInjection: boolean;
  /** Workspaces where the human explicitly unmasked `.env*` reads (default: empty). */
  readonly unmaskedEnvWorkspaces: readonly string[];
  readonly advanced: AdvancedSandboxConfig;
}

export type BasicConfigPatch = Partial<
  Pick<
    WslSandboxConfig,
    | 'enabled'
    | 'distro'
    | 'username'
    | 'workspaceRoot'
    | 'runnerPath'
    | 'sandboxMode'
    | 'approvalPolicyMode'
    | 'networkMode'
    | 'upstreamProxy'
    | 'mirrorCn'
    | 'cacheMode'
    | 'approvalTimeoutMs'
    | 'enablePwshGuard'
    | 'enablePromptInjection'
    | 'unmaskedEnvWorkspaces'
  >
>;

export type ConfigChangeListener = (next: WslSandboxConfig, prev: WslSandboxConfig) => void;

const VALID_SANDBOX_MODES = new Set<SandboxMode>(['read-only', 'workspace-write']);
const VALID_APPROVAL_MODES = new Set<ApprovalPolicyMode>(['balanced', 'strict', 'trust-workspace']);
const VALID_NETWORK_MODES = new Set<NetworkMode>(['allowlist-proxy', 'offline']);
const VALID_CACHE_MODES = new Set<CacheMode>(['workspace-persistent', 'ephemeral-tmp']);

export function getDefaultConfigPath(dshHome?: string): string {
  const base = dshHome ?? process.env.DSH_HOME ?? path.join(os.homedir(), '.dsh');
  return path.join(base, 'dsh-wsl-sandbox', 'config.json');
}

export function createDefaultConfig(overrides?: Partial<WslSandboxConfig>): WslSandboxConfig {
  const isWin = process.platform === 'win32';
  const base: WslSandboxConfig = {
    revision: 'rev-1',
    enabled: true,
    transportMode: isWin ? 'wsl' : 'local-linux',
    distro: 'Ubuntu-24.04',
    workspaceRoot: '/home/dev/workspace',
    runnerPath: '/opt/dsh-wsl-sandbox/dist/wsl-runner/src/main.js',
    sandboxMode: 'workspace-write',
    approvalPolicyMode: 'balanced',
    networkMode: 'allowlist-proxy',
    upstreamProxy: '',
    mirrorCn: false,
    cacheMode: 'workspace-persistent',
    approvalTimeoutMs: 60_000,
    enablePwshGuard: true,
    enablePromptInjection: true,
    unmaskedEnvWorkspaces: [],
    advanced: {
      shares: [],
      deviceNodes: [],
      localLabCidrs: [],
      localLabPorts: [],
      customAllowedDomains: [],
    },
  };
  return validateFullConfig({
    ...base,
    ...overrides,
    advanced: {
      ...base.advanced,
      ...(overrides?.advanced ?? {}),
    },
  });
}

function validateUpstreamProxy(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return '';
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    failSandbox('INVALID_SETUP', `Invalid upstreamProxy URL: ${trimmed}`);
  }
  if (!['http:', 'https:', 'socks5:', 'socks5h:'].includes(parsed.protocol)) {
    failSandbox('INVALID_SETUP', `Unsupported upstreamProxy protocol: ${parsed.protocol}`);
  }
  return trimmed;
}

function validateDomain(domain: string): string {
  const clean = domain.trim().toLowerCase();
  if (!/^(?:\*\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(clean)) {
    failSandbox('POLICY_BLOCK', `Invalid domain allowlist entry: ${domain}`);
  }
  return clean;
}

export function validateFullConfig(raw: WslSandboxConfig): WslSandboxConfig {
  if (!isValidIdentifier(raw.distro)) {
    failSandbox('INVALID_SETUP', `Invalid WSL distro name: ${raw.distro}`);
  }
  if (raw.username !== undefined && raw.username !== '' && !/^[a-z_][a-z0-9_-]{0,31}$/.test(raw.username)) {
    failSandbox('INVALID_SETUP', `Invalid Linux username: ${raw.username}`);
  }
  validateWorkspaceRoot(raw.workspaceRoot, raw.username);

  if (!VALID_SANDBOX_MODES.has(raw.sandboxMode)) {
    failSandbox('INVALID_SETUP', `Invalid sandboxMode: ${String(raw.sandboxMode)}`);
  }
  if (!VALID_APPROVAL_MODES.has(raw.approvalPolicyMode)) {
    failSandbox('INVALID_SETUP', `Invalid approvalPolicyMode: ${String(raw.approvalPolicyMode)}`);
  }
  if (!VALID_NETWORK_MODES.has(raw.networkMode)) {
    failSandbox('INVALID_SETUP', `Invalid networkMode: ${String(raw.networkMode)}`);
  }
  if (!VALID_CACHE_MODES.has(raw.cacheMode)) {
    failSandbox('INVALID_SETUP', `Invalid cacheMode: ${String(raw.cacheMode)}`);
  }
  if (!Number.isSafeInteger(raw.approvalTimeoutMs) || raw.approvalTimeoutMs < 1000 || raw.approvalTimeoutMs > 600_000) {
    failSandbox('INVALID_SETUP', `Invalid approvalTimeoutMs: ${raw.approvalTimeoutMs}`);
  }

  const upstreamProxy = validateUpstreamProxy(raw.upstreamProxy ?? '');
  const shares = (raw.advanced?.shares ?? []).map(validateShareEntry);
  const deviceNodes = (raw.advanced?.deviceNodes ?? []).map(validateDeviceNode);

  const localLabCidrs = (raw.advanced?.localLabCidrs ?? []).map((c) => {
    const trimmed = c.trim();
    if (!parseIpv4Cidr(trimmed)) {
      failSandbox('POLICY_BLOCK', `Invalid localLabCidr: ${c}`);
    }
    return trimmed;
  });

  const localLabPorts = (raw.advanced?.localLabPorts ?? []).map((p) => {
    if (!Number.isInteger(p) || p < 1 || p > 65535) {
      failSandbox('POLICY_BLOCK', `Invalid localLabPort: ${p}`);
    }
    return p;
  });

  const customAllowedDomains = (raw.advanced?.customAllowedDomains ?? []).map(validateDomain);

  return {
    ...raw,
    upstreamProxy,
    unmaskedEnvWorkspaces: [...new Set(raw.unmaskedEnvWorkspaces ?? [])],
    advanced: {
      shares,
      deviceNodes,
      localLabCidrs,
      localLabPorts,
      customAllowedDomains,
    },
  };
}

function nextRevision(current: string): string {
  const m = current.match(/^rev-(\d+)$/);
  const n = m ? Number(m[1]) + 1 : Date.now();
  return `rev-${n}`;
}

/**
 * Human-only persistent configuration store (`0600` file permissions).
 * Model tools NEVER receive write access to this store; only authenticated host HTTP routes
 * or host-side initialization may mutate it.
 */
export class ConfigStore {
  private readonly filePath: string;
  private readonly persistToDisk: boolean;
  private config: WslSandboxConfig;
  private readonly listeners = new Set<ConfigChangeListener>();

  constructor(options?: {
    filePath?: string;
    persistToDisk?: boolean;
    initial?: Partial<WslSandboxConfig>;
  }) {
    this.filePath = options?.filePath ?? getDefaultConfigPath();
    this.persistToDisk = options?.persistToDisk ?? true;
    this.config = this.loadOrInit(options?.initial);
  }

  private loadOrInit(initial?: Partial<WslSandboxConfig>): WslSandboxConfig {
    if (this.persistToDisk && fs.existsSync(this.filePath)) {
      try {
        const parsed = JSON.parse(fs.readFileSync(this.filePath, 'utf8')) as Partial<WslSandboxConfig>;
        return createDefaultConfig({ ...parsed, ...initial });
      } catch {
        // Fall through to defaults if corrupted
      }
    }
    const defaults = createDefaultConfig(initial);
    if (this.persistToDisk) {
      this.saveAtomic(defaults);
    }
    return defaults;
  }

  private saveAtomic(cfg: WslSandboxConfig): void {
    const dir = path.dirname(this.filePath);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const tmpPath = `${this.filePath}.tmp.${process.pid}`;
    fs.writeFileSync(tmpPath, JSON.stringify(cfg, null, 2) + '\n', { mode: 0o600 });
    fs.renameSync(tmpPath, this.filePath);
    try {
      fs.chmodSync(this.filePath, 0o600);
    } catch {
      // Best-effort on Windows NTFS
    }
  }

  get(): WslSandboxConfig {
    return this.config;
  }

  onChange(listener: ConfigChangeListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private commit(nextUnrev: WslSandboxConfig): WslSandboxConfig {
    const prev = this.config;
    const next = validateFullConfig({
      ...nextUnrev,
      revision: nextRevision(prev.revision),
    });
    this.config = next;
    if (this.persistToDisk) {
      this.saveAtomic(next);
    }
    for (const listener of this.listeners) {
      listener(next, prev);
    }
    return next;
  }

  /** Update basic settings only. Explicitly forbids smuggling `/mnt` full-drive mounts here (Q8). */
  updateBasic(patch: BasicConfigPatch & Record<string, unknown>): WslSandboxConfig {
    if ('mountFullWindowsDrives' in patch || 'mntMount' in patch || 'advanced' in patch) {
      failSandbox(
        'POLICY_BLOCK',
        'Full Windows drive (/mnt) mounting is disabled in basic config; use Advanced single-directory /shares/<alias> instead.',
      );
    }
    return this.commit({
      ...this.config,
      enabled: patch.enabled ?? this.config.enabled,
      distro: patch.distro ?? this.config.distro,
      username: patch.username !== undefined ? patch.username : this.config.username,
      workspaceRoot: patch.workspaceRoot ?? this.config.workspaceRoot,
      runnerPath: patch.runnerPath ?? this.config.runnerPath,
      sandboxMode: patch.sandboxMode ?? this.config.sandboxMode,
      approvalPolicyMode: patch.approvalPolicyMode ?? this.config.approvalPolicyMode,
      networkMode: patch.networkMode ?? this.config.networkMode,
      upstreamProxy: patch.upstreamProxy !== undefined ? patch.upstreamProxy : this.config.upstreamProxy,
      mirrorCn: patch.mirrorCn ?? this.config.mirrorCn,
      cacheMode: patch.cacheMode ?? this.config.cacheMode,
      approvalTimeoutMs: patch.approvalTimeoutMs ?? this.config.approvalTimeoutMs,
      enablePwshGuard: patch.enablePwshGuard ?? this.config.enablePwshGuard,
      enablePromptInjection: patch.enablePromptInjection ?? this.config.enablePromptInjection,
      unmaskedEnvWorkspaces: patch.unmaskedEnvWorkspaces ?? this.config.unmaskedEnvWorkspaces,
    });
  }

  /** Advanced: authorize a single directory mounted under `/shares/<alias>` (default `ro`). */
  addShare(share: AuthorizedShare): WslSandboxConfig {
    const validated = validateShareEntry({ ...share, mode: share.mode ?? 'ro' });
    const filtered = this.config.advanced.shares.filter(
      (s) => s.id !== validated.id && s.alias !== validated.alias,
    );
    return this.commit({
      ...this.config,
      advanced: {
        ...this.config.advanced,
        shares: [...filtered, validated],
      },
    });
  }

  /** Advanced: immediately revoke a single-directory share (triggers generation++ & kill). */
  removeShare(shareId: string): WslSandboxConfig {
    const filtered = this.config.advanced.shares.filter((s) => s.id !== shareId);
    return this.commit({
      ...this.config,
      advanced: {
        ...this.config.advanced,
        shares: filtered,
      },
    });
  }

  /** Advanced: update explicit single-device passthrough whitelist (Q13). */
  setDeviceNodes(nodes: readonly AuthorizedDeviceNode[]): WslSandboxConfig {
    const validated = nodes.map(validateDeviceNode);
    return this.commit({
      ...this.config,
      advanced: {
        ...this.config.advanced,
        deviceNodes: validated,
      },
    });
  }

  /** Advanced: update UDS proxy local lab CIDRs/ports and custom domain allowlist (Q16). */
  updateAdvancedNetwork(patch: {
    localLabCidrs?: readonly string[];
    localLabPorts?: readonly number[];
    customAllowedDomains?: readonly string[];
  }): WslSandboxConfig {
    return this.commit({
      ...this.config,
      advanced: {
        ...this.config.advanced,
        localLabCidrs: patch.localLabCidrs ?? this.config.advanced.localLabCidrs,
        localLabPorts: patch.localLabPorts ?? this.config.advanced.localLabPorts,
        customAllowedDomains: patch.customAllowedDomains ?? this.config.advanced.customAllowedDomains,
      },
    });
  }

  isWorkspaceEnvMasked(workspaceRoot: string): boolean {
    return !this.config.unmaskedEnvWorkspaces.includes(workspaceRoot);
  }
}
