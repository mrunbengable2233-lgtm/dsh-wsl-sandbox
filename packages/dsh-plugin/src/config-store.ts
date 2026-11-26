import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  type ApprovalPolicyMode,
  type AuthorizedDeviceNode,
  type AuthorizedShare,
  type CacheMode,
  type EnvironmentProfile,
  failSandbox,
  isValidIdentifier,
  isValidLogLevel,
  type LogLevel,
  type NetworkMode,
  parseIpv4Cidr,
  type SandboxMode,
  validateDeviceNode,
  validateShareEntry,
  validateWslNodeExecutable,
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
  /** Optional custom Linux Node binary inside WSL ('auto' shares DSH/mise/nvm/system Node). */
  readonly wslNodePath?: string;
  /** Selected Codex-aligned binary toolchain profile (`core` / `standard` / `universal`). */
  readonly environmentProfile: EnvironmentProfile;
  readonly sandboxMode: SandboxMode;
  readonly approvalPolicyMode: ApprovalPolicyMode;
  readonly networkMode: NetworkMode;
  readonly upstreamProxy: string;
  readonly mirrorCn: boolean;
  readonly cacheMode: CacheMode;
  /** Structured logging level (`debug` | `info` | `warn` | `error`, default `info`). */
  readonly logLevel: LogLevel;
  readonly approvalTimeoutMs: number;
  readonly enablePwshGuard: boolean;
  readonly enablePromptInjection: boolean;
  /** Workspaces where the human explicitly unmasked `.env*` reads (default: empty). */
  readonly unmaskedEnvWorkspaces: readonly string[];
  /** Custom host directory for storing original WSL config backups (`.wslconfig`, `wsl.conf`, `fstab`). */
  readonly backupDir?: string;
  readonly advanced: AdvancedSandboxConfig;
}

export type BasicConfigPatch = Partial<
  Pick<
    WslSandboxConfig,
    | 'enabled'
    | 'transportMode'
    | 'distro'
    | 'username'
    | 'workspaceRoot'
    | 'runnerPath'
    | 'wslNodePath'
    | 'environmentProfile'
    | 'sandboxMode'
    | 'approvalPolicyMode'
    | 'networkMode'
    | 'upstreamProxy'
    | 'mirrorCn'
    | 'cacheMode'
    | 'logLevel'
    | 'approvalTimeoutMs'
    | 'enablePwshGuard'
    | 'enablePromptInjection'
    | 'unmaskedEnvWorkspaces'
    | 'backupDir'
  >
>;

export type ConfigChangeListener = (next: WslSandboxConfig, prev: WslSandboxConfig) => void;

const VALID_TRANSPORT_MODES = new Set<WslSandboxConfig['transportMode']>(['wsl', 'local-linux']);
const VALID_ENV_PROFILES = new Set<EnvironmentProfile>(['core', 'standard', 'universal']);
const VALID_SANDBOX_MODES = new Set<SandboxMode>(['read-only', 'workspace-write']);
const VALID_APPROVAL_MODES = new Set<ApprovalPolicyMode>(['balanced', 'strict', 'trust-workspace']);
const VALID_NETWORK_MODES = new Set<NetworkMode>(['allowlist-proxy', 'offline']);
const VALID_CACHE_MODES = new Set<CacheMode>(['workspace-persistent', 'ephemeral-tmp']);

export function getDefaultConfigDir(dshHome?: string): string {
  const base = dshHome ?? process.env.DSH_HOME ?? path.join(os.homedir(), '.dsh');
  return path.join(base, 'dsh-wsl-sandbox');
}

export function getDefaultConfigPath(dshHome?: string): string {
  return path.join(getDefaultConfigDir(dshHome), 'config.json');
}

export function getDefaultBackupDir(dshHome?: string): string {
  return path.join(getDefaultConfigDir(dshHome), 'backups');
}

export function getDefaultLogDir(dshHome?: string): string {
  return path.join(getDefaultConfigDir(dshHome), 'logs');
}

/**
 * Restricts a plugin-owned private directory or file to owner-only access.
 * On POSIX uses `chmod 0700` / `0600`; on Windows NTFS removes inherited broad `Users`/`Everyone`
 * read/write ACLs via `icacls /inheritance:r` (NEVER called on `%USERPROFILE%` or WSL Settings paths).
 */
export function hardenPrivatePath(targetPath: string, kind: 'dir' | 'file' | 'readonly-file'): void {
  if (process.platform === 'win32') {
    const user = process.env.USERNAME;
    if (user && /^[A-Za-z0-9_.\- ]+$/.test(user)) {
      const perm = kind === 'dir' ? '(OI)(CI)F' : kind === 'readonly-file' ? 'R' : 'F';
      const args = [
        targetPath,
        '/inheritance:r',
        '/grant:r',
        `*S-1-5-18:${kind === 'dir' ? '(OI)(CI)F' : 'F'}`,
        `${user}:${perm}`,
      ];
      spawnSync('icacls.exe', args, { stdio: 'ignore', shell: false, windowsHide: true, timeout: 4000 });
    }
    if (kind === 'readonly-file') {
      spawnSync('attrib.exe', ['+R', targetPath], { stdio: 'ignore', shell: false, windowsHide: true, timeout: 3000 });
    }
    return;
  }

  try {
    const mode = kind === 'dir' ? 0o700 : kind === 'readonly-file' ? 0o400 : 0o600;
    fs.chmodSync(targetPath, mode);
  } catch {
    // Best-effort on virtual filesystems
  }
}

/**
 * Validates a user-selected backup directory.
 * Explicitly blocks drive roots, OS system directories, `%USERPROFILE%` / `$HOME` roots
 * (where WSL Settings & WSL Manager share `.wslconfig`), live plugin config directories,
 * and Windows WSL VHDX storage paths (`AppData\Local\Packages`, `AppData\Local\wsl`).
 */
export function validateBackupDirPath(rawDir: string | undefined): string | undefined {
  if (rawDir === undefined) return undefined;
  let trimmed = rawDir.trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length >= 2) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'") && trimmed.length >= 2)
  ) {
    trimmed = trimmed.slice(1, -1).trim();
  }
  if (!trimmed) return undefined;
  if (trimmed.includes('\0')) {
    failSandbox('POLICY_BLOCK', 'Invalid backupDir containing NUL byte');
  }

  const slashNorm = trimmed.replace(/\\/g, '/').replace(/\/+$/, '');
  const lower = slashNorm.toLowerCase();

  // Reject drive roots, OS system directories, Windows user profile roots, and WSL VHDX folders
  if (
    /^[a-z]:?$/.test(lower) ||
    slashNorm === '' ||
    slashNorm === '/' ||
    /^[a-z]:\/(windows|program files|program files \(x86\)|programdata)(\/|$)/i.test(slashNorm) ||
    /^[a-z]:\/users\/[^/]+$/i.test(slashNorm) ||
    /^[a-z]:\/users\/[^/]+\/appdata\/local\/(packages|wsl)(\/|$)/i.test(slashNorm) ||
    /^\/(etc|proc|sys|dev|boot|bin|sbin|usr|lib|lib64|var|run|mnt)(\/|$)/i.test(slashNorm) ||
    /^\/home\/[^/]+$/i.test(slashNorm)
  ) {
    failSandbox(
      'POLICY_BLOCK',
      `Refusing to use drive root, user profile root (shared with WSL Settings/WSL Manager .wslconfig), OS system dir, or WSL VHDX storage as backupDir: ${trimmed}`,
    );
  }

  // Reject pointing backupDir directly at live plugin config root (`~/.dsh` or `~/.dsh/dsh-wsl-sandbox` or `~/.config/dsh-wsl-sandbox`)
  const homeNorm = os.homedir().replace(/\\/g, '/').replace(/\/+$/, '').toLowerCase();
  const cfgDirNorm = getDefaultConfigDir().replace(/\\/g, '/').replace(/\/+$/, '').toLowerCase();
  const dshRootNorm = path.dirname(cfgDirNorm);
  if (
    lower === homeNorm ||
    lower === dshRootNorm ||
    lower === cfgDirNorm ||
    lower === `${homeNorm}/.config/dsh-wsl-sandbox` ||
    lower === `${homeNorm}/.ssh` ||
    lower === `${homeNorm}/.gnupg`
  ) {
    failSandbox(
      'POLICY_BLOCK',
      `Refusing to place backups directly in live config root (${trimmed}); choose a dedicated backup subdirectory instead.`,
    );
  }

  return trimmed;
}

function inferDefaultLinuxUser(): string {
  if (process.platform !== 'win32') {
    try {
      const u = os.userInfo().username;
      if (u && u !== 'root' && /^[a-z_][a-z0-9_-]{0,31}$/.test(u)) {
        return u;
      }
    } catch {
      // ignore
    }
  }
  return 'dev';
}

function resolveDefaultRunnerPath(isWin: boolean, defaultUser: string): string {
  const stagedPath = `/home/${defaultUser}/.local/share/dsh-wsl-sandbox/runner/dist/packages/wsl-runner/src/main.js`;
  if (isWin) return stagedPath;
  if (fs.existsSync(stagedPath)) return stagedPath;

  const localCandidates = [
    path.resolve(import.meta.dirname, '../../wsl-runner/src/main.js'),
    path.resolve(import.meta.dirname, '../../../dist/packages/wsl-runner/src/main.js'),
    path.resolve(import.meta.dirname, '../../wsl-runner/src/main.ts'),
  ];
  for (const candidate of localCandidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return stagedPath;
}

export function createDefaultConfig(overrides?: Partial<WslSandboxConfig>): WslSandboxConfig {
  const isWin = process.platform === 'win32';
  const defaultUser = inferDefaultLinuxUser();
  const base: WslSandboxConfig = {
    revision: 'rev-1',
    enabled: true,
    transportMode: isWin ? 'wsl' : 'local-linux',
    // On Windows: defaults to modern Ubuntu-26.04 LTS until installer/discovery binds the user's real distro;
    // on native Linux devbox: uses WSL_DISTRO_NAME if inside WSL or 'local-linux'.
    distro: isWin ? 'Ubuntu-26.04' : (process.env.WSL_DISTRO_NAME || 'local-linux'),
    workspaceRoot: `/home/${defaultUser}/workspace`,
    runnerPath: resolveDefaultRunnerPath(isWin, defaultUser),
    wslNodePath: 'auto',
    environmentProfile: 'standard',
    sandboxMode: 'workspace-write',
    approvalPolicyMode: 'balanced',
    networkMode: 'allowlist-proxy',
    upstreamProxy: '',
    mirrorCn: false,
    cacheMode: 'workspace-persistent',
    logLevel: 'info',
    approvalTimeoutMs: 60_000,
    enablePwshGuard: true,
    enablePromptInjection: true,
    unmaskedEnvWorkspaces: [],
    backupDir: getDefaultBackupDir(),
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

  if (!VALID_TRANSPORT_MODES.has(raw.transportMode)) {
    failSandbox('INVALID_SETUP', `Invalid transportMode: ${String(raw.transportMode)}`);
  }
  const environmentProfile: EnvironmentProfile = raw.environmentProfile ?? 'standard';
  if (!VALID_ENV_PROFILES.has(environmentProfile)) {
    failSandbox('INVALID_SETUP', `Invalid environmentProfile: ${String(environmentProfile)}`);
  }
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
  const logLevel: LogLevel = raw.logLevel ?? 'info';
  if (!isValidLogLevel(logLevel)) {
    failSandbox('INVALID_SETUP', `Invalid logLevel: ${String(logLevel)}`);
  }
  if (!Number.isSafeInteger(raw.approvalTimeoutMs) || raw.approvalTimeoutMs < 1000 || raw.approvalTimeoutMs > 600_000) {
    failSandbox('INVALID_SETUP', `Invalid approvalTimeoutMs: ${raw.approvalTimeoutMs}`);
  }

  const wslNodePath = validateWslNodeExecutable(raw.wslNodePath);
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
  const backupDir = validateBackupDirPath(raw.backupDir) ?? getDefaultBackupDir();

  return {
    ...raw,
    wslNodePath,
    environmentProfile,
    logLevel,
    upstreamProxy,
    backupDir,
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
 * Human-only persistent configuration store (`0600` on POSIX / owner-only ACL on Windows NTFS).
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

  getConfigFilePath(): string {
    return this.filePath;
  }

  getConfigDir(): string {
    return path.dirname(this.filePath);
  }

  isPersistent(): boolean {
    return this.persistToDisk;
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
    const dirExisted = fs.existsSync(dir);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    if (!dirExisted) {
      hardenPrivatePath(dir, 'dir');
    }
    const tmpPath = `${this.filePath}.tmp.${process.pid}.${randomBytes(4).toString('hex')}`;
    try {
      fs.writeFileSync(tmpPath, JSON.stringify(cfg, null, 2) + '\n', { mode: 0o600 });
      let lastErr: unknown;
      for (let attempt = 0; attempt < 3; attempt++) {
        try {
          fs.renameSync(tmpPath, this.filePath);
          lastErr = undefined;
          break;
        } catch (err) {
          lastErr = err;
          const code = (err as NodeJS.ErrnoException).code;
          if (code !== 'EPERM' && code !== 'EBUSY') throw err;
        }
      }
      if (lastErr) throw lastErr;
      hardenPrivatePath(this.filePath, 'file');
    } finally {
      if (fs.existsSync(tmpPath)) {
        try { fs.rmSync(tmpPath, { force: true }); } catch { /* ignore */ }
      }
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
      transportMode: patch.transportMode ?? this.config.transportMode,
      distro: patch.distro ?? this.config.distro,
      username: patch.username !== undefined ? patch.username : this.config.username,
      workspaceRoot: patch.workspaceRoot ?? this.config.workspaceRoot,
      runnerPath: patch.runnerPath ?? this.config.runnerPath,
      wslNodePath: patch.wslNodePath !== undefined ? patch.wslNodePath : this.config.wslNodePath,
      environmentProfile: patch.environmentProfile ?? this.config.environmentProfile,
      sandboxMode: patch.sandboxMode ?? this.config.sandboxMode,
      approvalPolicyMode: patch.approvalPolicyMode ?? this.config.approvalPolicyMode,
      networkMode: patch.networkMode ?? this.config.networkMode,
      upstreamProxy: patch.upstreamProxy !== undefined ? patch.upstreamProxy : this.config.upstreamProxy,
      mirrorCn: patch.mirrorCn ?? this.config.mirrorCn,
      cacheMode: patch.cacheMode ?? this.config.cacheMode,
      logLevel: patch.logLevel ?? this.config.logLevel,
      approvalTimeoutMs: patch.approvalTimeoutMs ?? this.config.approvalTimeoutMs,
      enablePwshGuard: patch.enablePwshGuard ?? this.config.enablePwshGuard,
      enablePromptInjection: patch.enablePromptInjection ?? this.config.enablePromptInjection,
      unmaskedEnvWorkspaces: patch.unmaskedEnvWorkspaces ?? this.config.unmaskedEnvWorkspaces,
      backupDir: patch.backupDir !== undefined ? patch.backupDir : this.config.backupDir,
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
