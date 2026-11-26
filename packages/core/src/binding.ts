import { posix } from 'node:path';
import { failSandbox } from './errors.ts';

export type SandboxMode = 'read-only' | 'workspace-write';
export type NetworkMode = 'allowlist-proxy' | 'offline';
export type CacheMode = 'workspace-persistent' | 'ephemeral-tmp';
export type ApprovalPolicyMode = 'balanced' | 'strict' | 'trust-workspace';
export type EnvironmentProfile = 'core' | 'standard' | 'universal';
export type LinuxArch = 'x86_64' | 'aarch64';

export interface AuthorizedShare {
  readonly id: string;
  readonly alias: string;
  readonly sourceLinuxPath: string;
  readonly mode: 'ro' | 'rw';
  readonly oneShot?: boolean;
}

export interface AuthorizedDeviceNode {
  readonly path: string;
  readonly label?: string;
}

export interface WslProbeResult {
  readonly sessionId: string;
  readonly backend: 'wsl' | string;
  readonly wslVersion: number;
  readonly distribution: string;
  readonly uid: number;
  readonly username: string;
  readonly arch: LinuxArch | string;
  readonly workspaceRoot: string;
  readonly cwd: string;
  readonly profile: SandboxMode;
  readonly revision: string;
  readonly runnerId: string;
  readonly sandboxReady: boolean;
  readonly enforcement: 'full' | 'partial';
  readonly bwrapVersion?: string;
  readonly supportsDisableUserns?: boolean;
  readonly probedSockets?: readonly string[];
  readonly authorizedShares?: readonly AuthorizedShare[];
  readonly authorizedDevices?: readonly AuthorizedDeviceNode[];
}

export interface SessionBinding {
  readonly sessionId: string;
  readonly backend: 'wsl';
  readonly wslVersion: 2;
  readonly distribution: string;
  readonly uid: number;
  readonly username: string;
  readonly arch: LinuxArch;
  readonly workspaceRoot: string;
  readonly cwd: string;
  readonly profile: SandboxMode;
  readonly revision: string;
  readonly generation: number;
  readonly runnerId: string;
  readonly sandboxReady: true;
  readonly enforcement: 'full' | 'partial';
  readonly supportsDisableUserns: boolean;
  readonly probedSockets: readonly string[];
  readonly authorizedShares: readonly AuthorizedShare[];
  readonly authorizedDevices: readonly AuthorizedDeviceNode[];
}

const VALID_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;
const VALID_LINUX_USERNAME_RE = /^[a-z_][a-z0-9_.-]{0,31}$/;
const VALID_SHARE_ALIAS_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
const ALLOWED_DEVICE_RE = /^\/dev\/(ttyUSB\d+|ttyACM\d+|ttyS\d+|bus\/usb\/\d{3}\/\d{3}|hidraw\d+|cdc-wdm\d+|video\d+|spidev\d+\.\d+|i2c-\d+)$/;

const INTERNAL_DISTRO_PATTERNS = [
  /^docker-desktop$/i,
  /^docker-desktop-data$/i,
  /^rancher-desktop/i,
  /^podman-machine/i,
];

const FORBIDDEN_WORKSPACE_ROOTS = new Set([
  '/',
  '/bin',
  '/boot',
  '/dev',
  '/etc',
  '/home',
  '/lib',
  '/lib64',
  '/mnt',
  '/mnt/wsl',
  '/mnt/wslg',
  '/mnt/wslg/distro',
  '/opt',
  '/proc',
  '/root',
  '/run',
  '/run/WSL',
  '/sbin',
  '/srv',
  '/sys',
  '/tmp',
  '/usr',
  '/var',
  '/var/run',
]);

const FORBIDDEN_WORKSPACE_PREFIXES = [
  '/bin/',
  '/boot/',
  '/dev/',
  '/etc/',
  '/lib/',
  '/lib64/',
  '/mnt/',
  '/proc/',
  '/root/',
  '/run/',
  '/sbin/',
  '/sys/',
  '/usr/',
  '/var/run/',
];

export function isValidIdentifier(value: unknown): value is string {
  return typeof value === 'string' && VALID_ID_RE.test(value);
}

/**
 * Validates a WSL distribution name including custom/DIY WSL Manager imports with spaces,
 * parentheses, or Unicode characters (e.g. `'AI workspace'`, `'Ubuntu (Lab)'`), while blocking
 * control characters, Windows path/UNC separators, and traversal segments.
 */
export function isValidDistroName(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  if (value.length === 0 || value.length > 128) return false;
  if (value.trim() !== value) return false;
  if (value === '.' || value === '..') return false;
  if (/[\x00-\x1f\x7f/\\:*?"<>|]/.test(value)) return false;
  return true;
}

export function isValidLinuxUsername(value: unknown): value is string {
  return typeof value === 'string' && VALID_LINUX_USERNAME_RE.test(value);
}

export function isSafeAbsoluteLinuxPath(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 4096) {
    return false;
  }
  if (value.includes('\0') || value.startsWith('//') || !value.startsWith('/')) {
    return false;
  }
  if (value.length > 1 && value.endsWith('/')) {
    return false;
  }
  return posix.normalize(value) === value;
}

export function isPathInside(root: string, candidate: string): boolean {
  const normRoot = posix.normalize(root);
  const normCand = posix.normalize(candidate);
  if (normRoot === '/') return normCand.startsWith('/');
  return normCand === normRoot || normCand.startsWith(normRoot + '/');
}

const FORBIDDEN_CONFIG_PATH_PATTERNS = [
  /(?:^|\/)\.dsh(?:\/|$)/i,
  /(?:^|\/)\.config\/dsh-wsl-sandbox(?:\/|$)/i,
  /(?:^|\/)\.wslconfig$/i,
  /(?:^|\/)\.ssh(?:\/|$)/i,
  /(?:^|\/)\.gnupg(?:\/|$)/i,
  /(?:^|\/)\.aws(?:\/|$)/i,
  /(?:^|\/)\.kube(?:\/|$)/i,
  /(?:^|\/)appdata\/local\/packages(?:\/|$)/i,
  /(?:^|\/)appdata\/local\/wsl(?:\/|$)/i,
];

export function validateWorkspaceRoot(linuxPath: string, username?: string): string {
  if (!isSafeAbsoluteLinuxPath(linuxPath)) {
    failSandbox('POLICY_BLOCK', `Invalid Linux workspace path: ${linuxPath}`);
  }
  if (FORBIDDEN_WORKSPACE_ROOTS.has(linuxPath)) {
    failSandbox('POLICY_BLOCK', `Forbidden system or root directory as workspaceRoot: ${linuxPath}`);
  }
  for (const prefix of FORBIDDEN_WORKSPACE_PREFIXES) {
    if (linuxPath.startsWith(prefix)) {
      failSandbox('POLICY_BLOCK', `Workspace root cannot live under protected mount ${prefix}: ${linuxPath}`);
    }
  }
  if (FORBIDDEN_CONFIG_PATH_PATTERNS.some((re) => re.test(linuxPath))) {
    failSandbox('POLICY_BLOCK', `Workspace root cannot point to private config/credential directory: ${linuxPath}`);
  }
  if (/^\/home\/[^/]+$/.test(linuxPath) || (username && (linuxPath === `/home/${username}` || linuxPath === '/root'))) {
    failSandbox('POLICY_BLOCK', `Entire user home directory cannot be mounted as workspaceRoot: ${linuxPath}`);
  }
  return linuxPath;
}

const FORBIDDEN_WINDOWS_MOUNT_PATTERNS = [
  /^\/mnt\/[a-z]$/i,
  /^\/mnt\/[a-z]\/windows(?:\/|$)/i,
  /^\/mnt\/[a-z]\/program files(?: \(x86\))?(?:\/|$)/i,
  /^\/mnt\/[a-z]\/programdata(?:\/|$)/i,
  /^\/mnt\/[a-z]\/system volume information(?:\/|$)/i,
  /^\/mnt\/[a-z]\/\$recycle\.bin(?:\/|$)/i,
  /^\/mnt\/[a-z]\/recovery(?:\/|$)/i,
  /^\/mnt\/[a-z]\/users$/i,
  /^\/mnt\/[a-z]\/users\/[^/]+$/i,
  /^\/mnt\/[a-z]\/users\/[^/]+\/appdata(?:\/|$)/i,
];

/**
 * Converts a Windows folder path (e.g. `D:\Datasets\Project` or `"C:/Users/Alice/Downloads/spec"`)
 * or a Linux path into a canonical normalized POSIX path without trailing slash.
 * Rejects UNC paths and bare drive roots (`C:\`, `D:\`) at validation time.
 */
export function normalizeSharePathInput(rawInput: string): string {
  if (typeof rawInput !== 'string') {
    failSandbox('POLICY_BLOCK', 'Share path must be a string');
  }
  let trimmed = rawInput.trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length >= 2) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'") && trimmed.length >= 2)
  ) {
    trimmed = trimmed.slice(1, -1).trim();
  }
  if (!trimmed || trimmed.includes('\0')) {
    failSandbox('POLICY_BLOCK', 'Share path cannot be empty or contain NUL bytes');
  }
  if (trimmed.startsWith('\\\\')) {
    failSandbox(
      'POLICY_BLOCK',
      `Windows UNC share paths are not supported directly (${trimmed}); use a local drive subfolder (e.g. D:\\Folder) or native Linux path.`,
    );
  }

  const winDriveMatch = trimmed.match(/^([A-Za-z]):(?:[\\/](.*))?$/);
  if (winDriveMatch) {
    const drive = winDriveMatch[1]!.toLowerCase();
    const rest = (winDriveMatch[2] ?? '').replace(/\\/g, '/').replace(/\/+$/, '');
    if (!rest) {
      failSandbox(
        'POLICY_BLOCK',
        `Refusing to mount entire Windows drive root (${drive.toUpperCase()}:\\ -> /mnt/${drive}); specify a concrete subdirectory such as ${drive.toUpperCase()}:\\Projects\\MyFolder`,
      );
    }
    const candidate = posix.normalize(`/mnt/${drive}/${rest}`);
    const trimmedCandidate =
      candidate.length > 1 && candidate.endsWith('/') ? candidate.slice(0, -1) : candidate;
    if (!trimmedCandidate.startsWith(`/mnt/${drive}/`)) {
      failSandbox('POLICY_BLOCK', `Share path traversal outside /mnt/${drive}/ is forbidden: ${rawInput}`);
    }
    return trimmedCandidate;
  }

  const slashTrimmed = trimmed.length > 1 && trimmed.endsWith('/') ? trimmed.replace(/\/+$/, '') : trimmed;
  return slashTrimmed || '/';
}

/**
 * Derives a safe `/shares/<alias>` identifier from a folder basename when user leaves alias blank.
 */
export function deriveShareAlias(normalizedLinuxPath: string): string {
  const base = posix.basename(normalizedLinuxPath);
  const cleaned = base
    .replace(/[^A-Za-z0-9_.-]+/g, '-')
    .replace(/^[^A-Za-z0-9]+/, '')
    .replace(/-+/g, '-')
    .slice(0, 48);
  return cleaned && VALID_SHARE_ALIAS_RE.test(cleaned) ? cleaned : `share-${Date.now().toString(36).slice(-4)}`;
}

export function validateShareEntry(share: AuthorizedShare): AuthorizedShare {
  const normalizedSource = normalizeSharePathInput(share.sourceLinuxPath);
  const effectiveId =
    typeof share.id === 'string' && share.id.trim() === ''
      ? `sh-${Date.now().toString(36)}`
      : share.id;
  const effectiveAlias =
    typeof share.alias === 'string' && share.alias.trim() === ''
      ? deriveShareAlias(normalizedSource)
      : share.alias;

  if (!isValidIdentifier(effectiveId) || !VALID_SHARE_ALIAS_RE.test(effectiveAlias)) {
    failSandbox('POLICY_BLOCK', `Invalid share id or alias: ${String(effectiveId)} / ${String(effectiveAlias)}`);
  }
  if (!isSafeAbsoluteLinuxPath(normalizedSource)) {
    failSandbox('POLICY_BLOCK', `Invalid share source path: ${share.sourceLinuxPath}`);
  }
  if (
    FORBIDDEN_WORKSPACE_ROOTS.has(normalizedSource) ||
    FORBIDDEN_WINDOWS_MOUNT_PATTERNS.some((re) => re.test(normalizedSource)) ||
    FORBIDDEN_CONFIG_PATH_PATTERNS.some((re) => re.test(normalizedSource)) ||
    /^\/home\/[^/]+$/.test(normalizedSource) ||
    isPathInside('/mnt/wslg/distro', normalizedSource) ||
    isPathInside('/mnt/wsl', normalizedSource) ||
    isPathInside('/run/WSL', normalizedSource) ||
    isPathInside('/etc', normalizedSource) ||
    isPathInside('/proc', normalizedSource) ||
    isPathInside('/sys', normalizedSource) ||
    isPathInside('/dev', normalizedSource) ||
    isPathInside('/root', normalizedSource) ||
    isPathInside('/boot', normalizedSource) ||
    isPathInside('/usr', normalizedSource) ||
    isPathInside('/bin', normalizedSource) ||
    isPathInside('/sbin', normalizedSource) ||
    isPathInside('/lib', normalizedSource) ||
    isPathInside('/lib64', normalizedSource) ||
    isPathInside('/var/run', normalizedSource)
  ) {
    failSandbox(
      'POLICY_BLOCK',
      `Refusing to share full drive, config/credential folder, WSL VHDX storage, or protected OS path: ${normalizedSource}`,
    );
  }
  if (share.mode !== 'ro' && share.mode !== 'rw') {
    failSandbox('POLICY_BLOCK', `Invalid share mode: ${String(share.mode)}`);
  }
  return Object.freeze({
    id: effectiveId,
    alias: effectiveAlias,
    sourceLinuxPath: normalizedSource,
    mode: share.mode,
    oneShot: Boolean(share.oneShot),
  });
}

export function validateDeviceNode(node: AuthorizedDeviceNode): AuthorizedDeviceNode {
  if (typeof node.path !== 'string' || !ALLOWED_DEVICE_RE.test(node.path)) {
    failSandbox(
      'POLICY_BLOCK',
      `Only explicit USB/serial/HID/CDC/video/SPI/I2C device nodes (/dev/ttyUSB*, /dev/ttyACM*, /dev/ttyS*, /dev/bus/usb/NNN/NNN, /dev/hidraw*, /dev/cdc-wdm*, /dev/video*, /dev/spidevX.Y, /dev/i2c-N) are allowed: ${node.path}`,
    );
  }
  return Object.freeze({ path: node.path, label: node.label });
}

export function isInternalContainerDistro(distro: string): boolean {
  return INTERNAL_DISTRO_PATTERNS.some((re) => re.test(distro));
}

export function parseWslUncPath(uncPath: string): { distribution: string; linuxPath: string } | null {
  const match = uncPath.match(/^\\\\(?:\?\\UNC\\)?(?:wsl\.localhost|wsl\$)\\([^\\]+)(.*)$/i);
  if (!match) return null;
  const distribution = match[1];
  const rest = match[2] ?? '';
  if (!distribution || !isValidDistroName(distribution)) return null;
  const linuxPath = posix.normalize('/' + rest.replace(/\\/g, '/'));
  const normalized = linuxPath.length > 1 && linuxPath.endsWith('/') ? linuxPath.slice(0, -1) : linuxPath;
  if (!isSafeAbsoluteLinuxPath(normalized)) return null;
  return { distribution, linuxPath: normalized };
}

export function validateProbeAndCreateBinding(
  probe: WslProbeResult,
  generation: number,
): SessionBinding {
  if (!probe || probe.backend !== 'wsl') {
    failSandbox('BACKEND_UNAVAILABLE', 'Target backend must be WSL 2; silent fallback to Windows is forbidden');
  }
  if (probe.wslVersion !== 2) {
    failSandbox('BACKEND_UNAVAILABLE', `WSL version ${probe.wslVersion} is unsupported; WSL 2 is required`);
  }
  if (!isValidIdentifier(probe.sessionId) || !isValidDistroName(probe.distribution)) {
    failSandbox('BACKEND_UNAVAILABLE', 'Invalid sessionId or distribution name');
  }
  if (isInternalContainerDistro(probe.distribution)) {
    failSandbox('BACKEND_UNAVAILABLE', `Refusing to bind internal container distribution: ${probe.distribution}`);
  }
  if (!Number.isSafeInteger(probe.uid) || probe.uid <= 0) {
    failSandbox('BACKEND_UNAVAILABLE', `Non-root Linux UID required (got ${probe.uid})`);
  }
  if (!isValidLinuxUsername(probe.username)) {
    failSandbox('BACKEND_UNAVAILABLE', `Invalid Linux username: ${probe.username}`);
  }
  if (probe.arch !== 'x86_64' && probe.arch !== 'aarch64') {
    failSandbox('BACKEND_UNAVAILABLE', `Unsupported Linux architecture: ${probe.arch}`);
  }
  if (!isValidIdentifier(probe.revision) || !isValidIdentifier(probe.runnerId)) {
    failSandbox('BACKEND_UNAVAILABLE', 'Invalid revision or runnerId');
  }
  if (probe.sandboxReady !== true) {
    failSandbox('SANDBOX_UNAVAILABLE', 'WSL 2 bubblewrap/seccomp probe did not pass; refusing unconfined execution');
  }
  if (probe.profile !== 'read-only' && probe.profile !== 'workspace-write') {
    failSandbox('POLICY_BLOCK', `Unsupported confined sandbox profile: ${String(probe.profile)}`);
  }

  const workspaceRoot = validateWorkspaceRoot(probe.workspaceRoot, probe.username);
  if (!isSafeAbsoluteLinuxPath(probe.cwd)) {
    failSandbox('POLICY_BLOCK', `Invalid cwd: ${probe.cwd}`);
  }
  if (probe.cwd.startsWith('/mnt/wslg/distro')) {
    failSandbox('POLICY_BLOCK', `Refusing to execute inside WSLg distro mirror: ${probe.cwd}`);
  }
  if (!isPathInside(workspaceRoot, probe.cwd)) {
    failSandbox('POLICY_BLOCK', `cwd (${probe.cwd}) must reside inside workspaceRoot (${workspaceRoot})`);
  }

  const shares: AuthorizedShare[] = [];
  const seenAliases = new Set<string>();
  for (const s of probe.authorizedShares ?? []) {
    const validated = validateShareEntry(s);
    if (seenAliases.has(validated.alias)) {
      failSandbox('POLICY_BLOCK', `Duplicate share alias: ${validated.alias}`);
    }
    seenAliases.add(validated.alias);
    shares.push(validated);
  }

  const devices: AuthorizedDeviceNode[] = [];
  const seenDevices = new Set<string>();
  for (const d of probe.authorizedDevices ?? []) {
    const validated = validateDeviceNode(d);
    if (!seenDevices.has(validated.path)) {
      seenDevices.add(validated.path);
      devices.push(validated);
    }
  }

  return Object.freeze({
    sessionId: probe.sessionId,
    backend: 'wsl',
    wslVersion: 2,
    distribution: probe.distribution,
    uid: probe.uid,
    username: probe.username,
    arch: probe.arch,
    workspaceRoot,
    cwd: probe.cwd,
    profile: probe.profile,
    revision: probe.revision,
    generation,
    runnerId: probe.runnerId,
    sandboxReady: true,
    enforcement: probe.enforcement === 'full' ? 'full' : 'partial',
    supportsDisableUserns: Boolean(probe.supportsDisableUserns),
    probedSockets: Object.freeze([...(probe.probedSockets ?? [])]),
    authorizedShares: Object.freeze(shares),
    authorizedDevices: Object.freeze(devices),
  });
}

export interface ExpectedProbeMatch {
  readonly expectedSessionId: string;
  readonly expectedDistribution: string;
  readonly expectedWorkspaceRoot: string;
  readonly expectedCwd: string;
  readonly expectedProfile: SandboxMode;
  readonly expectedRevision: string;
  readonly generation: number;
  readonly requestedWorkspaceRoot?: string;
  readonly homeDir?: string;
  readonly authorizedShares?: readonly AuthorizedShare[];
  readonly authorizedDevices?: readonly AuthorizedDeviceNode[];
}

function expandTildePath(rawPath: string, homeDir: string): string {
  if (rawPath === '~') return posix.normalize(homeDir);
  if (rawPath.startsWith('~/')) return posix.normalize(posix.join(homeDir, rawPath.slice(2)));
  return posix.normalize(rawPath);
}

export function assertVerifiedProbe(
  probe: WslProbeResult,
  expected: ExpectedProbeMatch,
): SessionBinding {
  if (probe.sessionId !== expected.expectedSessionId) {
    failSandbox('STALE_BINDING', `Probe sessionId mismatch: ${probe.sessionId} !== ${expected.expectedSessionId}`);
  }
  if (probe.distribution !== expected.expectedDistribution) {
    failSandbox('STALE_BINDING', `Probe distribution mismatch: ${probe.distribution} !== ${expected.expectedDistribution}`);
  }

  const effectiveHome = expected.homeDir ?? (probe.username ? `/home/${probe.username}` : undefined);
  const resolvedExpectedWorkspace =
    effectiveHome && (expected.expectedWorkspaceRoot === '~' || expected.expectedWorkspaceRoot.startsWith('~/'))
      ? expandTildePath(expected.expectedWorkspaceRoot, effectiveHome)
      : expected.expectedWorkspaceRoot;
  const resolvedExpectedCwd =
    effectiveHome && (expected.expectedCwd === '~' || expected.expectedCwd.startsWith('~/'))
      ? expandTildePath(expected.expectedCwd, effectiveHome)
      : expected.expectedCwd;

  if (expected.requestedWorkspaceRoot !== undefined) {
    const resolvedRequested =
      effectiveHome
        ? expandTildePath(expected.requestedWorkspaceRoot, effectiveHome)
        : posix.normalize(expected.requestedWorkspaceRoot);
    validateWorkspaceRoot(resolvedRequested, probe.username);
    if (probe.workspaceRoot !== resolvedRequested) {
      failSandbox(
        'STALE_BINDING',
        `Probe workspaceRoot mismatch against requestedWorkspaceRoot: ${probe.workspaceRoot} !== ${resolvedRequested}`,
      );
    }
  }

  if (probe.workspaceRoot !== resolvedExpectedWorkspace) {
    failSandbox('STALE_BINDING', `Probe workspaceRoot mismatch: ${probe.workspaceRoot} !== ${resolvedExpectedWorkspace}`);
  }
  if (probe.cwd !== resolvedExpectedCwd) {
    failSandbox('STALE_BINDING', `Probe cwd mismatch: ${probe.cwd} !== ${resolvedExpectedCwd}`);
  }
  if (probe.profile !== expected.expectedProfile) {
    failSandbox('STALE_BINDING', `Probe profile mismatch: ${probe.profile} !== ${expected.expectedProfile}`);
  }
  if (probe.revision !== expected.expectedRevision) {
    failSandbox('STALE_BINDING', `Probe revision mismatch: ${probe.revision} !== ${expected.expectedRevision}`);
  }
  return validateProbeAndCreateBinding(
    {
      ...probe,
      authorizedShares: expected.authorizedShares ?? probe.authorizedShares,
      authorizedDevices: expected.authorizedDevices ?? probe.authorizedDevices,
    },
    expected.generation,
  );
}
