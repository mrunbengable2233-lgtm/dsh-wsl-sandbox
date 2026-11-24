import { posix } from 'node:path';
import { failSandbox } from './errors.ts';

export type SandboxMode = 'read-only' | 'workspace-write';
export type NetworkMode = 'allowlist-proxy' | 'offline';
export type CacheMode = 'workspace-persistent' | 'ephemeral-tmp';
export type ApprovalPolicyMode = 'balanced' | 'strict' | 'trust-workspace';
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
const VALID_SHARE_ALIAS_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
const ALLOWED_DEVICE_RE = /^\/dev\/(ttyUSB\d+|ttyACM\d+|ttyS\d+|bus\/usb\/\d{3}\/\d{3})$/;

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
]);

const FORBIDDEN_WORKSPACE_PREFIXES = [
  '/dev/',
  '/etc/',
  '/mnt/',
  '/proc/',
  '/run/',
  '/sys/',
];

export function isValidIdentifier(value: unknown): value is string {
  return typeof value === 'string' && VALID_ID_RE.test(value);
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
  if (username && (linuxPath === `/home/${username}` || linuxPath === '/root')) {
    failSandbox('POLICY_BLOCK', `Entire user home directory cannot be mounted as workspaceRoot: ${linuxPath}`);
  }
  return linuxPath;
}

export function validateShareEntry(share: AuthorizedShare): AuthorizedShare {
  if (!isValidIdentifier(share.id) || !VALID_SHARE_ALIAS_RE.test(share.alias)) {
    failSandbox('POLICY_BLOCK', `Invalid share id or alias: ${share.id} / ${share.alias}`);
  }
  if (!isSafeAbsoluteLinuxPath(share.sourceLinuxPath)) {
    failSandbox('POLICY_BLOCK', `Invalid share source path: ${share.sourceLinuxPath}`);
  }
  if (
    FORBIDDEN_WORKSPACE_ROOTS.has(share.sourceLinuxPath) ||
    /^\/mnt\/[a-zA-Z]$/.test(share.sourceLinuxPath) ||
    share.sourceLinuxPath.startsWith('/mnt/wslg/distro') ||
    share.sourceLinuxPath.startsWith('/run/WSL') ||
    share.sourceLinuxPath.startsWith('/etc') ||
    share.sourceLinuxPath.startsWith('/proc') ||
    share.sourceLinuxPath.startsWith('/sys')
  ) {
    failSandbox('POLICY_BLOCK', `Refusing to share full drive or protected path: ${share.sourceLinuxPath}`);
  }
  if (share.mode !== 'ro' && share.mode !== 'rw') {
    failSandbox('POLICY_BLOCK', `Invalid share mode: ${String(share.mode)}`);
  }
  return Object.freeze({
    id: share.id,
    alias: share.alias,
    sourceLinuxPath: share.sourceLinuxPath,
    mode: share.mode,
    oneShot: Boolean(share.oneShot),
  });
}

export function validateDeviceNode(node: AuthorizedDeviceNode): AuthorizedDeviceNode {
  if (typeof node.path !== 'string' || !ALLOWED_DEVICE_RE.test(node.path)) {
    failSandbox(
      'POLICY_BLOCK',
      `Only explicit serial/USB device nodes (/dev/ttyUSB*, /dev/ttyACM*, /dev/bus/usb/NNN/NNN) are allowed: ${node.path}`,
    );
  }
  return Object.freeze({ path: node.path, label: node.label });
}

export function isInternalContainerDistro(distro: string): boolean {
  return INTERNAL_DISTRO_PATTERNS.some((re) => re.test(distro));
}

export function parseWslUncPath(uncPath: string): { distribution: string; linuxPath: string } | null {
  const match = uncPath.match(/^\\\\(?:wsl\.localhost|wsl\$)\\([^\\]+)(.*)$/i);
  if (!match) return null;
  const distribution = match[1];
  const rest = match[2] ?? '';
  if (!distribution || !isValidIdentifier(distribution)) return null;
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
  if (!isValidIdentifier(probe.sessionId) || !isValidIdentifier(probe.distribution)) {
    failSandbox('BACKEND_UNAVAILABLE', 'Invalid sessionId or distribution name');
  }
  if (isInternalContainerDistro(probe.distribution)) {
    failSandbox('BACKEND_UNAVAILABLE', `Refusing to bind internal container distribution: ${probe.distribution}`);
  }
  if (!Number.isSafeInteger(probe.uid) || probe.uid <= 0) {
    failSandbox('BACKEND_UNAVAILABLE', `Non-root Linux UID required (got ${probe.uid})`);
  }
  if (!isValidIdentifier(probe.username)) {
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
  readonly authorizedShares?: readonly AuthorizedShare[];
  readonly authorizedDevices?: readonly AuthorizedDeviceNode[];
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
  if (probe.workspaceRoot !== expected.expectedWorkspaceRoot) {
    failSandbox('STALE_BINDING', `Probe workspaceRoot mismatch: ${probe.workspaceRoot} !== ${expected.expectedWorkspaceRoot}`);
  }
  if (probe.cwd !== expected.expectedCwd) {
    failSandbox('STALE_BINDING', `Probe cwd mismatch: ${probe.cwd} !== ${expected.expectedCwd}`);
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
