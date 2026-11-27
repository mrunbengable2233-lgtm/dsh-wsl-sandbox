import fs from 'node:fs';
import { posix } from 'node:path';
import type {
  AuthorizedDeviceNode,
  AuthorizedShare,
  NetworkMode,
  SandboxMode,
} from './binding.ts';
import {
  DANGEROUS_DIRECTORIES,
  DANGEROUS_FILES,
  scanEnvSecretFiles,
} from './dangerous-paths.ts';
import { failSandbox } from './errors.ts';

export const HIGH_RISK_SYSTEM_SOCKETS = [
  '/run/dbus/system_bus_socket',
  '/run/docker.sock',
  '/var/run/docker.sock',
  '/run/podman/podman.sock',
  '/var/run/podman/podman.sock',
  '/run/containerd/containerd.sock',
  '/var/run/containerd/containerd.sock',
  '/run/crio/crio.sock',
  '/run/k3s/containerd/containerd.sock',
] as const;

export const WSL_DISPLAY_AUDIO_PATHS = [
  '/tmp/.X11-unix',
  '/mnt/wslg/.X11-unix',
  '/mnt/wslg/PulseServer',
] as const;

export interface RlimitConfig {
  readonly nproc: number;
  readonly nofile: number;
  readonly fsizeBytes: number;
}

export const DEFAULT_RLIMITS: RlimitConfig = Object.freeze({
  nproc: 4096,
  nofile: 8192,
  fsizeBytes: 8 * 1024 * 1024 * 1024, // 8 GiB
});

export interface RootEntry {
  readonly name: string;
  readonly kind: 'dir' | 'file' | 'symlink';
  readonly linkTarget?: string;
}

export const SENSITIVE_HOME_CONFIG_DIRS = [
  '.dsh',
  '.config/dsh-wsl-sandbox',
  '.ssh',
  '.gnupg',
  '.aws',
  '.kube',
  '.docker',
  '.config/gh',
  '.claude',
  '.codex',
  '.gemini',
] as const;

export const SENSITIVE_HOME_CREDENTIAL_FILES = [
  '.git-credentials',
  '.netrc',
  '.npmrc',
  '.pypirc',
  '.bash_history',
  '.zsh_history',
  '.dsh-wsl-env.sh',
  '.cargo/credentials.toml',
  '.cargo/credentials',
  '.yarnrc.yml',
  '.gem/credentials',
] as const;

export interface BwrapBuildInput {
  readonly argv: readonly string[];
  readonly cwd: string;
  readonly workspaceRoot: string;
  readonly mode: SandboxMode;
  readonly networkMode: NetworkMode;
  readonly supportsDisableUserns: boolean;
  readonly seccompFd?: number;
  readonly env: Readonly<Record<string, string>>;
  readonly homeDir?: string;
  readonly rlimits?: Partial<RlimitConfig>;
  readonly usePrlimit?: boolean;
  readonly shares?: readonly AuthorizedShare[];
  readonly devices?: readonly AuthorizedDeviceNode[];
  readonly additionalWritableRoots?: readonly string[];
  readonly cacheDir?: string;
  readonly maskEnvSecrets?: boolean;
  readonly emptyMaskFilePath?: string;
  readonly proxySocketHostPath?: string;
  readonly extraSocketsToMask?: readonly string[];
  /** Optional custom root entries for deterministic cross-platform unit tests. */
  readonly rootEntries?: readonly RootEntry[];
  /** Optional custom path existence checker (defaults to real fs.existsSync). */
  readonly existsSync?: (p: string) => boolean;
  /** Optional custom realpath resolver (defaults to real fs.realpathSync). */
  readonly realpathSync?: (p: string) => string;
  /** Optional custom stat kind checker (defaults to real fs.lstatSync). */
  readonly lstatKind?: (p: string) => 'file' | 'dir' | 'symlink' | 'socket' | 'other' | null;
  /** Optional custom symlink-following stat kind checker (defaults to fs.statSync). */
  readonly statKind?: (p: string) => 'file' | 'dir' | 'symlink' | 'socket' | 'other' | null;
  /** Optional custom file text reader (defaults to fs.readFileSync(p, 'utf8')). */
  readonly readFileSync?: (p: string) => string;
  /** Optional pre-scanned .env* list (overrides real disk scan for deterministic unit tests). */
  readonly preScannedEnvFiles?: readonly string[];
}

export interface BwrapBuildResult {
  readonly bwrapArgs: string[];
  readonly maskedSockets: string[];
  readonly maskedConfigPaths: string[];
  readonly maskedEnvFiles: string[];
  readonly protectedPaths: string[];
  /** Nonexistent Checklist B paths where bwrap will create a 0-byte mountpoint file; caller cleans up on exit. */
  readonly createdPlaceholders: string[];
  readonly mountedDevices: string[];
  readonly enforcement: 'full' | 'partial';
}

const SKIP_TOP_LEVEL = new Set(['dev', 'proc', 'sys', 'tmp', 'run', 'mnt', 'shares']);

function readLinuxRootEntries(): RootEntry[] {
  if (process.platform !== 'linux') {
    return [
      { name: 'bin', kind: 'symlink', linkTarget: 'usr/bin' },
      { name: 'lib', kind: 'symlink', linkTarget: 'usr/lib' },
      { name: 'lib64', kind: 'symlink', linkTarget: 'usr/lib64' },
      { name: 'sbin', kind: 'symlink', linkTarget: 'usr/sbin' },
      { name: 'etc', kind: 'dir' },
      { name: 'home', kind: 'dir' },
      { name: 'opt', kind: 'dir' },
      { name: 'usr', kind: 'dir' },
      { name: 'var', kind: 'dir' },
    ];
  }
  const entries: RootEntry[] = [];
  for (const name of fs.readdirSync('/').sort()) {
    if (SKIP_TOP_LEVEL.has(name)) continue;
    const full = `/${name}`;
    try {
      const st = fs.lstatSync(full);
      if (st.isSymbolicLink()) {
        entries.push({ name, kind: 'symlink', linkTarget: fs.readlinkSync(full) });
      } else if (st.isDirectory()) {
        entries.push({ name, kind: 'dir' });
      } else if (st.isFile()) {
        entries.push({ name, kind: 'file' });
      }
    } catch {
      // Ignore unreadable root entries
    }
  }
  return entries;
}

function defaultLstatKind(p: string): 'file' | 'dir' | 'symlink' | 'socket' | 'other' | null {
  try {
    const st = fs.lstatSync(p);
    if (st.isSymbolicLink()) return 'symlink';
    if (st.isDirectory()) return 'dir';
    if (st.isFile()) return 'file';
    if (st.isSocket()) return 'socket';
    return 'other';
  } catch {
    return null;
  }
}

function defaultStatKind(p: string): 'file' | 'dir' | 'symlink' | 'socket' | 'other' | null {
  try {
    const st = fs.statSync(p);
    if (st.isDirectory()) return 'dir';
    if (st.isFile()) return 'file';
    if (st.isSocket()) return 'socket';
    return 'other';
  } catch {
    return null;
  }
}

export function discoverSocketsToMask(
  env: Readonly<Record<string, string | undefined>>,
  extraSockets: readonly string[] = [],
  realpathSync: (p: string) => string = (p) => fs.realpathSync(p),
  existsSync: (p: string) => boolean = (p) => fs.existsSync(p),
  homeDir?: string,
): string[] {
  const candidates = new Set<string>(HIGH_RISK_SYSTEM_SOCKETS);
  const xdg = env.XDG_RUNTIME_DIR;
  if (xdg && xdg.startsWith('/')) {
    candidates.add(posix.join(xdg, 'bus'));
    candidates.add(posix.join(xdg, 'systemd', 'private'));
  }
  if (env.SSH_AUTH_SOCK && env.SSH_AUTH_SOCK.startsWith('/')) {
    candidates.add(env.SSH_AUTH_SOCK);
  }
  if (env.GPG_AGENT_INFO) {
    const gpgSock = env.GPG_AGENT_INFO.split(':')[0];
    if (gpgSock && gpgSock.startsWith('/')) {
      candidates.add(gpgSock);
    }
  }
  const effectiveHome = homeDir ?? env.HOME;
  if (effectiveHome && effectiveHome.startsWith('/') && effectiveHome !== '/') {
    candidates.add(posix.join(effectiveHome, '.1password', 'agent.sock'));
    candidates.add(posix.join(effectiveHome, '.ssh', 'agent.sock'));
  }
  for (const s of extraSockets) {
    if (s.startsWith('/')) candidates.add(s);
  }

  const resolved = new Set<string>();
  for (const candidate of candidates) {
    if (!existsSync(candidate)) continue;
    try {
      const target = realpathSync(candidate);
      resolved.add(target);
      if (target !== candidate) {
        resolved.add(candidate);
      }
    } catch {
      // Fail-closed: if a high-risk socket exists but cannot be resolved, abort preparation
      failSandbox('SANDBOX_PREPARATION_FAILED', `Failed to resolve high-risk socket for masking: ${candidate}`);
    }
  }

  return Array.from(resolved).sort();
}

export function buildBwrapArgs(input: BwrapBuildInput): BwrapBuildResult {
  if (!input.argv || input.argv.length === 0) {
    failSandbox('INVALID_ACTION', 'bwrap argv must be non-empty');
  }
  if (input.cwd.startsWith('/mnt/wslg/distro') || input.workspaceRoot.startsWith('/mnt/wslg/distro')) {
    failSandbox('POLICY_BLOCK', 'Refusing to launch bwrap under /mnt/wslg/distro');
  }

  const exists = input.existsSync ?? ((p: string) => fs.existsSync(p));
  const realpath = input.realpathSync ?? ((p: string) => fs.realpathSync(p));
  const lstatKind = input.lstatKind ?? defaultLstatKind;
  const statKind = input.statKind ?? ((p: string): 'file' | 'dir' | 'symlink' | 'socket' | 'other' | null => {
    if (input.lstatKind) {
      const lk = input.lstatKind(p);
      if (lk === 'symlink') {
        try {
          const rp = realpath(p);
          if (rp !== p) return input.lstatKind(rp);
        } catch {
          return null;
        }
      }
      return lk;
    }
    return defaultStatKind(p);
  });
  const rootEntries = input.rootEntries ?? readLinuxRootEntries();
  const emptyMask = input.emptyMaskFilePath ?? '/dev/null';
  const effectiveHome = input.homeDir ?? input.env.HOME;

  const args: string[] = [];

  // 1. Namespace & terminal isolation
  args.push('--unshare-user');
  if (input.supportsDisableUserns) {
    args.push('--disable-userns');
  }
  args.push('--unshare-pid', '--unshare-ipc', '--unshare-net', '--new-session', '--die-with-parent');

  // 2. Clean environment inside sandbox
  args.push('--clearenv');
  for (const [k, v] of Object.entries(input.env)) {
    if (k.includes('\0') || v.includes('\0')) continue;
    args.push('--setenv', k, v);
  }

  // 3. Base read-only root built over bwrap's fresh tmpfs `/`, enabling clean `/shares`
  //    and atomic tmpfs masking of `/run` (hiding /run/WSL, dbus, docker/podman/containerd/k3s)
  //    and `/mnt` (hiding /mnt/c, /mnt/wsl, /mnt/wslg/distro, WSLg X11/PulseAudio).
  for (const entry of rootEntries) {
    if (SKIP_TOP_LEVEL.has(entry.name)) continue;
    const full = `/${entry.name}`;
    if (entry.kind === 'symlink' && entry.linkTarget) {
      args.push('--symlink', entry.linkTarget, full);
    } else {
      args.push('--ro-bind', full, full);
    }
  }

  args.push('--dev', '/dev');
  args.push('--proc', '/proc');
  if (lstatKind('/sys') === 'dir') {
    args.push('--ro-bind', '/sys', '/sys');
  }
  args.push('--tmpfs', '/tmp');
  args.push('--tmpfs', '/var/tmp');
  args.push('--tmpfs', '/run');
  args.push('--tmpfs', '/mnt');

  // NixOS-WSL compatibility: keep /run/current-system accessible after masking /run
  if (lstatKind('/run/current-system') !== null) {
    args.push('--ro-bind', '/run/current-system', '/run/current-system');
  }

  // /etc/resolv.conf dangling symlink fix: keep /run & /mnt completely empty while binding
  // resolved resolv.conf in allowlist-proxy mode, or masking empty in offline mode.
  const resolvKind = lstatKind('/etc/resolv.conf');
  if (input.networkMode === 'offline') {
    if (resolvKind === 'file' || resolvKind === 'symlink') {
      args.push('--ro-bind', emptyMask, '/etc/resolv.conf');
    }
  } else if (resolvKind === 'file' || resolvKind === 'symlink' || exists('/etc/resolv.conf')) {
    try {
      const resolvedResolv = realpath('/etc/resolv.conf');
      if (resolvedResolv !== '/etc/resolv.conf' && exists(resolvedResolv)) {
        args.push('--ro-bind', resolvedResolv, '/etc/resolv.conf');
      }
    } catch {
      // Ignore broken/unresolvable host /etc/resolv.conf
    }
  }

  // 4. Mask any extra non-/run, non-/tmp, non-/mnt high-risk sockets (e.g. custom SSH_AUTH_SOCK, agent.sock)
  const maskedSockets = discoverSocketsToMask(
    { ...process.env, ...input.env },
    input.extraSocketsToMask ?? [],
    realpath,
    exists,
    effectiveHome,
  );
  for (const sock of maskedSockets) {
    if (
      sock.startsWith('/tmp/') ||
      sock.startsWith('/mnt/') ||
      sock.startsWith('/run/') ||
      sock.startsWith('/var/run/')
    ) {
      continue; // already hidden under fresh empty tmpfs
    }
    args.push('--ro-bind', emptyMask, sock);
  }

  // 4b. Mask private user config & credential directories under $HOME (including symlinked dirs/files)
  //     so sandboxed AI has ZERO read/write access to plugin config/backups or host credentials.
  const maskedConfigPaths: string[] = [];
  if (effectiveHome && effectiveHome.startsWith('/') && effectiveHome !== '/') {
    const isHiddenTmpfs = (p: string): boolean =>
      p.startsWith('/tmp/') ||
      p.startsWith('/var/tmp/') ||
      p.startsWith('/run/') ||
      p.startsWith('/var/run/') ||
      p.startsWith('/mnt/');
    const overlapsWorkspaceOrCache = (p: string): boolean =>
      input.workspaceRoot === p ||
      input.workspaceRoot.startsWith(p + '/') ||
      (Boolean(input.cacheDir) && (input.cacheDir === p || input.cacheDir!.startsWith(p + '/')));

    for (const relDir of SENSITIVE_HOME_CONFIG_DIRS) {
      const target = posix.join(effectiveHome, relDir);
      if (overlapsWorkspaceOrCache(target)) continue;
      if (!exists(target) || statKind(target) !== 'dir') continue;

      let resolved = target;
      try {
        resolved = realpath(target);
      } catch {
        resolved = target;
      }

      if (lstatKind(target) === 'symlink' && resolved !== target) {
        if (
          !overlapsWorkspaceOrCache(resolved) &&
          resolved !== '/' &&
          resolved !== effectiveHome &&
          !isHiddenTmpfs(resolved)
        ) {
          args.push('--tmpfs', resolved, '--remount-ro', resolved);
          maskedConfigPaths.push(resolved);
        }
        maskedConfigPaths.push(target);
      } else {
        args.push('--tmpfs', target, '--remount-ro', target);
        maskedConfigPaths.push(target);
      }
    }

    for (const relFile of SENSITIVE_HOME_CREDENTIAL_FILES) {
      const target = posix.join(effectiveHome, relFile);
      if (!exists(target) || statKind(target) !== 'file') continue;

      let resolved = target;
      try {
        resolved = realpath(target);
      } catch {
        resolved = target;
      }

      if (lstatKind(target) === 'symlink' && resolved !== target) {
        if (
          !overlapsWorkspaceOrCache(resolved) &&
          resolved !== '/' &&
          resolved !== effectiveHome &&
          resolved !== '/dev/null' &&
          resolved !== emptyMask &&
          !isHiddenTmpfs(resolved)
        ) {
          args.push('--ro-bind', emptyMask, resolved);
          maskedConfigPaths.push(resolved);
        }
        maskedConfigPaths.push(target);
      } else {
        args.push('--ro-bind', emptyMask, target);
        maskedConfigPaths.push(target);
      }
    }
  }

  // 5. Controlled UDS proxy socket mount inside private `/run/dsh-proxy`
  if (input.networkMode === 'allowlist-proxy' && input.proxySocketHostPath) {
    if (!exists(input.proxySocketHostPath)) {
      failSandbox('SANDBOX_PREPARATION_FAILED', `UDS proxy socket not found: ${input.proxySocketHostPath}`);
    }
    args.push('--tmpfs', '/run/dsh-proxy');
    args.push('--bind', input.proxySocketHostPath, '/run/dsh-proxy/proxy.sock');
  }

  // 6. Advanced human-authorized shares mapped ONLY to `/shares/<alias>`
  if (input.shares && input.shares.length > 0) {
    args.push('--tmpfs', '/shares');
    for (const share of input.shares) {
      const dest = `/shares/${share.alias}`;
      const mountFlag = share.mode === 'rw' && input.mode === 'workspace-write' ? '--bind' : '--ro-bind';
      args.push(mountFlag, share.sourceLinuxPath, dest);
    }
  }

  // Lock `/` itself read-only after creating top-level mountpoints (`/shares`, `/run`, `/mnt`, etc.)
  args.push('--remount-ro', '/');

  // 7. Workspace & isolated cache (workspace-write rw; read-only always binds workspaceRoot ro)
  if (input.mode === 'workspace-write') {
    args.push('--bind', input.workspaceRoot, input.workspaceRoot);

    for (const extraRoot of input.additionalWritableRoots ?? []) {
      const kind = statKind(extraRoot);
      if (kind !== 'dir') {
        failSandbox('SANDBOX_PREPARATION_FAILED', `additionalWritableRoot must be a physical directory: ${extraRoot}`);
      }
      args.push('--bind', extraRoot, extraRoot);
    }

    if (input.cacheDir) {
      args.push('--bind', input.cacheDir, input.cacheDir);
    }
  } else {
    args.push('--ro-bind', input.workspaceRoot, input.workspaceRoot);
  }

  // 8. Checklist B: Workspace-internal read-only locks (applied AFTER --bind workspaceRoot!)
  const protectedPaths: string[] = [];
  const createdPlaceholders: string[] = [];
  if (input.mode === 'workspace-write') {
    // Git worktree / submodule `.git` file + optional `gitdir:` target inside workspaceRoot
    const dotGitPath = posix.join(input.workspaceRoot, '.git');
    if (lstatKind(dotGitPath) === 'file') {
      if (exists(dotGitPath)) {
        args.push('--ro-bind', dotGitPath, dotGitPath);
        protectedPaths.push(dotGitPath);
        try {
          const readText = input.readFileSync ?? ((p: string) => fs.readFileSync(p, 'utf8'));
          const content = readText(dotGitPath);
          const m = content.match(/^gitdir:\s*(.+)$/im);
          if (m && m[1]) {
            const rawGitDir = m[1].trim();
            const resolvedGitDir = rawGitDir.startsWith('/')
              ? posix.normalize(rawGitDir)
              : posix.normalize(posix.join(input.workspaceRoot, rawGitDir));
            const normRoot = posix.normalize(input.workspaceRoot);
            if (
              (resolvedGitDir === normRoot || resolvedGitDir.startsWith(normRoot + '/')) &&
              resolvedGitDir !== normRoot &&
              exists(resolvedGitDir)
            ) {
              args.push('--ro-bind', resolvedGitDir, resolvedGitDir);
              protectedPaths.push(resolvedGitDir);
            }
          }
        } catch {
          // Ignore unreadable .git file in unit tests using virtual lstatKind
        }
      } else {
        args.push('--ro-bind', emptyMask, dotGitPath);
        protectedPaths.push(dotGitPath);
      }
    }

    for (const relFile of DANGEROUS_FILES) {
      const target = posix.join(input.workspaceRoot, relFile);
      const kind = lstatKind(target);
      if (kind !== null) {
        if (exists(target)) {
          args.push('--ro-bind', target, target);
        } else {
          // Broken symlink -> mask with emptyMask instead of crashing bwrap
          args.push('--ro-bind', emptyMask, target);
        }
        protectedPaths.push(target);
      } else {
        // Non-existent dangerous file: bind emptyMask read-only to prevent in-sandbox creation!
        args.push('--ro-bind', emptyMask, target);
        protectedPaths.push(target);
        createdPlaceholders.push(target);
      }
    }

    for (const relDirOrFile of DANGEROUS_DIRECTORIES) {
      const target = posix.join(input.workspaceRoot, relDirOrFile);
      const parentDir = posix.dirname(target);
      const kind = lstatKind(target);
      if (kind !== null) {
        if (exists(target)) {
          args.push('--ro-bind', target, target);
        } else {
          args.push('--ro-bind', emptyMask, target);
        }
        protectedPaths.push(target);
      } else if (lstatKind(parentDir) === 'dir') {
        // Parent exists (e.g. .git exists, .git/hooks missing): block creation with read-only placeholder
        args.push('--ro-bind', emptyMask, target);
        protectedPaths.push(target);
        createdPlaceholders.push(target);
      }
    }
  }

  // 9. Depth-limited .env* secret read masking (applies in BOTH read-only and workspace-write)
  const maskedEnvFiles: string[] = [];
  if (input.maskEnvSecrets !== false) {
    const envFiles = input.preScannedEnvFiles
      ? [...input.preScannedEnvFiles]
      : scanEnvSecretFiles(input.workspaceRoot);
    for (const envFile of envFiles) {
      args.push('--ro-bind', emptyMask, envFile);
      maskedEnvFiles.push(envFile);
    }
  }

  // 10. Advanced physical device passthrough (ONLY human-explicit single nodes)
  const mountedDevices: string[] = [];
  for (const dev of input.devices ?? []) {
    if (!exists(dev.path)) {
      failSandbox('SANDBOX_PREPARATION_FAILED', `Authorized physical device node not found: ${dev.path}`);
    }
    args.push('--dev-bind', dev.path, dev.path);
    mountedDevices.push(dev.path);
  }

  // 11. Seccomp BPF fd
  if (input.seccompFd !== undefined) {
    args.push('--seccomp', String(input.seccompFd));
  }

  // 12. Working directory
  args.push('--chdir', input.cwd);
  args.push('--');

  // 13. Optional prlimit resource caps (nsjail-inspired fork-bomb & disk-fill defense)
  if (input.usePrlimit !== false) {
    const rl: RlimitConfig = {
      nproc: input.rlimits?.nproc ?? DEFAULT_RLIMITS.nproc,
      nofile: input.rlimits?.nofile ?? DEFAULT_RLIMITS.nofile,
      fsizeBytes: input.rlimits?.fsizeBytes ?? DEFAULT_RLIMITS.fsizeBytes,
    };
    args.push(
      'prlimit',
      `--nproc=${rl.nproc}`,
      `--nofile=${rl.nofile}`,
      `--fsize=${rl.fsizeBytes}`,
      '--',
    );
  }

  args.push(...input.argv);

  return {
    bwrapArgs: args,
    maskedSockets,
    maskedConfigPaths,
    maskedEnvFiles,
    protectedPaths,
    createdPlaceholders,
    mountedDevices,
    enforcement: input.seccompFd !== undefined && input.supportsDisableUserns ? 'full' : 'partial',
  };
}
