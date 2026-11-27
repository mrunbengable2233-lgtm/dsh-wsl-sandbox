import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { posix } from 'node:path';
import {
  compileSeccompBpf,
  discoverSocketsToMask,
  failSandbox,
  isPathInside,
  type LinuxArch,
  type ProbeParams,
  validateWorkspaceRoot,
  type WslProbeResult,
} from '../../core/src/index.ts';

function findExecutable(name: string): string | undefined {
  if (!name) return undefined;
  if (name.includes('/')) {
    try {
      const st = fs.statSync(name);
      if (st.isFile()) {
        fs.accessSync(name, fs.constants.X_OK);
        return name;
      }
    } catch {
      return undefined;
    }
    return undefined;
  }
  const pathEnv =
    process.env.PATH ||
    '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/run/current-system/sw/bin';
  for (const dir of pathEnv.split(path.delimiter)) {
    if (!dir) continue;
    const candidate = path.join(dir, name);
    try {
      const st = fs.statSync(candidate);
      if (st.isFile()) {
        fs.accessSync(candidate, fs.constants.X_OK);
        return candidate;
      }
    } catch {
      // continue searching
    }
  }
  return undefined;
}

export function detectLinuxArch(): LinuxArch {
  if (process.arch === 'x64') return 'x86_64';
  if (process.arch === 'arm64') return 'aarch64';
  failSandbox('BACKEND_UNAVAILABLE', `Unsupported CPU architecture for seccomp-bpf: ${process.arch}`);
}

export function detectWslKernelVersion(): { isWsl: boolean; wslVersion: number; kernelRelease: string } {
  const kernelRelease = os.release();
  let procVersion = kernelRelease;
  try {
    procVersion = fs.readFileSync('/proc/version', 'utf8');
  } catch {
    // Fallback to os.release()
  }
  const lower = procVersion.toLowerCase();
  if (lower.includes('wsl2') || lower.includes('microsoft-standard-wsl2')) {
    return { isWsl: true, wslVersion: 2, kernelRelease };
  }
  // WSL 2 kernels always expose `/run/WSL` and/or `/dev/dxg` even on custom builds without standard marker
  if (fs.existsSync('/run/WSL') || fs.existsSync('/dev/dxg')) {
    return { isWsl: true, wslVersion: 2, kernelRelease };
  }
  if (lower.includes('microsoft')) {
    // WSL 1 kernels contain "Microsoft" without WSL2 markers
    return { isWsl: true, wslVersion: 1, kernelRelease };
  }
  return { isWsl: false, wslVersion: 0, kernelRelease };
}

function formatUsernsDiagnostics(stderr: string): string {
  const lower = stderr.toLowerCase();
  if (
    lower.includes('apparmor') ||
    lower.includes('operation not permitted') ||
    lower.includes('setting up uid map') ||
    lower.includes('permission denied') ||
    lower.includes('userns')
  ) {
    return `${stderr.trim()} (hint: check sysctl kernel.apparmor_restrict_unprivileged_userns / Ubuntu 24.04 AppArmor bwrap profile)`;
  }
  return stderr.trim();
}

export function probeBwrapCapabilities(arch: LinuxArch): {
  readonly bwrapAvailable: boolean;
  readonly bwrapVersion?: string;
  readonly supportsDisableUserns: boolean;
  readonly functionalSelfTestPassed: boolean;
  readonly selfTestDetail: string;
} {
  const verRes = spawnSync('bwrap', ['--version'], { encoding: 'utf8', timeout: 5000 });
  if (verRes.error || verRes.status !== 0) {
    return {
      bwrapAvailable: false,
      supportsDisableUserns: false,
      functionalSelfTestPassed: false,
      selfTestDetail: verRes.error ? verRes.error.message : (verRes.stderr || 'bwrap not found').trim(),
    };
  }
  const bwrapVersion = (verRes.stdout || '').trim();

  // Check --disable-userns support using portable `sh -c :` instead of `/bin/true`
  const disableCheck = spawnSync(
    'bwrap',
    [
      '--unshare-user', '--disable-userns', '--unshare-pid', '--unshare-net',
      '--ro-bind', '/', '/', '--dev', '/dev', '--proc', '/proc', '--tmpfs', '/tmp',
      '--', 'sh', '-c', ':',
    ],
    { encoding: 'utf8', timeout: 5000 },
  );
  const supportsDisableUserns = disableCheck.status === 0;

  // Functional bwrap + seccomp self-test:
  // 1) private /tmp write must SUCCEED
  // 2) read-only /etc write must FAIL (EROFS)
  // 3) seccomp filter loads and allows normal execution
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-wsl-probe-'));
  const bpfPath = path.join(tmpDir, 'probe.bpf');
  let bpfFd: number | undefined;
  try {
    fs.chmodSync(tmpDir, 0o700);
    const bpf = compileSeccompBpf({
      arch,
      blockNetworkSockets: true,
      blockUsernsClone: !supportsDisableUserns,
    });
    fs.writeFileSync(bpfPath, bpf, { mode: 0o600 });
    bpfFd = fs.openSync(bpfPath, 'r');

    const args = ['--unshare-user'];
    if (supportsDisableUserns) args.push('--disable-userns');
    args.push(
      '--unshare-pid', '--unshare-ipc', '--unshare-net', '--new-session', '--die-with-parent',
      '--ro-bind', '/', '/', '--dev', '/dev', '--proc', '/proc', '--tmpfs', '/tmp',
      '--seccomp', '3',
      '--',
      '/bin/sh', '-c',
      'echo ok > /tmp/probe_ok && ! (touch /etc/.dsh_probe_ro 2>/dev/null) && echo SELF_TEST_OK',
    );

    const selfTest = spawnSync('bwrap', args, {
      encoding: 'utf8',
      timeout: 8000,
      stdio: ['ignore', 'pipe', 'pipe', bpfFd],
    });
    const ok = selfTest.status === 0 && (selfTest.stdout || '').includes('SELF_TEST_OK');
    const combinedErr = `${disableCheck.stderr || ''}\n${selfTest.stderr || ''}`;
    return {
      bwrapAvailable: true,
      bwrapVersion,
      supportsDisableUserns,
      functionalSelfTestPassed: ok,
      selfTestDetail: ok
        ? 'bwrap + seccomp functional probe passed'
        : `exit=${selfTest.status} stderr=${formatUsernsDiagnostics(combinedErr)}`,
    };
  } catch (err) {
    return {
      bwrapAvailable: true,
      bwrapVersion,
      supportsDisableUserns,
      functionalSelfTestPassed: false,
      selfTestDetail: err instanceof Error ? err.message : String(err),
    };
  } finally {
    if (bpfFd !== undefined) {
      try { fs.closeSync(bpfFd); } catch { /* ignore */ }
    }
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

export function runEnvironmentProbe(params: ProbeParams, runnerId: string = randomUUID()): WslProbeResult {
  const uid = typeof process.getuid === 'function' ? process.getuid() : -1;
  if (uid <= 0) {
    failSandbox('BACKEND_UNAVAILABLE', `Refusing to run sandbox runner as root or unknown UID (${uid})`);
  }

  const username = os.userInfo().username;
  const homeDir = os.homedir() || `/home/${username}`;
  const arch = detectLinuxArch();
  const kernel = detectWslKernelVersion();

  let effectiveWslVersion = kernel.wslVersion;
  if (!kernel.isWsl) {
    if (params.allowLinuxDevMode) {
      effectiveWslVersion = 2;
    } else {
      failSandbox(
        'BACKEND_UNAVAILABLE',
        `Expected WSL 2 Linux kernel, got native kernel "${kernel.kernelRelease}"`,
      );
    }
  } else if (kernel.wslVersion !== 2) {
    failSandbox('BACKEND_UNAVAILABLE', `WSL ${kernel.wslVersion} is not supported; upgrade distro to WSL 2`);
  }

  // Validate requested workspaceRoot syntax first, then create missing workspace directory if ENOENT (never follow broken symlink)
  const normalizedRequestedWs = posix.normalize(params.workspaceRoot);
  validateWorkspaceRoot(normalizedRequestedWs, username);
  let wsStat: fs.Stats | null = null;
  try {
    wsStat = fs.lstatSync(params.workspaceRoot);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      try {
        fs.mkdirSync(params.workspaceRoot, { recursive: true, mode: 0o755 });
      } catch (mkErr) {
        failSandbox(
          'POLICY_BLOCK',
          `Failed to initialize workspaceRoot in Linux distro: ${mkErr instanceof Error ? mkErr.message : String(mkErr)}`,
        );
      }
    }
  }
  if (wsStat?.isSymbolicLink() && !fs.existsSync(params.workspaceRoot)) {
    failSandbox('POLICY_BLOCK', `workspaceRoot is a dangling symlink: ${params.workspaceRoot}`);
  }

  // Canonicalize and verify workspaceRoot & cwd inside target Linux filesystem
  let canonicalWorkspace: string;
  let canonicalCwd: string;
  try {
    canonicalWorkspace = fs.realpathSync(params.workspaceRoot);
    canonicalCwd = fs.realpathSync(params.cwd);
  } catch (err) {
    failSandbox(
      'POLICY_BLOCK',
      `Failed to resolve workspaceRoot/cwd in Linux distro: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  validateWorkspaceRoot(canonicalWorkspace, username);
  if (!isPathInside(canonicalWorkspace, canonicalCwd)) {
    failSandbox('POLICY_BLOCK', `Canonical cwd (${canonicalCwd}) escapes canonical workspaceRoot (${canonicalWorkspace})`);
  }
  if (canonicalCwd.startsWith('/mnt/wslg/distro') || canonicalWorkspace.startsWith('/mnt/wslg/distro')) {
    failSandbox('POLICY_BLOCK', 'Workspace or cwd cannot reside inside /mnt/wslg/distro');
  }

  const bwrap = probeBwrapCapabilities(arch);
  if (!bwrap.bwrapAvailable || !bwrap.functionalSelfTestPassed) {
    failSandbox('SANDBOX_UNAVAILABLE', `bwrap/seccomp self-test failed: ${bwrap.selfTestDetail}`);
  }

  const hasPrlimit = Boolean(findExecutable('prlimit'));
  const probedSockets = discoverSocketsToMask(process.env, [], undefined, undefined, homeDir);

  return {
    sessionId: params.sessionId,
    backend: 'wsl',
    wslVersion: effectiveWslVersion,
    distribution: params.distribution,
    uid,
    username,
    arch,
    workspaceRoot: canonicalWorkspace,
    cwd: canonicalCwd,
    profile: params.profile,
    revision: params.revision,
    runnerId,
    sandboxReady: true,
    enforcement: bwrap.supportsDisableUserns ? 'full' : 'partial',
    bwrapVersion: bwrap.bwrapVersion,
    supportsDisableUserns: bwrap.supportsDisableUserns,
    hasPrlimit,
    requestedWorkspaceRoot: params.workspaceRoot,
    homeDir,
    probedSockets,
    authorizedShares: params.authorizedShares ?? [],
    authorizedDevices: params.authorizedDevices ?? [],
  };
}
