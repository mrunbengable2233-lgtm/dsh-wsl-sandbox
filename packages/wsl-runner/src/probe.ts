import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
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
  if (lower.includes('microsoft')) {
    // WSL 1 kernels contain "Microsoft" without WSL2 standard marker
    return { isWsl: true, wslVersion: 1, kernelRelease };
  }
  return { isWsl: false, wslVersion: 0, kernelRelease };
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

  // Check --disable-userns support
  const disableCheck = spawnSync(
    'bwrap',
    [
      '--unshare-user', '--disable-userns', '--unshare-pid', '--unshare-net',
      '--ro-bind', '/', '/', '--dev', '/dev', '--proc', '/proc', '--tmpfs', '/tmp',
      '--', '/bin/true',
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
    const bpf = compileSeccompBpf({ arch, blockNetworkSockets: true });
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
    return {
      bwrapAvailable: true,
      bwrapVersion,
      supportsDisableUserns,
      functionalSelfTestPassed: ok,
      selfTestDetail: ok
        ? 'bwrap + seccomp functional probe passed'
        : `exit=${selfTest.status} stderr=${(selfTest.stderr || '').trim()}`,
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

  const probedSockets = discoverSocketsToMask(process.env);

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
    probedSockets,
    authorizedShares: params.authorizedShares ?? [],
    authorizedDevices: params.authorizedDevices ?? [],
  };
}
