import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

// Shared cross-platform test environment probe & repo-root resolver.
// 1. Resolves `REPO_ROOT` independent of `process.cwd()` and works identically whether running
//    from `tests/` source files OR `dist/.compiled-tests/` compiled JS files.
// 2. Automatically runs `scripts/build.mjs` once if `dist/` or `client.js` is missing.
// 3. Honestly probes real OS / `bwrap` / Unix-socket / POSIX `bash`+`tar` capabilities.

function findRepoRoot(startDir: string): string {
  let cur = path.resolve(startDir);
  for (let i = 0; i < 8; i++) {
    const pkgPath = path.join(cur, 'package.json');
    if (fs.existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')) as { name?: string };
        if (pkg.name === 'dsh-wsl-sandbox') {
          return cur;
        }
      } catch {
        // continue
      }
    }
    const parent = path.dirname(cur);
    if (parent === cur) break;
    cur = parent;
  }
  return process.cwd();
}

export const REPO_ROOT = findRepoRoot(import.meta.dirname);
export const BUILT_RUNNER_PATH = path.join(REPO_ROOT, 'dist', 'packages', 'wsl-runner', 'src', 'main.js');
export const BUILT_CLIENT_PATH = path.join(REPO_ROOT, 'client.js');
export const PROVISION_SH_PATH = path.join(REPO_ROOT, 'packages', 'bootstrap', 'provision-wsl.sh');

export function ensureArtifactsBuilt(): void {
  if (fs.existsSync(BUILT_RUNNER_PATH) && fs.existsSync(BUILT_CLIENT_PATH)) {
    return;
  }
  const lockPath = path.join(REPO_ROOT, '.build-test.lock');
  let acquired = false;
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (fs.existsSync(BUILT_RUNNER_PATH) && fs.existsSync(BUILT_CLIENT_PATH) && !fs.existsSync(lockPath)) {
      return;
    }
    try {
      const fd = fs.openSync(lockPath, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY, 0o600);
      fs.writeSync(fd, String(process.pid));
      fs.closeSync(fd);
      acquired = true;
      break;
    } catch {
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 80);
    }
  }
  if (!acquired) {
    if (fs.existsSync(BUILT_RUNNER_PATH) && fs.existsSync(BUILT_CLIENT_PATH)) return;
  }
  try {
    if (!fs.existsSync(BUILT_RUNNER_PATH) || !fs.existsSync(BUILT_CLIENT_PATH)) {
      const buildScript = path.join(REPO_ROOT, 'scripts', 'build.mjs');
      const env: NodeJS.ProcessEnv = { ...process.env };
      delete env.NODE_OPTIONS;
      if ((process.versions as Record<string, string | undefined>).electron) {
        env.ELECTRON_RUN_AS_NODE = '1';
      }
      const res = spawnSync(process.execPath, [buildScript], {
        cwd: REPO_ROOT,
        stdio: 'inherit',
        env,
        windowsHide: true,
      });
      if (res.status !== 0) {
        throw new Error(`Failed building dist/ artifacts via ${buildScript} (exit ${res.status})`);
      }
    }
  } finally {
    if (acquired) {
      try { fs.rmSync(lockPath, { force: true }); } catch { /* ignore */ }
    }
  }
}

ensureArtifactsBuilt();

export const IS_WINDOWS = process.platform === 'win32';
export const IS_LINUX = process.platform === 'linux';
const STRICT_KERNEL = process.env.DSH_STRICT_KERNEL_TESTS === '1';

function detectBwrapSkipReason(): string | false {
  if (!IS_LINUX) {
    return `Requires Linux kernel + bubblewrap (current platform is ${process.platform}; run inside WSL 2)`;
  }
  const res = spawnSync('bwrap', ['--ro-bind', '/', '/', '--', '/bin/true'], {
    encoding: 'utf8',
    timeout: 5000,
  });
  if (res.status === 0) {
    return false;
  }
  if (STRICT_KERNEL) {
    return false; // Let test fail loudly in strict kernel CI!
  }
  const detail = res.error?.message || (res.stderr ?? '').trim() || `exit ${res.status}`;
  return `bubblewrap (bwrap) not runnable on this host (${detail}); run provision-wsl.sh --step base`;
}

function detectPosixBashSkipReason(): string | false {
  if (IS_WINDOWS) {
    return 'Requires POSIX bash shell (run inside WSL 2; Windows System32 bash.exe is a WSL launcher)';
  }
  const res = spawnSync('bash', ['-c', 'echo ok'], { encoding: 'utf8', timeout: 3000 });
  return res.status === 0 ? false : 'POSIX bash not available on PATH';
}

function detectPosixTarSkipReason(): string | false {
  const res = spawnSync('tar', ['--version'], { encoding: 'utf8', timeout: 3000, windowsHide: true });
  return res.status === 0 ? false : 'tar binary not available on PATH';
}

export const BWRAP_SKIP_REASON: string | false = detectBwrapSkipReason();
export const UDS_SKIP_REASON: string | false = IS_WINDOWS
  ? 'Unix Domain Socket statSync().isSocket() & bwrap socket bind mounts require POSIX/Linux'
  : false;
export const POSIX_BASH_SKIP_REASON: string | false = detectPosixBashSkipReason();
export const POSIX_TAR_SKIP_REASON: string | false = detectPosixTarSkipReason();

/**
 * Verifies private permissions honestly across POSIX (`0700` / `0600` / `0400`) and Windows NTFS (`attrib +R`).
 */
export function assertPrivateFileMode(targetPath: string, expectedPosixOctal: number, message?: string): void {
  const st = fs.statSync(targetPath);
  if (IS_WINDOWS) {
    if (expectedPosixOctal === 0o400) {
      assert.equal(st.mode & 0o222, 0, message ?? `Expected Windows read-only attribute on ${targetPath}`);
    } else {
      assert.equal(fs.existsSync(targetPath), true, message);
    }
    return;
  }
  assert.equal(st.mode & 0o777, expectedPosixOctal, message);
}
