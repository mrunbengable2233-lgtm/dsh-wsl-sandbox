import { type ChildProcess, spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { posix } from 'node:path';
import {
  buildBwrapArgs,
  type CollectedStream,
  compileSeccompBpf,
  failSandbox,
  isPathInside,
  type ProcExecParams,
  type ProcExecResult,
  sanitizeSandboxEnv,
  type SessionBinding,
} from '../../core/src/index.ts';
import { resolveEphemeralRamTmpRoot } from './hygiene.ts';

const DEFAULT_TIMEOUT_MS = 120_000;
const DEFAULT_GRACE_MS = 2_000;
const DEFAULT_MAX_OUTPUT_BYTES = 256 * 1024;
const MAX_COLLECTOR_OUTPUT_BYTES = 4 * 1024 * 1024;

function findExecutableInHost(candidates: readonly string[], commandName: string): string | undefined {
  for (const candidate of candidates) {
    try {
      const st = fs.statSync(candidate);
      if (st.isFile()) {
        fs.accessSync(candidate, fs.constants.X_OK);
        return candidate;
      }
    } catch {
      // continue
    }
  }
  const pathEnv =
    process.env.PATH ||
    '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/run/current-system/sw/bin';
  for (const dir of pathEnv.split(path.delimiter)) {
    if (!dir) continue;
    const candidate = path.join(dir, commandName);
    try {
      const st = fs.statSync(candidate);
      if (st.isFile()) {
        fs.accessSync(candidate, fs.constants.X_OK);
        return candidate;
      }
    } catch {
      // continue
    }
  }
  return undefined;
}

function resolveBashExecutable(): string {
  return (
    findExecutableInHost(
      ['/bin/bash', '/usr/bin/bash', '/usr/local/bin/bash', '/run/current-system/sw/bin/bash'],
      'bash',
    ) ?? '/bin/bash'
  );
}

function hasPrlimitBinary(): boolean {
  return Boolean(
    findExecutableInHost(['/usr/bin/prlimit', '/bin/prlimit', '/run/current-system/sw/bin/prlimit'], 'prlimit'),
  );
}

function resolveExecutionCwd(binding: SessionBinding, requestedCwd: string): {
  readonly bwrapCwd: string;
  readonly hostSpawnCwd: string;
} {
  if (!requestedCwd || requestedCwd.includes('\0')) {
    failSandbox('POLICY_BLOCK', `Invalid working directory: ${String(requestedCwd)}`);
  }
  const normReq = posix.normalize(requestedCwd.replace(/\\/g, '/'));
  if (normReq === '/shares' || normReq.startsWith('/shares/')) {
    const parts = normReq.split('/').filter(Boolean);
    const alias = parts[1];
    const share = binding.authorizedShares.find((s) => s.alias === alias);
    if (!share) {
      failSandbox('POLICY_BLOCK', `Unauthorized share cwd: ${requestedCwd}`);
    }
    const shareRootReal = fs.realpathSync(share.sourceLinuxPath).replace(/\\/g, '/');
    const subRel = parts.slice(2).join('/');
    const candidate = subRel ? posix.join(shareRootReal, subRel) : shareRootReal;
    let hostDirReal: string;
    try {
      hostDirReal = fs.realpathSync(candidate).replace(/\\/g, '/');
    } catch (err) {
      failSandbox(
        'POLICY_BLOCK',
        `Failed to resolve share cwd (${requestedCwd}): ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    if (!isPathInside(shareRootReal, hostDirReal)) {
      failSandbox('POLICY_BLOCK', `Share cwd escapes share root: ${requestedCwd} -> ${hostDirReal}`);
    }
    return { bwrapCwd: normReq, hostSpawnCwd: hostDirReal };
  }

  let wsReal: string;
  let cwdReal: string;
  try {
    wsReal = fs.realpathSync(binding.workspaceRoot).replace(/\\/g, '/');
    cwdReal = fs.realpathSync(normReq).replace(/\\/g, '/');
  } catch (err) {
    failSandbox(
      'POLICY_BLOCK',
      `Failed to resolve cwd (${requestedCwd}): ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (!isPathInside(wsReal, cwdReal)) {
    failSandbox('POLICY_BLOCK', `cwd escapes workspaceRoot (${wsReal}): ${requestedCwd} -> ${cwdReal}`);
  }
  return { bwrapCwd: cwdReal, hostSpawnCwd: cwdReal };
}

const DENIAL_SIGNATURES = [
  'read-only file system',
  'erofs',
  'permission denied',
  'operation not permitted',
  'network is unreachable',
  'dsh wsl sandbox proxy blocked',
] as const;

const RUNNER_FAILURE_SIGNATURES = [
  'bwrap:',
  'setting up uid map',
  'creating new namespace failed',
  'execvp',
] as const;

interface ActiveProc {
  readonly execId: string;
  readonly sessionId: string;
  readonly terminalId?: string;
  readonly generation: number;
  readonly pgid: number | undefined;
  readonly child: ChildProcess;
  readonly killGroup: () => Promise<void>;
  readonly killGroupSync: () => void;
}

class BoundedStreamCollector {
  private readonly maxBytes: number;
  private chunks: Buffer[] = [];
  private headIdx = 0;
  private keptBytes = 0;
  private totalBytes = 0;
  private truncated = false;
  private finishedResult: CollectedStream | undefined;

  constructor(maxBytes: number) {
    this.maxBytes = Math.min(MAX_COLLECTOR_OUTPUT_BYTES, Math.max(1024, maxBytes));
  }

  push(chunk: Buffer): void {
    this.totalBytes += chunk.length;
    if (chunk.length === 0) return;

    if (chunk.length >= this.maxBytes) {
      if (this.keptBytes > 0 || chunk.length > this.maxBytes) {
        this.truncated = true;
      }
      this.chunks = [Buffer.from(chunk.subarray(chunk.length - this.maxBytes))];
      this.headIdx = 0;
      this.keptBytes = this.chunks[0]!.length;
      return;
    }

    this.chunks.push(chunk);
    this.keptBytes += chunk.length;
    if (this.keptBytes > this.maxBytes) {
      this.truncated = true;
      while (this.headIdx < this.chunks.length && this.keptBytes > this.maxBytes) {
        const head = this.chunks[this.headIdx]!;
        const excess = this.keptBytes - this.maxBytes;
        if (head.length <= excess) {
          this.keptBytes -= head.length;
          this.headIdx += 1;
        } else {
          this.chunks[this.headIdx] = head.subarray(excess);
          this.keptBytes -= excess;
          break;
        }
      }
      if (this.headIdx > 64) {
        this.chunks = this.chunks.slice(this.headIdx);
        this.headIdx = 0;
      }
    }
  }

  finish(): CollectedStream {
    if (!this.finishedResult) {
      const activeChunks = this.headIdx > 0 ? this.chunks.slice(this.headIdx) : this.chunks;
      let buf = activeChunks.length === 1 ? activeChunks[0]! : Buffer.concat(activeChunks, this.keptBytes);
      if (this.truncated && buf.length > 0) {
        // Advance past orphan UTF-8 continuation bytes (`10xxxxxx`) at the truncated boundary
        let start = 0;
        while (start < buf.length && start < 3 && (buf[start]! & 0xc0) === 0x80) {
          start += 1;
        }
        if (start > 0) {
          buf = buf.subarray(start);
        }
      }
      this.finishedResult = {
        text: buf.toString('utf8'),
        truncated: this.truncated,
        totalBytes: this.totalBytes,
        spillPath: undefined,
      };
    }
    return this.finishedResult;
  }
}

/**
 * Inside `--unshare-net`, bridges a sandbox-private loopback port (127.0.0.1:<port>)
 * to the mounted Unix Domain Socket `/run/dsh-proxy/proxy.sock` so standard CLI tools
 * (`curl`, `npm`, `pnpm`, `uv`, `pip`, `git`, `cargo`, `go`) use `HTTP_PROXY`/`HTTPS_PROXY`
 * seamlessly while direct outbound IP access stays kernel-blocked.
 *
 * IMPORTANT: Runs `innerCommand` inside a subshell `( ... )` so inner `trap ... EXIT`
 * handlers (including `ConfinedTerminalManager`'s `__dsh_emit_cwd` trap or user scripts)
 * can NEVER clobber the outer bridge teardown that terminates `socat`/`node` immediately.
 */
function wrapCommandWithUdsLoopbackBridge(innerCommand: string): string {
  return [
    '__dsh_proxy_port=$((38000 + ((${RANDOM:-0} + $$) % 20000)))',
    '__dsh_port_hex=$(printf "%04X" "$__dsh_proxy_port")',
    '__dsh_bridge_pid=""',
    '__dsh_stop_bridge() { if [ -n "$__dsh_bridge_pid" ]; then kill "$__dsh_bridge_pid" 2>/dev/null || true; wait "$__dsh_bridge_pid" 2>/dev/null || true; __dsh_bridge_pid=""; fi; }',
    'if command -v socat >/dev/null 2>&1; then',
    '  socat "TCP-LISTEN:${__dsh_proxy_port},bind=127.0.0.1,fork,reuseaddr" "UNIX-CONNECT:/run/dsh-proxy/proxy.sock" </dev/null >/dev/null 2>&1 &',
    '  __dsh_bridge_pid=$!',
    'else',
    '  node -e "const n=require(\'node:net\');n.createServer(c=>{const u=n.connect(\'/run/dsh-proxy/proxy.sock\');c.pipe(u);u.pipe(c);c.on(\'error\',()=>u.destroy());u.on(\'error\',()=>c.destroy());}).listen(Number(process.argv[1]),\'127.0.0.1\');" "$__dsh_proxy_port" </dev/null >/dev/null 2>&1 &',
    '  __dsh_bridge_pid=$!',
    'fi',
    'trap __dsh_stop_bridge EXIT INT TERM',
    'export HTTP_PROXY="http://127.0.0.1:${__dsh_proxy_port}"',
    'export HTTPS_PROXY="http://127.0.0.1:${__dsh_proxy_port}"',
    'export http_proxy="http://127.0.0.1:${__dsh_proxy_port}"',
    'export https_proxy="http://127.0.0.1:${__dsh_proxy_port}"',
    '__dsh_tries=0',
    'while [ "$__dsh_tries" -lt 20 ]; do',
    '  if grep -qi ":${__dsh_port_hex} " /proc/net/tcp 2>/dev/null; then break; fi',
    '  __dsh_tries=$((__dsh_tries + 1))',
    '  sleep 0.02',
    'done',
    '(',
    innerCommand,
    ')',
    '__dsh_inner_rc=$?',
    '__dsh_stop_bridge',
    'exit $__dsh_inner_rc',
  ].join('\n');
}

/**
 * Verifies on Linux that `pid` is still the process-group leader we spawned (protecting
 * against PID reuse signaling an unrelated human terminal or another DSH session).
 */
function isOwnedProcessGroupAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 1) return false;
  if (process.platform !== 'linux') return true;
  try {
    const statText = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
    const closeParen = statText.lastIndexOf(')');
    if (closeParen < 0) return false;
    const fields = statText.slice(closeParen + 2).trim().split(/\s+/);
    const state = fields[0];
    const pgrp = Number(fields[2]);
    if (state === 'Z' || state === 'X') return false;
    return pgrp === pid;
  } catch {
    return false;
  }
}

function classifyStderr(
  exitCode: number | null,
  stderrText: string,
): { runnerFailed: boolean; denied: boolean; denialMatches: string[] } {
  if (exitCode === 0) {
    return { runnerFailed: false, denied: false, denialMatches: [] };
  }
  const lower = stderrText.toLowerCase();
  const lines = lower.split('\n').map((l) => l.trim()).filter(Boolean);
  const runnerFailed = lines.some((line) =>
    RUNNER_FAILURE_SIGNATURES.some((sig) => line.includes(sig)),
  );
  const denialMatches = DENIAL_SIGNATURES.filter((sig) => lower.includes(sig));
  return {
    runnerFailed,
    denied: !runnerFailed && denialMatches.length > 0,
    denialMatches: [...denialMatches],
  };
}

export class ConfinedProcManager {
  private readonly active = new Map<string, ActiveProc>();
  private readonly placeholderRefs = new Map<string, number>();
  private readonly runtimeDir: string;
  private readonly emptyMaskFile: string;

  constructor(baseTempDir?: string) {
    this.runtimeDir =
      baseTempDir ?? fs.mkdtempSync(path.join(resolveEphemeralRamTmpRoot(), 'dsh-wsl-runner-'));
    fs.mkdirSync(this.runtimeDir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(this.runtimeDir, 'owner.pid'), `${process.pid}\n`, { mode: 0o600 });
    this.emptyMaskFile = path.join(this.runtimeDir, 'empty-mask');
    fs.writeFileSync(this.emptyMaskFile, '', { mode: 0o444 });
  }

  getRuntimeDir(): string {
    return this.runtimeDir;
  }

  private acquirePlaceholders(paths: readonly string[]): string[] {
    const acquired: string[] = [];
    for (const p of paths) {
      this.placeholderRefs.set(p, (this.placeholderRefs.get(p) ?? 0) + 1);
      acquired.push(p);
    }
    return acquired;
  }

  private releasePlaceholders(paths: readonly string[]): void {
    for (const p of paths) {
      const next = (this.placeholderRefs.get(p) ?? 1) - 1;
      if (next <= 0) {
        this.placeholderRefs.delete(p);
        try {
          const st = fs.lstatSync(p);
          if (st.isFile() && st.size === 0) {
            fs.unlinkSync(p);
          }
        } catch {
          // Already absent or non-empty
        }
      } else {
        this.placeholderRefs.set(p, next);
      }
    }
  }

  getActiveCount(sessionId?: string): number {
    if (!sessionId) return this.active.size;
    let count = 0;
    for (const p of this.active.values()) {
      if (p.sessionId === sessionId) count++;
    }
    return count;
  }

  listActive(sessionId?: string): Array<{
    readonly execId: string;
    readonly sessionId: string;
    readonly terminalId?: string;
    readonly generation: number;
    readonly pgid?: number;
  }> {
    return Array.from(this.active.values())
      .filter((p) => !sessionId || p.sessionId === sessionId)
      .map((p) => ({
        execId: p.execId,
        sessionId: p.sessionId,
        terminalId: p.terminalId,
        generation: p.generation,
        pgid: p.pgid,
      }));
  }

  async kill(execId: string): Promise<boolean> {
    const entry = this.active.get(execId);
    if (!entry) return false;
    await entry.killGroup();
    return true;
  }

  async killTerminal(sessionId: string, terminalId: string): Promise<number> {
    const victims = Array.from(this.active.values()).filter(
      (p) => p.sessionId === sessionId && p.terminalId === terminalId,
    );
    await Promise.all(victims.map((v) => v.killGroup()));
    return victims.length;
  }

  async invalidateGeneration(
    minValidGeneration: number,
    scope?: { readonly sessionId?: string; readonly terminalId?: string },
  ): Promise<number> {
    const victims = Array.from(this.active.values()).filter((p) => {
      if (p.generation >= minValidGeneration) return false;
      if (scope?.sessionId && p.sessionId !== scope.sessionId) return false;
      if (scope?.terminalId && p.terminalId !== scope.terminalId) return false;
      return true;
    });
    await Promise.all(victims.map((v) => v.killGroup()));
    return victims.length;
  }

  cleanupSync(): void {
    for (const entry of this.active.values()) {
      entry.killGroupSync();
    }
    this.active.clear();
    const remaining = Array.from(this.placeholderRefs.keys());
    this.placeholderRefs.clear();
    for (const p of remaining) {
      try {
        const st = fs.lstatSync(p);
        if (st.isFile() && st.size === 0) fs.unlinkSync(p);
      } catch {
        // ignore
      }
    }
    try {
      if (fs.existsSync(this.emptyMaskFile)) {
        fs.chmodSync(this.emptyMaskFile, 0o600);
      }
    } catch {
      // ignore
    }
    fs.rmSync(this.runtimeDir, { recursive: true, force: true });
  }

  async disposeAll(): Promise<void> {
    const all = Array.from(this.active.values());
    await Promise.all(all.map((p) => p.killGroup()));
    this.cleanupSync();
  }

  async exec(params: ProcExecParams): Promise<ProcExecResult> {
    const execId = params.execId ?? randomUUID();
    const timeoutMs = Math.min(600_000, Math.max(100, params.timeoutMs ?? DEFAULT_TIMEOUT_MS));
    const graceMs = Math.min(10_000, Math.max(100, params.graceMs ?? DEFAULT_GRACE_MS));
    const maxOutputBytes = params.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;

    const useBridge = params.networkMode === 'allowlist-proxy' && Boolean(params.proxySocketHostPath);
    const bashExe = resolveBashExecutable();

    let targetArgv: string[];
    if (params.argv && params.argv.length > 0 && !useBridge) {
      targetArgv = [...params.argv];
    } else if (params.command !== undefined) {
      const script = useBridge ? wrapCommandWithUdsLoopbackBridge(params.command) : params.command;
      targetArgv = [bashExe, '-c', script];
    } else if (params.argv && params.argv.length > 0 && useBridge) {
      const quoted = params.argv.map((a) => `'${a.replace(/'/g, "'\\''")}'`).join(' ');
      targetArgv = [bashExe, '-c', wrapCommandWithUdsLoopbackBridge(quoted)];
    } else {
      failSandbox('INVALID_ACTION', 'proc.exec requires either command or argv');
    }

    const resolvedCwd = resolveExecutionCwd(params.binding, params.cwd);

    const homeDir = os.homedir() || `/home/${params.binding.username}`;
    const ownerEnv: Record<string, string> = {
      ...(params.dshEnv ?? {}),
      DSH_WSL_SESSION_ID: params.binding.sessionId,
      DSH_WSL_EXEC_ID: execId,
    };
    if (params.ownerRunnerId ?? params.binding.runnerId) {
      ownerEnv.DSH_WSL_OWNER_RUNNER = params.ownerRunnerId ?? params.binding.runnerId;
    }
    if (params.terminalId) {
      ownerEnv.DSH_WSL_TERMINAL_ID = params.terminalId;
    }

    const sanitizedEnv = sanitizeSandboxEnv({
      baseEnv: process.env,
      extraEnv: params.env,
      dshEnv: ownerEnv,
      homeDir,
      cacheRootDir: params.cacheDir,
      mirrorCn: params.mirrorCn,
    });

    if (params.cacheDir && params.mode === 'workspace-write') {
      fs.mkdirSync(params.cacheDir, { recursive: true, mode: 0o700 });
      try {
        const lastUsedPath = path.join(params.cacheDir, '.last-used');
        const fd = fs.openSync(lastUsedPath, 'a', 0o600);
        fs.closeSync(fd);
        const now = new Date();
        fs.utimesSync(lastUsedPath, now, now);
      } catch {
        // Non-fatal cache timestamp update failure
      }
    }

    // Compile architecture-specific seccomp-bpf and open fd for `bwrap --seccomp 3`
    const bpfPath = path.join(this.runtimeDir, `seccomp-${execId}.bpf`);
    const bpfBuf = compileSeccompBpf({
      arch: params.binding.arch,
      // Offline mode blocks AF_INET/AF_INET6 at seccomp layer too; allowlist-proxy relies on
      // --unshare-net isolation + AF_VSOCK/AF_PACKET block so sandbox-local 127.0.0.1 bridge works.
      blockNetworkSockets: params.networkMode === 'offline',
      blockUsernsClone: !params.binding.supportsDisableUserns,
    });
    fs.writeFileSync(bpfPath, bpfBuf, { mode: 0o600 });
    const bpfFd = fs.openSync(bpfPath, 'r');

    const usePrlimit = params.binding.hasPrlimit !== false && hasPrlimitBinary();

    let bwrapBuild;
    try {
      bwrapBuild = buildBwrapArgs({
        argv: targetArgv,
        cwd: resolvedCwd.bwrapCwd,
        workspaceRoot: params.binding.workspaceRoot,
        mode: params.mode,
        networkMode: params.networkMode,
        supportsDisableUserns: params.binding.supportsDisableUserns,
        seccompFd: 3,
        env: sanitizedEnv,
        homeDir,
        rlimits: params.rlimits,
        usePrlimit,
        shares: params.binding.authorizedShares,
        devices: params.binding.authorizedDevices,
        cacheDir: params.cacheDir,
        maskEnvSecrets: params.maskEnvSecrets !== false,
        emptyMaskFilePath: this.emptyMaskFile,
        proxySocketHostPath: params.proxySocketHostPath,
      });
    } catch (err) {
      try { fs.closeSync(bpfFd); } catch { /* ignore */ }
      fs.rmSync(bpfPath, { force: true });
      throw err;
    }

    const acquiredPlaceholders = this.acquirePlaceholders(bwrapBuild.createdPlaceholders);

    const child = spawn('bwrap', bwrapBuild.bwrapArgs, {
      cwd: resolvedCwd.hostSpawnCwd,
      detached: true,
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe', bpfFd],
    });

    // Attach stdin error listener immediately so EPIPE on fast-exiting child NEVER emits unhandled 'error'
    child.stdin?.on('error', () => {});

    // Parent no longer needs bpfFd or temp file once child inherited fd 3
    try { fs.closeSync(bpfFd); } catch { /* ignore */ }
    fs.rmSync(bpfPath, { force: true });

    if (params.stdin !== undefined && child.stdin) {
      child.stdin.write(params.stdin);
      child.stdin.end();
    } else if (child.stdin) {
      child.stdin.end();
    }

    const stdoutCollector = new BoundedStreamCollector(maxOutputBytes);
    const stderrCollector = new BoundedStreamCollector(maxOutputBytes);
    child.stdout?.on('data', (chunk: Buffer) => stdoutCollector.push(chunk));
    child.stderr?.on('data', (chunk: Buffer) => stderrCollector.push(chunk));

    let timedOut = false;
    let aborted = false;
    let exited = false;
    let killPromise: Promise<void> | undefined;

    const waitClose = new Promise<{ exitCode: number | null; signal: string | null }>((resolve, reject) => {
      child.once('error', (err) => {
        exited = true;
        reject(err);
      });
      child.once('close', (code, signal) => {
        exited = true;
        resolve({ exitCode: code, signal: signal ?? null });
      });
    });

    const killGroupSync = (): void => {
      if (exited || child.exitCode !== null) return;
      const pid = child.pid;
      if (pid && isOwnedProcessGroupAlive(pid)) {
        try { process.kill(-pid, 'SIGKILL'); } catch { /* already gone */ }
      }
    };

    const killGroup = (fromTimeout = false): Promise<void> => {
      if (!fromTimeout && !timedOut) aborted = true;
      if (exited) return Promise.resolve();
      if (killPromise) return killPromise;
      killPromise = (async () => {
        const pid = child.pid;
        if (pid && isOwnedProcessGroupAlive(pid)) {
          try { process.kill(-pid, 'SIGTERM'); } catch { /* already gone */ }
          const forceTimer = setTimeout(() => {
            if (!exited && child.exitCode === null && isOwnedProcessGroupAlive(pid)) {
              try { process.kill(-pid, 'SIGKILL'); } catch { /* already gone */ }
            }
          }, graceMs);
          forceTimer.unref();
          await waitClose.catch(() => undefined);
          clearTimeout(forceTimer);
        }
      })();
      return killPromise;
    };

    this.active.set(execId, {
      execId,
      sessionId: params.binding.sessionId,
      terminalId: params.terminalId,
      generation: params.binding.generation,
      pgid: child.pid,
      child,
      killGroup: () => killGroup(false),
      killGroupSync,
    });

    const timer = setTimeout(() => {
      if (!exited) {
        timedOut = true;
        void killGroup(true);
      }
    }, timeoutMs);
    timer.unref();

    try {
      const outcome = await waitClose;
      const stdout = stdoutCollector.finish();
      const stderr = stderrCollector.finish();
      const classification = classifyStderr(outcome.exitCode, stderr.text);

      return {
        exitCode: outcome.exitCode,
        signal: outcome.signal,
        timedOut,
        aborted,
        timeoutMs,
        stdout,
        stderr,
        sandbox: {
          mode: params.mode,
          denied: classification.denied,
          enforcement: bwrapBuild.enforcement,
          runnerFailed: classification.runnerFailed,
          denialMatches: classification.denialMatches,
        },
      };
    } catch (err) {
      failSandbox(
        'SANDBOX_UNAVAILABLE',
        `Failed to spawn bwrap sandbox: ${err instanceof Error ? err.message : String(err)}`,
      );
    } finally {
      clearTimeout(timer);
      stdoutCollector.finish();
      stderrCollector.finish();
      this.active.delete(execId);
      this.releasePlaceholders(acquiredPlaceholders);
    }
  }
}
