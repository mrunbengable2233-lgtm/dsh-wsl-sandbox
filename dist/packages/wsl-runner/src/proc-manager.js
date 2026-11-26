import {                    spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  buildBwrapArgs,
                       
  compileSeccompBpf,
  failSandbox,
                      
                      
  sanitizeSandboxEnv,
} from '../../core/src/index.js';
import { resolveEphemeralRamTmpRoot } from './hygiene.js';

const DEFAULT_TIMEOUT_MS = 120_000;
const DEFAULT_GRACE_MS = 2_000;
const DEFAULT_MAX_OUTPUT_BYTES = 256 * 1024;
const MAX_SPILL_BYTES = 10 * 1024 * 1024;

const DENIAL_SIGNATURES = [
  'read-only file system',
  'erofs',
  'permission denied',
  'operation not permitted',
  'network is unreachable',
  'dsh wsl sandbox proxy blocked',
]         ;

const RUNNER_FAILURE_SIGNATURES = [
  'bwrap:',
  'setting up uid map',
  'creating new namespace failed',
  'execvp',
]         ;

                      
                          
                             
                               
                              
                                    
                               
                                          
                                     
 

class BoundedStreamCollector {
                   maxBytes        ;
                   spillDir        ;
                   name        ;
          chunks           = [];
          keptBytes = 0;
          totalBytes = 0;
          truncated = false;
          spillPath                    ;
          spillFd                    ;
          spillBytes = 0;
          spillAborted = false;
          finishedResult                             ;

  constructor(maxBytes        , spillDir        , name        ) {
    this.maxBytes = Math.max(1024, maxBytes);
    this.spillDir = spillDir;
    this.name = name;
  }

  push(chunk        )       {
    this.totalBytes += chunk.length;

    if (!this.truncated && this.keptBytes + chunk.length <= this.maxBytes) {
      this.chunks.push(chunk);
      this.keptBytes += chunk.length;
      return;
    }

    // Overflow -> begin spill file with previously buffered bytes + new bytes
    if (!this.truncated) {
      this.truncated = true;
      try {
        fs.mkdirSync(this.spillDir, { recursive: true, mode: 0o700 });
        this.spillPath = path.join(this.spillDir, `${this.name}-${randomUUID()}.log`);
        this.spillFd = fs.openSync(this.spillPath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
        for (const prev of this.chunks) {
          this.writeSpill(prev);
        }
      } catch {
        this.spillAborted = true;
        this.spillPath = undefined;
      }
    }

    this.writeSpill(chunk);

    // Keep tail up to maxBytes in memory
    const combined = Buffer.concat([...this.chunks, chunk]);
    if (combined.length > this.maxBytes) {
      const tail = combined.subarray(combined.length - this.maxBytes);
      this.chunks = [tail];
      this.keptBytes = tail.length;
    } else {
      this.chunks = [combined];
      this.keptBytes = combined.length;
    }
  }

          writeSpill(buf        )       {
    if (this.spillAborted || this.spillFd === undefined) return;
    if (this.spillBytes + buf.length > MAX_SPILL_BYTES) {
      try { fs.closeSync(this.spillFd); } catch { /* ignore */ }
      this.spillFd = undefined;
      if (this.spillPath) fs.rmSync(this.spillPath, { force: true });
      this.spillPath = undefined;
      this.spillAborted = true;
      return;
    }
    try {
      fs.writeSync(this.spillFd, buf);
      this.spillBytes += buf.length;
    } catch {
      this.spillAborted = true;
    }
  }

  finish()                  {
    if (this.spillFd !== undefined) {
      try { fs.closeSync(this.spillFd); } catch { /* ignore */ }
      this.spillFd = undefined;
    }
    if (!this.finishedResult) {
      this.finishedResult = {
        text: Buffer.concat(this.chunks).toString('utf8'),
        truncated: this.truncated,
        totalBytes: this.totalBytes,
        spillPath: this.truncated && !this.spillAborted ? this.spillPath : undefined,
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
function wrapCommandWithUdsLoopbackBridge(innerCommand        )         {
  return [
    '__dsh_proxy_port=$((38000 + ($$ % 10000)))',
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
    'sleep 0.05',
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
function isOwnedProcessGroupAlive(pid        )          {
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
  exitCode               ,
  stderrText        ,
)                                                                      {
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
                   active = new Map                    ();
                   placeholderRefs = new Map                ();
                   runtimeDir        ;
                   emptyMaskFile        ;
                   spillDir        ;

  constructor(baseTempDir         ) {
    this.runtimeDir =
      baseTempDir ?? fs.mkdtempSync(path.join(resolveEphemeralRamTmpRoot(), 'dsh-wsl-runner-'));
    fs.mkdirSync(this.runtimeDir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(this.runtimeDir, 'owner.pid'), `${process.pid}\n`, { mode: 0o600 });
    this.emptyMaskFile = path.join(this.runtimeDir, 'empty-mask');
    fs.writeFileSync(this.emptyMaskFile, '', { mode: 0o444 });
    this.spillDir = path.join(this.runtimeDir, 'spills');
  }

  getRuntimeDir()         {
    return this.runtimeDir;
  }

          acquirePlaceholders(paths                   )           {
    const acquired           = [];
    for (const p of paths) {
      this.placeholderRefs.set(p, (this.placeholderRefs.get(p) ?? 0) + 1);
      acquired.push(p);
    }
    return acquired;
  }

          releasePlaceholders(paths                   )       {
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

  getActiveCount(sessionId         )         {
    if (!sessionId) return this.active.size;
    let count = 0;
    for (const p of this.active.values()) {
      if (p.sessionId === sessionId) count++;
    }
    return count;
  }

  listActive(sessionId         )         
                            
                               
                                 
                                
                           
     {
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

  async kill(execId        )                   {
    const entry = this.active.get(execId);
    if (!entry) return false;
    await entry.killGroup();
    return true;
  }

  async killTerminal(sessionId        , terminalId        )                  {
    const victims = Array.from(this.active.values()).filter(
      (p) => p.sessionId === sessionId && p.terminalId === terminalId,
    );
    await Promise.all(victims.map((v) => v.killGroup()));
    return victims.length;
  }

  async invalidateGeneration(
    minValidGeneration        ,
    scope                                                                ,
  )                  {
    const victims = Array.from(this.active.values()).filter((p) => {
      if (p.generation >= minValidGeneration) return false;
      if (scope?.sessionId && p.sessionId !== scope.sessionId) return false;
      if (scope?.terminalId && p.terminalId !== scope.terminalId) return false;
      return true;
    });
    await Promise.all(victims.map((v) => v.killGroup()));
    return victims.length;
  }

  cleanupSync()       {
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

  async disposeAll()                {
    const all = Array.from(this.active.values());
    await Promise.all(all.map((p) => p.killGroup()));
    this.cleanupSync();
  }

  async exec(params                )                          {
    const execId = params.execId ?? randomUUID();
    const timeoutMs = Math.min(600_000, Math.max(100, params.timeoutMs ?? DEFAULT_TIMEOUT_MS));
    const graceMs = Math.min(10_000, Math.max(100, params.graceMs ?? DEFAULT_GRACE_MS));
    const maxOutputBytes = params.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;

    const useBridge = params.networkMode === 'allowlist-proxy' && Boolean(params.proxySocketHostPath);

    let targetArgv          ;
    if (params.argv && params.argv.length > 0 && !useBridge) {
      targetArgv = [...params.argv];
    } else if (params.command !== undefined) {
      const script = useBridge ? wrapCommandWithUdsLoopbackBridge(params.command) : params.command;
      targetArgv = ['/bin/bash', '-c', script];
    } else if (params.argv && params.argv.length > 0 && useBridge) {
      const quoted = params.argv.map((a) => `'${a.replace(/'/g, "'\\''")}'`).join(' ');
      targetArgv = ['/bin/bash', '-c', wrapCommandWithUdsLoopbackBridge(quoted)];
    } else {
      failSandbox('INVALID_ACTION', 'proc.exec requires either command or argv');
    }

    const homeDir = os.homedir() || `/home/${params.binding.username}`;
    const ownerEnv                         = {
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
    }

    // Compile architecture-specific seccomp-bpf and open fd for `bwrap --seccomp 3`
    const bpfPath = path.join(this.runtimeDir, `seccomp-${execId}.bpf`);
    const bpfBuf = compileSeccompBpf({
      arch: params.binding.arch,
      // Offline mode blocks AF_INET/AF_INET6 at seccomp layer too; allowlist-proxy relies on
      // --unshare-net isolation + AF_VSOCK/AF_PACKET block so sandbox-local 127.0.0.1 bridge works.
      blockNetworkSockets: params.networkMode === 'offline',
    });
    fs.writeFileSync(bpfPath, bpfBuf, { mode: 0o600 });
    const bpfFd = fs.openSync(bpfPath, 'r');

    let bwrapBuild;
    try {
      bwrapBuild = buildBwrapArgs({
        argv: targetArgv,
        cwd: params.cwd,
        workspaceRoot: params.binding.workspaceRoot,
        mode: params.mode,
        networkMode: params.networkMode,
        supportsDisableUserns: params.binding.supportsDisableUserns,
        seccompFd: 3,
        env: sanitizedEnv,
        homeDir,
        rlimits: params.rlimits,
        usePrlimit: true,
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
      detached: true,
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe', bpfFd],
    });

    // Parent no longer needs bpfFd or temp file once child inherited fd 3
    try { fs.closeSync(bpfFd); } catch { /* ignore */ }
    fs.rmSync(bpfPath, { force: true });

    if (params.stdin !== undefined && child.stdin) {
      child.stdin.write(params.stdin);
      child.stdin.end();
    } else if (child.stdin) {
      child.stdin.end();
    }

    const stdoutCollector = new BoundedStreamCollector(maxOutputBytes, this.spillDir, `out-${execId}`);
    const stderrCollector = new BoundedStreamCollector(maxOutputBytes, this.spillDir, `err-${execId}`);
    child.stdout?.on('data', (chunk        ) => stdoutCollector.push(chunk));
    child.stderr?.on('data', (chunk        ) => stderrCollector.push(chunk));

    let timedOut = false;
    let aborted = false;
    let exited = false;
    let killing = false;

    const waitClose = new Promise                                                    ((resolve, reject) => {
      child.once('error', (err) => {
        exited = true;
        reject(err);
      });
      child.once('close', (code, signal) => {
        exited = true;
        resolve({ exitCode: code, signal: signal ?? null });
      });
    });

    const killGroupSync = ()       => {
      if (exited || child.exitCode !== null) return;
      const pid = child.pid;
      if (pid && isOwnedProcessGroupAlive(pid)) {
        try { process.kill(-pid, 'SIGKILL'); } catch { /* already gone */ }
      }
    };

    const killGroup = async (fromTimeout = false)                => {
      if (exited || killing) return;
      killing = true;
      if (!fromTimeout && !timedOut) aborted = true;
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
