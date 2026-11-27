import {                                      spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import readline from 'node:readline';
import {
  buildHostNodeChildEnv,
  buildWslNodeSpawnArgs,
  failSandbox,
  isValidIdentifier,
                
  MAX_RPC_FRAME_BYTES,
  parseRunnerWireLog,
  resolveSharedHostNodeRuntime,
                          
                           
                  
                   
  SandboxError,
                        
} from '../../core/src/index.js';

                                      
                                       
                          
                             
                              
                                   
                                  
                               
                                     
                                                                                                                              
                                  
                                        
                                                                                   
                                             
 

                        
                                             
                                        
                                 
 

const DEFAULT_RUNNER_LEASE_MS = 180_000;
const DEFAULT_HEARTBEAT_MS = 30_000;

/**
 * Persistent NDJSON RPC transport connecting the DSH Host plugin to `wsl-runner`.
 *
 * Lifecycle, shared-Node & leak-prevention invariants:
 * - Always uses `shell: false` on the Windows host and passes `--cd ~` to `wsl.exe` so the Linux
 *   runner NEVER holds an open working-directory handle on any Windows NTFS plugin or project folder.
 * - Shares Node.js cleanly:
 *   - On `local-linux`: reuses DSH's own `process.execPath` carrier (`ELECTRON_RUN_AS_NODE=1` when
 *     inside Electron DSH Desktop, with `NODE_OPTIONS`/`TSX_*` scrubbed).
 *   - On `wsl`: resolves shared Linux `node` across `.dsh-wsl-env.sh`, `~/.dsh/runtime/bin`, `mise`,
 *     `nvm`, `fnm`, `volta`, and `/usr/bin` via positional `sh -c '... exec "$NODE_BIN" "$TARGET"'`,
 *     preserving exact runner PID while strictly rejecting `/mnt/*.exe`.
 * - Ingests `[DSH_RUNNER_LOG]` structured lines from runner `stderr` into the Host `StructuredLogger`
 *   so runner events are unified into Host's coalesced `2.5s` batched sink with ZERO extra WSL VHDX I/O.
 */
export class WslTransport {
                   options                     ;
          child                                            ;
          stdoutRl                                ;
          stderrRl                                ;
          heartbeatTimer                            ;
          processExitHook                          ;
                   inFlight = new Map                      ();
          runnerNodeInfo                                                  = {};
          disposed = false;

  constructor(options                     ) {
    if (options.mode === 'wsl' && !isValidIdentifier(options.distro)) {
      failSandbox('INVALID_SETUP', `Invalid WSL distribution name: ${options.distro}`);
    }
    this.options = options;
  }

  isRunning()          {
    return Boolean(this.child && !this.child.killed && this.child.exitCode === null);
  }

  getChildPid()                     {
    return this.child?.pid;
  }

  getRunnerNodeInfo()                                                                    {
    return this.runnerNodeInfo;
  }

          clearHeartbeatAndExitHook()       {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = undefined;
    }
    if (this.processExitHook) {
      process.off('exit', this.processExitHook);
      this.processExitHook = undefined;
    }
  }

          closeReadlines()       {
    this.stdoutRl?.close();
    this.stdoutRl = undefined;
    this.stderrRl?.close();
    this.stderrRl = undefined;
  }

  async ensureStarted()                {
    if (this.disposed) {
      failSandbox('BACKEND_UNAVAILABLE', 'WslTransport has been disposed');
    }
    if (this.isRunning()) return;

    const leaseMs = this.options.runnerLeaseMs ?? DEFAULT_RUNNER_LEASE_MS;
    const logLevel = this.options.logLevel ?? this.options.logger?.getLevel() ?? 'info';

    let command        ;
    let args          ;
    let env                   ;

    if (this.options.mode === 'wsl') {
      command = this.options.wslExecutable ?? 'wsl.exe';
      if (
        process.env.DSH_WSL_NO_HOST_SPAWN === '1' &&
        /^(?:wsl|wsl\.exe)$/i.test(command.replace(/^.*[\\/]/, ''))
      ) {
        failSandbox('BACKEND_UNAVAILABLE', 'Spawning host wsl.exe is disabled under DSH_WSL_NO_HOST_SPAWN=1');
      }
      args = buildWslNodeSpawnArgs({
        distro: this.options.distro,
        username: this.options.username,
        nodeExecutable: this.options.nodeExecutable,
        scriptPath: this.options.runnerPath,
        leaseMs,
        logLevel,
      });
      env = buildHostNodeChildEnv(process.env, {
        DSH_WSL_RUNNER_LEASE_MS: leaseMs > 0 ? String(leaseMs) : undefined,
      });
    } else {
      const hostNode = resolveSharedHostNodeRuntime(this.options.nodeExecutable);
      command = hostNode.executable;
      args = [this.options.runnerPath];
      env = buildHostNodeChildEnv(
        process.env,
        {
          DSH_WSL_RUNNER_LEASE_MS: leaseMs > 0 ? String(leaseMs) : undefined,
          DSH_WSL_LOG_LEVEL: logLevel,
        },
        this.options.nodeExecutable,
      );
    }

    const child = spawn(command, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      shell: false,
      windowsHide: true,
      env,
    });

    this.child = child;
    this.options.logger?.log('info', {
      component: 'transport',
      event: 'transport.spawn',
      message: `Spawned WSL sandbox runner (${this.options.mode}:${this.options.distro}, pid=${child.pid ?? 'pending'})`,
      data: {
        mode: this.options.mode,
        distro: this.options.distro,
        runnerPath: this.options.runnerPath,
        childPid: child.pid ?? null,
      },
    });

    const onProcessExit = ()       => {
      try {
        if (!child.killed && child.exitCode === null) {
          try { child.stdin.destroy(); } catch { /* ignore */ }
          try { child.kill('SIGTERM'); } catch { /* ignore */ }
        }
      } catch {
        // ignore
      }
    };
    this.processExitHook = onProcessExit;
    process.once('exit', onProcessExit);

    const stderrRl = readline.createInterface({ input: child.stderr, crlfDelay: Infinity });
    this.stderrRl = stderrRl;
    stderrRl.on('line', (line) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      const wireEntry = parseRunnerWireLog(trimmed);
      if (wireEntry) {
        this.options.logger?.ingestExternal(wireEntry);
        return;
      }
      this.options.logger?.log('warn', {
        component: 'transport',
        event: 'runner.stderr',
        message: trimmed,
      });
      this.options.onStderr?.(trimmed);
    });

    const rejectAll = (reason        )       => {
      this.clearHeartbeatAndExitHook();
      for (const [id, call] of this.inFlight) {
        clearTimeout(call.timer);
        call.reject(new SandboxError('BACKEND_UNAVAILABLE', reason));
        this.inFlight.delete(id);
      }
      this.closeReadlines();
      if (this.child === child) {
        this.child = undefined;
      }
    };

    child.once('error', (err) => {
      this.options.logger?.log('error', {
        component: 'transport',
        event: 'transport.error',
        message: `Failed to spawn WSL runner (${command}): ${err.message}`,
        data: { command, error: err.message },
      });
      rejectAll(`Failed to spawn WSL runner (${command}): ${err.message}`);
    });

    child.once('exit', (code, signal) => {
      if (!this.disposed) {
        this.options.logger?.log('warn', {
          component: 'transport',
          event: 'transport.exit',
          message: `WSL runner exited (code=${code}, signal=${signal})`,
          data: { code, signal },
        });
      }
      rejectAll(`WSL runner exited unexpectedly (code=${code}, signal=${signal})`);
    });

    const stdoutRl = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
    this.stdoutRl = stdoutRl;

    stdoutRl.on('line', (line) => {
      if (!line.trim()) return;
      if (Buffer.byteLength(line, 'utf8') > MAX_RPC_FRAME_BYTES) return;

      let parsed                         ;
      try {
        parsed = JSON.parse(line)                           ;
      } catch {
        return;
      }

      if (parsed.kind === 'callback') {
        void this.handleRunnerCallback(parsed                                 );
        return;
      }

      const resp = parsed                          ;
      const pending = this.inFlight.get(resp.id);
      if (!pending) return;

      clearTimeout(pending.timer);
      this.inFlight.delete(resp.id);

      if (resp.ok) {
        if (resp.result && typeof resp.result === 'object') {
          const rObj = resp.result                                                     ;
          if (typeof rObj.nodeVersion === 'string') {
            this.runnerNodeInfo = {
              nodeVersion: rObj.nodeVersion,
              nodeExecPath: typeof rObj.nodeExecPath === 'string' ? rObj.nodeExecPath : this.runnerNodeInfo.nodeExecPath,
            };
          }
        }
        pending.resolve(resp.result);
      } else {
        const errCode = resp.error?.code ?? 'PROCESS_EXIT';
        pending.reject(
          new SandboxError(errCode, resp.error?.message ?? 'WSL runner RPC error', resp.error?.details),
        );
      }
    });

    if (leaseMs > 0) {
      const interval = Math.max(2000, Math.min(this.options.heartbeatIntervalMs ?? DEFAULT_HEARTBEAT_MS, Math.floor(leaseMs / 3)));
      this.heartbeatTimer = setInterval(() => {
        if (!this.isRunning()) return;
        void this.call('ping', {}, 5_000).catch(() => {});
      }, interval);
      this.heartbeatTimer.unref();
    }
  }

          async handleRunnerCallback(cb                    )                {
    let allowed = false;
    if (cb.method === 'proxy.authorizeHost' && this.options.onAuthorizeProxyHost) {
      try {
        allowed = await this.options.onAuthorizeProxyHost(cb.params.host, cb.params.port);
      } catch {
        allowed = false;
      }
    }
    if (this.child && !this.child.killed && this.child.stdin.writable) {
      const response                      = {
        kind: 'callback-response',
        id: cb.id,
        ok: true,
        result: { allowed },
      };
      this.child.stdin.write(JSON.stringify(response) + '\n');
    }
  }

  async call                   (
    method        ,
    params                          = {},
    timeoutMs = 150_000,
  )                   {
    await this.ensureStarted();
    const child = this.child;
    if (!child || !child.stdin.writable) {
      failSandbox('BACKEND_UNAVAILABLE', 'WSL runner stdin is not writable');
    }

    const id = randomUUID();
    const frame             = { id, method, params };
    const serialized = JSON.stringify(frame) + '\n';
    if (Buffer.byteLength(serialized, 'utf8') > MAX_RPC_FRAME_BYTES) {
      failSandbox('INVALID_ACTION', `RPC frame exceeds ${MAX_RPC_FRAME_BYTES} bytes`);
    }

    return new Promise         ((resolve, reject) => {
      const timer = setTimeout(() => {
        this.inFlight.delete(id);
        this.options.logger?.log('error', {
          component: 'transport',
          event: 'transport.rpcTimeout',
          message: `WSL runner RPC '${method}' timed out after ${timeoutMs}ms`,
          data: { method, timeoutMs },
        });
        reject(new SandboxError('TIMEOUT', `WSL runner RPC '${method}' timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      timer.unref();

      this.inFlight.set(id, {
        resolve: resolve                            ,
        reject,
        timer,
      });

      child.stdin.write(serialized, (err) => {
        if (err) {
          clearTimeout(timer);
          this.inFlight.delete(id);
          reject(new SandboxError('RUNNER_UNAVAILABLE', `Failed writing RPC '${method}': ${err.message}`));
        }
      });
    });
  }

  async setRunnerLogLevel(level          )                {
    if (!this.isRunning()) return;
    await this.call('logs.setLevel', { level }, 3_000).catch(() => {});
  }

  async invalidate(
    minValidGeneration        ,
    scope                                                                ,
  )                  {
    if (!this.isRunning()) return 0;
    try {
      const res = await this.call                         (
        'invalidate',
        {
          generation: minValidGeneration,
          sessionId: scope?.sessionId,
          terminalId: scope?.terminalId,
        },
        10_000,
      );
      return res.killedCount;
    } catch {
      return 0;
    }
  }

  async dispose()                {
    if (this.disposed) return;
    this.disposed = true;
    this.clearHeartbeatAndExitHook();

    const child = this.child;

    // 1. Send graceful shutdown RPC first so in-WSL runner closes proxy sockets, kills owned PGIDs,
    //    flushes logs, and deletes /tmp/dsh-wsl-* cleanly before stdio closes.
    if (child && !child.killed && child.exitCode === null && child.stdin.writable) {
      try {
        const id = randomUUID();
        const frame             = { id, method: 'shutdown', params: {} };
        await new Promise      ((resolve) => {
          const t = setTimeout(resolve, 1200);
          t.unref();
          this.inFlight.set(id, {
            resolve: () => { clearTimeout(t); resolve(); },
            reject: () => { clearTimeout(t); resolve(); },
            timer: t,
          });
          child.stdin.write(JSON.stringify(frame) + '\n', () => {});
        });
      } catch {
        // Proceed to EOF / signal teardown
      }
    }

    this.child = undefined;
    this.closeReadlines();

    for (const [id, call] of this.inFlight) {
      clearTimeout(call.timer);
      call.reject(new SandboxError('CANCELLED', 'WslTransport disposed'));
      this.inFlight.delete(id);
    }

    if (child && !child.killed && child.exitCode === null) {
      await new Promise      ((resolve) => {
        const forceTimer = setTimeout(() => {
          try {
            child.kill('SIGKILL');
          } catch {
            // ignore
          }
          resolve();
        }, 1500);
        forceTimer.unref();

        child.once('exit', () => {
          clearTimeout(forceTimer);
          resolve();
        });
        try {
          child.stdin.end();
        } catch {
          try { child.kill('SIGTERM'); } catch { /* ignore */ }
        }
      });
    }

    this.options.logger?.log('info', {
      component: 'transport',
      event: 'transport.disposed',
      message: 'WslTransport disposed cleanly',
    });
  }
}
