import {                                      spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import readline from 'node:readline';
import {
  failSandbox,
  isValidIdentifier,
  MAX_RPC_FRAME_BYTES,
                          
                           
                  
                   
  SandboxError,
} from '../../core/src/index.js';

                                      
                                       
                          
                             
                              
                                   
                                  
                                  
                                                                                   
                                             
 

                        
                                             
                                        
                                 
 

/**
 * Persistent NDJSON RPC transport connecting the DSH Host plugin to `wsl-runner`.
 *
 * Security invariants:
 * - Always uses `shell: false` (never passes untrusted strings to cmd.exe or pwsh).
 * - Zero silent fallback to Windows host execution when WSL is unavailable.
 * - Cleanly rejects all in-flight RPCs on runner EOF/crash and supports bidirectional
 *   `proxy.authorizeHost` approval callbacks.
 */
export class WslTransport {
                   options                     ;
          child                                            ;
          rl                                ;
                   inFlight = new Map                      ();
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

  async ensureStarted()                {
    if (this.disposed) {
      failSandbox('BACKEND_UNAVAILABLE', 'WslTransport has been disposed');
    }
    if (this.isRunning()) return;

    const env                    = { ...process.env };
    if (this.options.runnerLeaseMs && this.options.runnerLeaseMs > 0) {
      env.DSH_WSL_RUNNER_LEASE_MS = String(this.options.runnerLeaseMs);
    }

    let command        ;
    let args          ;

    if (this.options.mode === 'wsl') {
      command = this.options.wslExecutable ?? 'wsl.exe';
      args = ['-d', this.options.distro];
      if (this.options.username) {
        args.push('-u', this.options.username);
      }
      args.push('--', this.options.nodeExecutable ?? 'node', this.options.runnerPath);
    } else {
      command = this.options.nodeExecutable ?? process.execPath;
      args = [this.options.runnerPath];
    }

    const child = spawn(command, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      shell: false,
      windowsHide: true,
      env,
    });

    this.child = child;

    child.stderr.on('data', (chunk        ) => {
      const text = chunk.toString('utf8').trim();
      if (text) this.options.onStderr?.(text);
    });

    const rejectAll = (reason        )       => {
      for (const [id, call] of this.inFlight) {
        clearTimeout(call.timer);
        call.reject(new SandboxError('BACKEND_UNAVAILABLE', reason));
        this.inFlight.delete(id);
      }
      this.rl?.close();
      this.rl = undefined;
      if (this.child === child) {
        this.child = undefined;
      }
    };

    child.once('error', (err) => {
      rejectAll(`Failed to spawn WSL runner (${command}): ${err.message}`);
    });

    child.once('exit', (code, signal) => {
      rejectAll(`WSL runner exited unexpectedly (code=${code}, signal=${signal})`);
    });

    const rl = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
    this.rl = rl;

    rl.on('line', (line) => {
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
        pending.resolve(resp.result);
      } else {
        const errCode = resp.error?.code ?? 'PROCESS_EXIT';
        pending.reject(
          new SandboxError(errCode, resp.error?.message ?? 'WSL runner RPC error', resp.error?.details),
        );
      }
    });
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

  async invalidate(minValidGeneration        )                  {
    if (!this.isRunning()) return 0;
    try {
      const res = await this.call                         ('invalidate', { generation: minValidGeneration }, 10_000);
      return res.killedCount;
    } catch {
      return 0;
    }
  }

  async dispose()                {
    this.disposed = true;
    const child = this.child;
    this.child = undefined;
    this.rl?.close();
    this.rl = undefined;

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
          child.kill('SIGTERM');
        }
      });
    }
  }
}
