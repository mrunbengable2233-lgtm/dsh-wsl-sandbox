import { type ChildProcessWithoutNullStreams, spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import readline from 'node:readline';
import {
  failSandbox,
  isValidIdentifier,
  MAX_RPC_FRAME_BYTES,
  type RpcCallbackRequest,
  type RpcCallbackResponse,
  type RpcRequest,
  type RpcResponse,
  SandboxError,
} from '../../core/src/index.ts';

export interface WslTransportOptions {
  readonly mode: 'wsl' | 'local-linux';
  readonly distro: string;
  readonly username?: string;
  readonly runnerPath: string;
  readonly nodeExecutable?: string;
  readonly wslExecutable?: string;
  /** Idle self-termination lease inside WSL runner (defaults to 180s with 30s heartbeat so crashed hosts leave 0 orphans). */
  readonly runnerLeaseMs?: number;
  readonly heartbeatIntervalMs?: number;
  readonly onAuthorizeProxyHost?: (host: string, port: number) => Promise<boolean>;
  readonly onStderr?: (line: string) => void;
}

interface InFlightCall {
  readonly resolve: (value: unknown) => void;
  readonly reject: (err: Error) => void;
  readonly timer: NodeJS.Timeout;
}

const DEFAULT_RUNNER_LEASE_MS = 180_000;
const DEFAULT_HEARTBEAT_MS = 30_000;

/**
 * Persistent NDJSON RPC transport connecting the DSH Host plugin to `wsl-runner`.
 *
 * Lifecycle & leak-prevention invariants:
 * - Always uses `shell: false` and passes `--cd ~` to `wsl.exe` so the Linux runner NEVER holds
 *   an open working-directory handle on any Windows NTFS plugin or project folder.
 * - Sends periodic unref'd `ping` heartbeats paired with `DSH_WSL_RUNNER_LEASE_MS`, plus a
 *   graceful `shutdown` RPC on `dispose()` and a synchronous `process.once('exit')` failsafe
 *   so disabling/uninstalling the plugin or exiting DSH leaves ZERO orphan processes or locks.
 * - Never executes `wsl.exe --shutdown` or kills unrelated `wsl.exe` / user terminal sessions.
 */
export class WslTransport {
  private readonly options: WslTransportOptions;
  private child: ChildProcessWithoutNullStreams | undefined;
  private rl: readline.Interface | undefined;
  private heartbeatTimer: NodeJS.Timeout | undefined;
  private processExitHook: (() => void) | undefined;
  private readonly inFlight = new Map<string, InFlightCall>();
  private disposed = false;

  constructor(options: WslTransportOptions) {
    if (options.mode === 'wsl' && !isValidIdentifier(options.distro)) {
      failSandbox('INVALID_SETUP', `Invalid WSL distribution name: ${options.distro}`);
    }
    this.options = options;
  }

  isRunning(): boolean {
    return Boolean(this.child && !this.child.killed && this.child.exitCode === null);
  }

  getChildPid(): number | undefined {
    return this.child?.pid;
  }

  private clearHeartbeatAndExitHook(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = undefined;
    }
    if (this.processExitHook) {
      process.off('exit', this.processExitHook);
      this.processExitHook = undefined;
    }
  }

  async ensureStarted(): Promise<void> {
    if (this.disposed) {
      failSandbox('BACKEND_UNAVAILABLE', 'WslTransport has been disposed');
    }
    if (this.isRunning()) return;

    const leaseMs = this.options.runnerLeaseMs ?? DEFAULT_RUNNER_LEASE_MS;
    const env: NodeJS.ProcessEnv = { ...process.env };
    if (leaseMs > 0) {
      env.DSH_WSL_RUNNER_LEASE_MS = String(leaseMs);
    }

    let command: string;
    let args: string[];

    if (this.options.mode === 'wsl') {
      command = this.options.wslExecutable ?? 'wsl.exe';
      // `--cd ~` prevents wsl.exe from inheriting the Windows host CWD on NTFS (zero Windows folder lock!)
      args = ['-d', this.options.distro, '--cd', '~'];
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

    const onProcessExit = (): void => {
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

    child.stderr.on('data', (chunk: Buffer) => {
      const text = chunk.toString('utf8').trim();
      if (text) this.options.onStderr?.(text);
    });

    const rejectAll = (reason: string): void => {
      this.clearHeartbeatAndExitHook();
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

      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(line) as Record<string, unknown>;
      } catch {
        return;
      }

      if (parsed.kind === 'callback') {
        void this.handleRunnerCallback(parsed as unknown as RpcCallbackRequest);
        return;
      }

      const resp = parsed as unknown as RpcResponse;
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

    if (leaseMs > 0) {
      const interval = Math.max(2000, Math.min(this.options.heartbeatIntervalMs ?? DEFAULT_HEARTBEAT_MS, Math.floor(leaseMs / 3)));
      this.heartbeatTimer = setInterval(() => {
        if (!this.isRunning()) return;
        void this.call('ping', {}, 5_000).catch(() => {});
      }, interval);
      this.heartbeatTimer.unref();
    }
  }

  private async handleRunnerCallback(cb: RpcCallbackRequest): Promise<void> {
    let allowed = false;
    if (cb.method === 'proxy.authorizeHost' && this.options.onAuthorizeProxyHost) {
      try {
        allowed = await this.options.onAuthorizeProxyHost(cb.params.host, cb.params.port);
      } catch {
        allowed = false;
      }
    }
    if (this.child && !this.child.killed && this.child.stdin.writable) {
      const response: RpcCallbackResponse = {
        kind: 'callback-response',
        id: cb.id,
        ok: true,
        result: { allowed },
      };
      this.child.stdin.write(JSON.stringify(response) + '\n');
    }
  }

  async call<TResult = unknown>(
    method: string,
    params: Record<string, unknown> = {},
    timeoutMs = 150_000,
  ): Promise<TResult> {
    await this.ensureStarted();
    const child = this.child;
    if (!child || !child.stdin.writable) {
      failSandbox('BACKEND_UNAVAILABLE', 'WSL runner stdin is not writable');
    }

    const id = randomUUID();
    const frame: RpcRequest = { id, method, params };
    const serialized = JSON.stringify(frame) + '\n';
    if (Buffer.byteLength(serialized, 'utf8') > MAX_RPC_FRAME_BYTES) {
      failSandbox('INVALID_ACTION', `RPC frame exceeds ${MAX_RPC_FRAME_BYTES} bytes`);
    }

    return new Promise<TResult>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.inFlight.delete(id);
        reject(new SandboxError('TIMEOUT', `WSL runner RPC '${method}' timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      timer.unref();

      this.inFlight.set(id, {
        resolve: resolve as (value: unknown) => void,
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

  async invalidate(
    minValidGeneration: number,
    scope?: { readonly sessionId?: string; readonly terminalId?: string },
  ): Promise<number> {
    if (!this.isRunning()) return 0;
    try {
      const res = await this.call<{ killedCount: number }>(
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

  async dispose(): Promise<void> {
    if (this.disposed) return;
    this.disposed = true;
    this.clearHeartbeatAndExitHook();

    const child = this.child;

    // 1. Send graceful shutdown RPC first so in-WSL runner closes proxy sockets, kills owned PGIDs,
    //    and deletes /tmp/dsh-wsl-* cleanly before stdio closes.
    if (child && !child.killed && child.exitCode === null && child.stdin.writable) {
      try {
        const id = randomUUID();
        const frame: RpcRequest = { id, method: 'shutdown', params: {} };
        await new Promise<void>((resolve) => {
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
    this.rl?.close();
    this.rl = undefined;

    for (const [id, call] of this.inFlight) {
      clearTimeout(call.timer);
      call.reject(new SandboxError('CANCELLED', 'WslTransport disposed'));
      this.inFlight.delete(id);
    }

    if (child && !child.killed && child.exitCode === null) {
      await new Promise<void>((resolve) => {
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
  }
}
