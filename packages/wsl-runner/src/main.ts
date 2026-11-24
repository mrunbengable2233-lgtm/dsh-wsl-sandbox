#!/usr/bin/env node
/**
 * Persistent in-distro NDJSON Runner for dsh-wsl-sandbox.
 * Communicates with the Windows/Host DSH plugin via line-delimited JSON over stdio.
 * Zero 9P dependency, zero systemd requirement, clean PGID teardown on stdin EOF or heartbeat timeout.
 */
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import {
  isSandboxError,
  MAX_RPC_FRAME_BYTES,
  type ProbeParams,
  type ProcExecParams,
  type ProxyConfigureParams,
  type RpcCallbackRequest,
  type RpcCallbackResponse,
  type RpcRequest,
  type RpcResponse,
  type SessionBinding,
  type TerminalExecParams,
  UdsAllowlistProxy,
} from '../../core/src/index.ts';
import { ConfinedFsService } from './fs-service.ts';
import { runEnvironmentProbe } from './probe.ts';
import { ConfinedProcManager } from './proc-manager.ts';
import { ConfinedTerminalManager } from './pty-manager.ts';

const runnerId = randomUUID();
const startedAt = Date.now();
const leaseMs = Number(process.env.DSH_WSL_RUNNER_LEASE_MS || 0);

const fsService = new ConfinedFsService();
const procManager = new ConfinedProcManager();
const termManager = new ConfinedTerminalManager(procManager);

const proxyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-wsl-proxy-'));
fs.chmodSync(proxyDir, 0o700);
const managedProxySocketPath = path.join(proxyDir, 'proxy.sock');
let managedProxy: UdsAllowlistProxy | undefined;
let interactiveProxyApproval = false;

const pendingCallbacks = new Map<
  string,
  { resolve: (allowed: boolean) => void; timer: NodeJS.Timeout }
>();

let lastActivity = Date.now();

function sendFrame(frame: RpcResponse | RpcCallbackRequest): void {
  process.stdout.write(JSON.stringify(frame) + '\n');
}

function send(resp: RpcResponse): void {
  sendFrame(resp);
}

function requestHostProxyAuthorization(host: string, port: number): Promise<boolean> {
  if (!interactiveProxyApproval) {
    return Promise.resolve(false);
  }
  const id = `cb-${randomUUID()}`;
  return new Promise<boolean>((resolve) => {
    const timer = setTimeout(() => {
      pendingCallbacks.delete(id);
      resolve(false);
    }, 65_000);
    timer.unref();
    pendingCallbacks.set(id, { resolve, timer });
    sendFrame({
      kind: 'callback',
      id,
      method: 'proxy.authorizeHost',
      params: { host, port },
    });
  });
}

async function configureManagedProxy(params: ProxyConfigureParams): Promise<{ enabled: boolean; socketPath?: string }> {
  interactiveProxyApproval = Boolean(params.enableInteractiveApproval);

  if (!params.enabled) {
    if (managedProxy) {
      await managedProxy.stop();
      managedProxy = undefined;
    }
    return { enabled: false };
  }

  if (managedProxy) {
    managedProxy.updatePolicy({
      customAllowedDomains: params.customAllowedDomains ?? [],
      upstreamProxy: params.upstreamProxy ?? '',
      localLabCidrs: params.localLabCidrs ?? [],
      localLabPorts: params.localLabPorts ?? [],
    });
    return { enabled: true, socketPath: managedProxy.getSocketPath() };
  }

  const proxy = new UdsAllowlistProxy({
    socketPath: managedProxySocketPath,
    customAllowedDomains: params.customAllowedDomains,
    upstreamProxy: params.upstreamProxy,
    localLabCidrs: params.localLabCidrs,
    localLabPorts: params.localLabPorts,
    authorizeUnknownHost: (host, port) => requestHostProxyAuthorization(host, port),
  });
  await proxy.start();
  managedProxy = proxy;
  return { enabled: true, socketPath: proxy.getSocketPath() };
}

function withManagedProxy(params: ProcExecParams): ProcExecParams {
  if (
    params.networkMode === 'allowlist-proxy' &&
    !params.proxySocketHostPath &&
    managedProxy
  ) {
    return { ...params, proxySocketHostPath: managedProxy.getSocketPath() };
  }
  return params;
}

async function handleRequest(req: RpcRequest): Promise<unknown> {
  lastActivity = Date.now();
  const p = (req.params ?? {}) as Record<string, unknown>;

  switch (req.method) {
    case 'ping':
      return {
        ok: true,
        runnerId,
        uptimeMs: Date.now() - startedAt,
        activeProcs: procManager.getActiveCount(),
        proxyEnabled: Boolean(managedProxy),
      };

    case 'probe':
      return runEnvironmentProbe(p as unknown as ProbeParams, runnerId);

    case 'proxy.configure':
      return configureManagedProxy(p as unknown as ProxyConfigureParams);

    case 'proxy.approveDomain': {
      const host = String(p.host ?? '').trim();
      if (managedProxy && host) {
        managedProxy.addSessionAllowedDomain(host);
        return { approved: true, host };
      }
      return { approved: false, host };
    }

    case 'proxy.status':
      return {
        enabled: Boolean(managedProxy),
        socketPath: managedProxy?.getSocketPath(),
      };

    case 'fs.stat':
      return fsService.stat(p as unknown as { binding: SessionBinding; path: string; maskEnvSecrets?: boolean });

    case 'fs.read':
      return fsService.read(
        p as unknown as { binding: SessionBinding; path: string; offset?: number; limit?: number; maskEnvSecrets?: boolean },
      );

    case 'fs.write':
      return fsService.write(p as unknown as { binding: SessionBinding; path: string; content: string });

    case 'fs.edit':
      return fsService.edit(
        p as unknown as { binding: SessionBinding; path: string; oldText: string; newText: string; replaceAll?: boolean },
      );

    case 'fs.list':
      return fsService.list(p as unknown as { binding: SessionBinding; path: string; maxEntries?: number });

    case 'fs.glob':
      return fsService.glob(p as unknown as { binding: SessionBinding; pattern: string; cwd?: string; maxResults?: number });

    case 'fs.grep':
      return fsService.grep(
        p as unknown as { binding: SessionBinding; query: string; cwd?: string; regex?: boolean; maxMatches?: number; maskEnvSecrets?: boolean },
      );

    case 'fs.delete':
      return fsService.delete(p as unknown as { binding: SessionBinding; path: string });

    case 'fs.move':
      return fsService.move(p as unknown as { binding: SessionBinding; from: string; to: string });

    case 'proc.exec':
      return procManager.exec(withManagedProxy(p as unknown as ProcExecParams));

    case 'proc.kill':
      return { killed: await procManager.kill(String(p.execId ?? '')) };

    case 'term.exec': {
      const tp = p as unknown as TerminalExecParams;
      return termManager.exec({ ...withManagedProxy(tp), terminalId: tp.terminalId });
    }

    case 'term.reset':
      return { reset: termManager.reset(String(p.terminalId ?? '')) };

    case 'invalidate': {
      const gen = Number(p.generation ?? Number.MAX_SAFE_INTEGER);
      termManager.clearAll();
      managedProxy?.clearSessionAllowedDomains();
      const killedCount = await procManager.invalidateGeneration(gen);
      return { killedCount };
    }

    default:
      throw Object.assign(new Error(`Unknown RPC method: ${req.method}`), { code: 'INVALID_ACTION' });
  }
}

async function shutdown(): Promise<void> {
  for (const [, cb] of pendingCallbacks) {
    clearTimeout(cb.timer);
    cb.resolve(false);
  }
  pendingCallbacks.clear();
  if (managedProxy) {
    await managedProxy.stop().catch(() => {});
    managedProxy = undefined;
  }
  await procManager.disposeAll();
  fs.rmSync(proxyDir, { recursive: true, force: true });
  process.exit(0);
}

if (leaseMs > 0) {
  const leaseTimer = setInterval(() => {
    if (Date.now() - lastActivity > leaseMs) {
      void shutdown();
    }
  }, Math.min(5000, Math.max(500, Math.floor(leaseMs / 3))));
  leaseTimer.unref();
}

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });

rl.on('line', (line) => {
  if (!line.trim()) return;
  if (Buffer.byteLength(line, 'utf8') > MAX_RPC_FRAME_BYTES) {
    send({
      id: 'unknown',
      ok: false,
      error: { code: 'INVALID_ACTION', message: `Frame exceeds ${MAX_RPC_FRAME_BYTES} bytes` },
    });
    return;
  }

  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(line) as Record<string, unknown>;
  } catch {
    send({
      id: 'unknown',
      ok: false,
      error: { code: 'INVALID_ACTION', message: 'Malformed JSON frame' },
    });
    return;
  }

  if (parsed.kind === 'callback-response') {
    const cbResp = parsed as unknown as RpcCallbackResponse;
    const entry = pendingCallbacks.get(cbResp.id);
    if (entry) {
      clearTimeout(entry.timer);
      pendingCallbacks.delete(cbResp.id);
      entry.resolve(Boolean(cbResp.ok && cbResp.result?.allowed));
    }
    return;
  }

  const req = parsed as unknown as RpcRequest;

  void handleRequest(req).then(
    (result) => send({ id: req.id, ok: true, result }),
    (err: unknown) => {
      if (isSandboxError(err)) {
        send({
          id: req.id,
          ok: false,
          error: { code: err.code, message: err.message, details: err.details },
        });
      } else {
        const anyErr = err as { code?: string; message?: string };
        send({
          id: req.id,
          ok: false,
          error: {
            code: anyErr?.code === 'INVALID_ACTION' ? 'INVALID_ACTION' : 'PROCESS_EXIT',
            message: anyErr?.message ?? String(err),
          },
        });
      }
    },
  );
});

rl.on('close', () => {
  void shutdown();
});

process.on('SIGTERM', () => void shutdown());
process.on('SIGINT', () => void shutdown());
