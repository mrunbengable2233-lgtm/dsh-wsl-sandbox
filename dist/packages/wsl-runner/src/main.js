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
  formatRunnerWireLog,
  isSandboxError,
                      
  MAX_RPC_FRAME_BYTES,
  normalizeLogLevel,
                   
                      
                            
  RotatingNdjsonSink,
                          
                           
                  
                   
                      
  StructuredLogger,
                          
  UdsAllowlistProxy,
} from '../../core/src/index.js';
import { ConfinedFsService } from './fs-service.js';
import {
  collectWslFootprint,
  forceRemoveReadOnlyTree,
  pruneWorkspaceCaches,
  resolveEphemeralRamTmpRoot,
  sweepOrphanedRunnerTempDirs,
  writeDeduplicatedReadOnlyBackup,
} from './hygiene.js';
import { runEnvironmentProbe } from './probe.js';
import { ConfinedProcManager } from './proc-manager.js';
import { ConfinedTerminalManager } from './pty-manager.js';

const runnerId = randomUUID();
const startedAt = Date.now();
const leaseMs = Number(process.env.DSH_WSL_RUNNER_LEASE_MS || 0);

const runnerLogDir =
  process.env.DSH_WSL_RUNNER_LOG_DIR || path.join(os.homedir(), '.config', 'dsh-wsl-sandbox', 'logs');
// When paired with Host WslTransport, runner logs stream over memory stderr pipe to Host's coalesced sink
// so we NEVER double-write every log line to both WSL VHDX ext4 and Windows NTFS!
const runnerFileSink =
  process.env.DSH_WSL_RUNNER_FILE_LOG === '1' && process.env.DSH_WSL_DISABLE_FILE_LOG !== '1'
    ? new RotatingNdjsonSink({
        logDir: runnerLogDir,
        fileName: 'wsl-runner.ndjson',
        maxBytes: 5 * 1024 * 1024,
        maxFiles: 3,
        flushIntervalMs: 2500,
      })
    : undefined;

const runnerLogger = new StructuredLogger({
  source: 'wsl-runner',
  level: normalizeLogLevel(process.env.DSH_WSL_LOG_LEVEL, 'info'),
  fileSink: runnerFileSink,
  preloadFromDisk: false,
  onEntry: (entry) => {
    try {
      process.stderr.write(formatRunnerWireLog(entry));
    } catch {
      // ignore broken stderr during teardown
    }
  },
});

const rlog = runnerLogger.child('runner');
rlog.info('runner.start', 'WSL sandbox runner started', {
  runnerId,
  nodeVersion: process.version,
  nodeExecPath: process.execPath,
  leaseMs,
  logFilePath: runnerLogger.getLogFilePath() ?? null,
});

const fsService = new ConfinedFsService();
const procManager = new ConfinedProcManager();
const termManager = new ConfinedTerminalManager(procManager);

const proxyDir = fs.mkdtempSync(path.join(resolveEphemeralRamTmpRoot(), 'dsh-wsl-proxy-'));
fs.chmodSync(proxyDir, 0o700);
fs.writeFileSync(path.join(proxyDir, 'owner.pid'), `${process.pid}\n`, { mode: 0o600 });
const managedProxySocketPath = path.join(proxyDir, 'proxy.sock');

// Sweep any `/tmp/dsh-wsl-runner-*` or `/tmp/dsh-wsl-proxy-*` orphaned by a prior SIGKILL (`kill -9`)
// or `wsl.exe --terminate`, plus workspace package caches untouched for > 30 days.
try {
  const swept = sweepOrphanedRunnerTempDirs({
    excludeDirs: [procManager.getRuntimeDir(), proxyDir],
  });
  const cacheSweep = pruneWorkspaceCaches({
    maxAgeDays: Number(process.env.DSH_WSL_CACHE_MAX_AGE_DAYS || 30),
  });
  if (swept.sweptDirs.length > 0 || cacheSweep.removedDirs.length > 0) {
    rlog.info('runner.hygiene_sweep', 'Cleaned stale crash temp dirs and expired workspace caches', {
      sweptTempDirs: swept.sweptDirs.length,
      prunedCacheDirs: cacheSweep.removedDirs.length,
    });
  }
} catch {
  // Never block runner startup on best-effort hygiene sweep
}
let managedProxy                               ;
let interactiveProxyApproval = false;

const pendingCallbacks = new Map 
         
                                                                
 ();

let lastActivity = Date.now();

function sendFrame(frame                                  )       {
  process.stdout.write(JSON.stringify(frame) + '\n');
}

function send(resp             )       {
  sendFrame(resp);
}

function requestHostProxyAuthorization(host        , port        )                   {
  if (!interactiveProxyApproval) {
    return Promise.resolve(false);
  }
  const id = `cb-${randomUUID()}`;
  return new Promise         ((resolve) => {
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

async function configureManagedProxy(params                      )                                                     {
  interactiveProxyApproval = Boolean(params.enableInteractiveApproval);

  if (!params.enabled) {
    if (managedProxy) {
      await managedProxy.stop();
      managedProxy = undefined;
      rlog.info('proxy.stopped', 'Managed UDS allowlist proxy stopped');
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
    rlog.debug('proxy.updated', 'Managed UDS allowlist proxy policy updated', {
      customDomains: (params.customAllowedDomains ?? []).length,
      hasUpstreamProxy: Boolean(params.upstreamProxy),
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
    onDenied: ({ host, port, reason }) => {
      runnerLogger.log('warn', {
        component: 'proxy',
        event: 'proxy.blocked',
        message: `Blocked outbound connection to ${host}:${port} (${reason})`,
        data: { host, port, reason },
      });
    },
    onAllowed: ({ host, port, via }) => {
      runnerLogger.log('debug', {
        component: 'proxy',
        event: 'proxy.allowed',
        message: `Allowed outbound connection to ${host}:${port} via ${via}`,
        data: { host, port, via },
      });
    },
  });
  await proxy.start();
  managedProxy = proxy;
  rlog.info('proxy.started', 'Managed UDS allowlist proxy started', {
    socketPath: proxy.getSocketPath(),
    hasUpstreamProxy: Boolean(params.upstreamProxy),
  });
  return { enabled: true, socketPath: proxy.getSocketPath() };
}

function withManagedProxy(params                )                 {
  if (
    params.networkMode === 'allowlist-proxy' &&
    !params.proxySocketHostPath &&
    managedProxy
  ) {
    return { ...params, proxySocketHostPath: managedProxy.getSocketPath() };
  }
  return params;
}

async function handleRequest(req            )                   {
  lastActivity = Date.now();
  const p = (req.params ?? {})                           ;

  switch (req.method) {
    case 'ping':
      return {
        ok: true,
        pid: process.pid,
        runnerId,
        nodeVersion: process.version,
        nodeExecPath: process.execPath,
        uptimeMs: Date.now() - startedAt,
        activeProcs: procManager.getActiveCount(),
        proxyEnabled: Boolean(managedProxy),
      };

    case 'probe': {
      const t0 = Date.now();
      const probeRes = await runEnvironmentProbe(p                          , runnerId);
      rlog.info(
        'probe.completed',
        `Environment probe completed (ready=${probeRes.sandboxReady}, enforcement=${probeRes.enforcement})`,
        {
          distribution: probeRes.distribution,
          uid: probeRes.uid,
          username: probeRes.username,
          workspaceRoot: probeRes.workspaceRoot,
          sandboxReady: probeRes.sandboxReady,
          enforcement: probeRes.enforcement,
          nodeVersion: process.version,
          nodeExecPath: process.execPath,
        },
        { sessionId: probeRes.sessionId, durationMs: Date.now() - t0 },
      );
      return {
        ...probeRes,
        nodeVersion: process.version,
        nodeExecPath: process.execPath,
      };
    }

    case 'proxy.configure':
      return configureManagedProxy(p                                   );

    case 'proxy.approveDomain': {
      const host = String(p.host ?? '').trim();
      if (managedProxy && host) {
        managedProxy.addSessionAllowedDomain(host);
        runnerLogger.log('info', {
          component: 'proxy',
          event: 'proxy.domainApproved',
          message: `Approved domain '${host}' for current runner session`,
          data: { host },
        });
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
      return fsService.stat(p                                                                                  );

    case 'fs.read':
      return fsService.read(
        p                                                                                                                   ,
      );

    case 'fs.write':
      return fsService.write(p                                                                         );

    case 'fs.edit':
      return fsService.edit(
        p                                                                                                                ,
      );

    case 'fs.list':
      return fsService.list(p                                                                             );

    case 'fs.glob':
      return fsService.glob(p                                                                                              );

    case 'fs.grep':
      return fsService.grep(
        p                                                                                                                                       ,
      );

    case 'fs.delete':
      return fsService.delete(p                                                        );

    case 'fs.move':
      return fsService.move(p                                                                    );

    case 'proc.exec': {
      const execParams = withManagedProxy({ ...(p                             ), ownerRunnerId: runnerId });
      const t0 = Date.now();
      const res = await procManager.exec(execParams);
      const dur = Date.now() - t0;
      const lvl = res.timedOut || res.sandbox.denied || res.sandbox.runnerFailed ? 'warn' : 'info';
      runnerLogger.log(lvl, {
        component: 'proc',
        event: 'proc.exec',
        message: `Sandbox exec finished (exit=${res.exitCode}, timedOut=${res.timedOut}, denied=${res.sandbox.denied})`,
        sessionId: execParams.binding?.sessionId,
        durationMs: dur,
        data: {
          cwd: execParams.cwd,
          mode: execParams.mode,
          networkMode: execParams.networkMode,
          exitCode: res.exitCode,
          signal: res.signal,
          timedOut: res.timedOut,
          aborted: res.aborted,
          denied: res.sandbox.denied,
          denialMatches: res.sandbox.denialMatches,
        },
      });
      return res;
    }

    case 'proc.kill':
      return { killed: await procManager.kill(String(p.execId ?? '')) };

    case 'proc.list':
      return {
        runnerId,
        active: procManager.listActive(typeof p.sessionId === 'string' ? p.sessionId : undefined),
        terminals: termManager.listSessions(typeof p.sessionId === 'string' ? p.sessionId : undefined),
      };

    case 'term.exec': {
      const tp = p                                 ;
      const t0 = Date.now();
      const res = await termManager.exec({ ...withManagedProxy({ ...tp, ownerRunnerId: runnerId }), terminalId: tp.terminalId });
      const dur = Date.now() - t0;
      const lvl = res.timedOut || res.sandbox.denied ? 'warn' : 'info';
      runnerLogger.log(lvl, {
        component: 'terminal',
        event: 'term.exec',
        message: `Terminal '${tp.terminalId}' exec finished (exit=${res.exitCode}, cwd=${res.cwd})`,
        sessionId: tp.binding?.sessionId,
        durationMs: dur,
        data: {
          terminalId: tp.terminalId,
          cwd: res.cwd,
          exitCode: res.exitCode,
          timedOut: res.timedOut,
          denied: res.sandbox.denied,
        },
      });
      return res;
    }

    case 'term.reset':
      return {
        reset: await termManager.reset(
          String(p.terminalId ?? ''),
          typeof p.sessionId === 'string' ? p.sessionId : undefined,
        ),
      };

    case 'term.kill': {
      const sid = String(p.sessionId ?? '');
      const tid = String(p.terminalId ?? '');
      if (!sid || !tid) return { killedCount: 0 };
      const killedCount = await procManager.killTerminal(sid, tid);
      return { killedCount };
    }

    case 'invalidate': {
      const gen = Number(p.generation ?? Number.MAX_SAFE_INTEGER);
      const sessionId = typeof p.sessionId === 'string' && p.sessionId ? p.sessionId : undefined;
      const terminalId = typeof p.terminalId === 'string' && p.terminalId ? p.terminalId : undefined;
      if (sessionId) {
        termManager.clearSession(sessionId, terminalId);
      } else if (!terminalId) {
        termManager.clearAll();
      }
      if (!terminalId) {
        managedProxy?.clearSessionAllowedDomains();
      }
      const killedCount = await procManager.invalidateGeneration(gen, { sessionId, terminalId });
      rlog.info(
        'session.invalidate',
        `Invalidated generation < ${gen} (killed=${killedCount})`,
        { generation: gen, killedCount, scopedSessionId: sessionId ?? null, scopedTerminalId: terminalId ?? null },
        { sessionId },
      );
      return { killedCount, scopedSessionId: sessionId ?? null, scopedTerminalId: terminalId ?? null };
    }

    case 'logs.tail': {
      const entries = runnerLogger.query(p                             );
      return {
        ok: true,
        entries,
        level: runnerLogger.getLevel(),
        bufferedCount: runnerLogger.getBufferedCount(),
      };
    }

    case 'logs.setLevel': {
      const nextLvl = normalizeLogLevel(p.level, runnerLogger.getLevel());
      runnerLogger.setLevel(nextLvl);
      return { ok: true, level: nextLvl };
    }

    case 'logs.clear': {
      return { ok: true, ...runnerLogger.clear() };
    }

    case 'shutdown': {
      rlog.info('runner.shutdown', 'Graceful shutdown requested by host');
      // Respond cleanly first so host transport knows graceful cleanup completed, then exit
      setImmediate(() => {
        void shutdown();
      });
      return { ok: true, runnerId, shuttingDown: true };
    }

    case 'env.doctor': {
      const { runDoctor } = await import('../../bootstrap/src/doctor.js');
      return runDoctor({
        upstreamProxy: typeof p.upstreamProxy === 'string' && p.upstreamProxy ? p.upstreamProxy : undefined,
        strictWsl2: Boolean(p.strictWsl2),
        profile: typeof p.profile === 'string' ? (p.profile                                     ) : undefined,
      });
    }

    case 'cache.clear': {
      const cacheBase = path.join(os.homedir(), '.cache', 'dsh-wsl-sandbox');
      let clearedEntries = 0;
      if (fs.existsSync(cacheBase)) {
        const st = fs.lstatSync(cacheBase);
        if (!st.isSymbolicLink() && st.isDirectory()) {
          clearedEntries = fs.readdirSync(cacheBase).length;
          forceRemoveReadOnlyTree(cacheBase);
        }
      }
      const swept = sweepOrphanedRunnerTempDirs({
        excludeDirs: [procManager.getRuntimeDir(), proxyDir],
      });
      rlog.info('cache.cleared', `Cleared ${clearedEntries} sandbox cache dirs and ${swept.sweptDirs.length} orphan temp dirs`, {
        clearedEntries,
        sweptTempDirs: swept.sweptDirs.length,
      });
      return { ok: true, cacheBase, clearedEntries, sweptTempDirs: swept.sweptDirs };
    }

    case 'wsl.footprint': {
      return {
        ok: true,
        ...collectWslFootprint(),
      };
    }

    case 'wsl.backupConfigs': {
      const backupDir = path.join(os.homedir(), '.config', 'dsh-wsl-sandbox', 'backups');
      fs.mkdirSync(backupDir, { recursive: true, mode: 0o700 });
      const ts = new Date().toISOString().replace(/[:.]/g, '-');
      const savedFiles           = [];
      let wslConfContent                = null;
      let fstabContent                = null;
      let drvfsMountsContent                = null;

      if (fs.existsSync('/etc/wsl.conf')) {
        wslConfContent = fs.readFileSync('/etc/wsl.conf', 'utf8');
        const res = writeDeduplicatedReadOnlyBackup({
          backupDir,
          origFileName: 'wsl.conf.orig',
          rollingPrefix: 'wsl.conf',
          rollingExt: 'bak',
          timestamp: ts,
          content: wslConfContent,
          maxRolling: 5,
        });
        savedFiles.push(...res.savedPaths);
      } else {
        const absentPath = path.join(backupDir, 'wsl.conf.orig.absent');
        if (!fs.existsSync(absentPath) && !fs.existsSync(path.join(backupDir, 'wsl.conf.orig'))) {
          fs.writeFileSync(absentPath, `# /etc/wsl.conf absent at initial snapshot (${ts})\n`, { mode: 0o400 });
          try { fs.chmodSync(absentPath, 0o400); } catch { /* best effort */ }
          savedFiles.push(absentPath);
        }
      }

      if (fs.existsSync('/etc/fstab')) {
        fstabContent = fs.readFileSync('/etc/fstab', 'utf8');
        const res = writeDeduplicatedReadOnlyBackup({
          backupDir,
          origFileName: 'fstab.orig',
          rollingPrefix: 'fstab',
          rollingExt: 'bak',
          timestamp: ts,
          content: fstabContent,
          maxRolling: 5,
        });
        savedFiles.push(...res.savedPaths);
      }

      if (fs.existsSync('/proc/mounts')) {
        try {
          drvfsMountsContent = fs
            .readFileSync('/proc/mounts', 'utf8')
            .split('\n')
            .filter((line) => /drvfs|9p|\/mnt\//.test(line))
            .join('\n');
          const res = writeDeduplicatedReadOnlyBackup({
            backupDir,
            origFileName: 'drvfs-mounts.orig.txt',
            rollingPrefix: 'drvfs-mounts',
            rollingExt: 'txt',
            timestamp: ts,
            content: drvfsMountsContent + '\n',
            maxRolling: 5,
          });
          savedFiles.push(...res.savedPaths);
        } catch {
          // ignore unreadable /proc/mounts
        }
      }

      return {
        ok: true,
        wslInternalBackupDir: backupDir,
        wslSavedFiles: savedFiles,
        wslConfContent,
        fstabContent,
        drvfsMountsContent,
        sandboxTmpfsMntLocked: true,
      };
    }

    case 'wsl.listBackups': {
      const backupDir = path.join(os.homedir(), '.config', 'dsh-wsl-sandbox', 'backups');
      const entries = fs.existsSync(backupDir) ? fs.readdirSync(backupDir).sort() : [];
      let automountDisabledInWslConf = false;
      if (fs.existsSync('/etc/wsl.conf')) {
        try {
          const raw = fs.readFileSync('/etc/wsl.conf', 'utf8');
          automountDisabledInWslConf = /\[automount\][\s\S]*?enabled\s*=\s*false/i.test(raw);
        } catch {
          // ignore
        }
      }
      return {
        ok: true,
        backupDir,
        entries,
        sandboxTmpfsMntLocked: true,
        automountDisabledInWslConf,
      };
    }

    default:
      throw Object.assign(new Error(`Unknown RPC method: ${req.method}`), { code: 'INVALID_ACTION' });
  }
}

let shuttingDown = false;

function cleanupTempArtifactsSync()       {
  runnerLogger.dispose();
  procManager.cleanupSync();
  try {
    fs.rmSync(proxyDir, { recursive: true, force: true });
  } catch {
    // ignore
  }
}

async function shutdown()                {
  if (shuttingDown) return;
  shuttingDown = true;

  // Hard exit watchdog guarantees the WSL runner can NEVER hang on exit/disable
  const watchdog = setTimeout(() => {
    cleanupTempArtifactsSync();
    process.exit(0);
  }, 3000);
  watchdog.unref();

  for (const [, cb] of pendingCallbacks) {
    clearTimeout(cb.timer);
    cb.resolve(false);
  }
  pendingCallbacks.clear();

  if (managedProxy) {
    const p = managedProxy;
    managedProxy = undefined;
    await p.stop().catch(() => {});
  }
  await procManager.disposeAll().catch(() => {});
  cleanupTempArtifactsSync();
  clearTimeout(watchdog);
  process.exit(0);
}

process.on('exit', () => {
  cleanupTempArtifactsSync();
});

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

  let parsed                         ;
  try {
    parsed = JSON.parse(line)                           ;
  } catch {
    send({
      id: 'unknown',
      ok: false,
      error: { code: 'INVALID_ACTION', message: 'Malformed JSON frame' },
    });
    return;
  }

  if (parsed.kind === 'callback-response') {
    const cbResp = parsed                                  ;
    const entry = pendingCallbacks.get(cbResp.id);
    if (entry) {
      clearTimeout(entry.timer);
      pendingCallbacks.delete(cbResp.id);
      entry.resolve(Boolean(cbResp.ok && cbResp.result?.allowed));
    }
    return;
  }

  const req = parsed                         ;

  void handleRequest(req).then(
    (result) => send({ id: req.id, ok: true, result }),
    (err         ) => {
      if (isSandboxError(err)) {
        send({
          id: req.id,
          ok: false,
          error: { code: err.code, message: err.message, details: err.details },
        });
      } else {
        const anyErr = err                                       ;
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
process.stdin.on('end', () => {
  void shutdown();
});
process.stdin.on('close', () => {
  void shutdown();
});
process.on('SIGHUP', () => void shutdown());
process.on('SIGTERM', () => void shutdown());
process.on('SIGINT', () => void shutdown());
