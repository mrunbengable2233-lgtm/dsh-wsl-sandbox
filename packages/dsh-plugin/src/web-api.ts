import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import type { IncomingMessage, ServerResponse } from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {
  type ApprovalDecisionKind,
  type AuthorizedDeviceNode,
  type AuthorizedShare,
  failSandbox,
  isSandboxError,
  isValidLogLevel,
  type LogLevel,
  type LogSource,
  type StructuredLogger,
} from '../../core/src/index.ts';
import type { ApprovalBridge } from './approval-bridge.ts';
import {
  type BasicConfigPatch,
  type ConfigStore,
  getDefaultBackupDir,
  hardenPrivatePath,
  validateBackupDirPath,
} from './config-store.ts';
import {
  type DshCordisContext,
  type DshHttpHandler,
  type DshHttpRequest,
  type DshHttpResponse,
  getOptionalService,
} from './cordis-types.ts';
import {
  computeRemoveAgentsMdContent,
  computeUpsertAgentsMdContent,
  removeAgentsMdWslSection,
  upsertAgentsMdWslSection,
} from './prompt-injector.ts';
import { findPluginPackageRoot, type WslSandboxSessionManager } from './tools.ts';
import { renderWslSandboxUiHtml } from './web-ui-entry.ts';
import {
  discoverWslDistrosAsync,
  isHostSpawnDisabled,
  isInsideLxssBasePath,
  probeWslDistroUserAsync,
} from './wsl-discovery.ts';

export interface WebApiDeps {
  readonly configStore: ConfigStore;
  readonly sessionManager: WslSandboxSessionManager;
  readonly approvalBridge: ApprovalBridge;
  readonly logger?: StructuredLogger;
  readonly skipHttpRouter?: boolean;
  readonly skipWebServer?: boolean;
}

interface RouteEntry {
  readonly method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  readonly pattern: string;
  readonly regex: RegExp;
  readonly paramNames: readonly string[];
  readonly handler: DshHttpHandler;
}

function compilePattern(pattern: string): { regex: RegExp; paramNames: string[] } {
  const paramNames: string[] = [];
  const escaped = pattern
    .split('/')
    .map((seg) => {
      if (seg.startsWith(':')) {
        paramNames.push(seg.slice(1));
        return '([^/]+)';
      }
      return seg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    })
    .join('/');
  return { regex: new RegExp(`^${escaped}$`), paramNames };
}

function sendError(res: DshHttpResponse, err: unknown): void {
  if (isSandboxError(err)) {
    res.status(err.code === 'POLICY_BLOCK' ? 403 : 400).json({
      ok: false,
      error: { code: err.code, message: err.message, details: err.details },
    });
    return;
  }
  res.status(500).json({
    ok: false,
    error: { code: 'INTERNAL', message: err instanceof Error ? err.message : String(err) },
  });
}

function safe(handler: DshHttpHandler): DshHttpHandler {
  return async (req, res) => {
    try {
      await handler(req, res);
    } catch (err) {
      sendError(res, err);
    }
  };
}

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1']);

function extractHostHostname(rawHost: string | undefined): string {
  if (!rawHost) return '';
  const trimmed = rawHost.trim().toLowerCase();
  if (trimmed.startsWith('[')) {
    const end = trimmed.indexOf(']');
    return end > 0 ? trimmed.slice(1, end) : trimmed;
  }
  const firstColon = trimmed.indexOf(':');
  if (firstColon !== -1 && trimmed.indexOf(':', firstColon + 1) === -1) {
    return trimmed.slice(0, firstColon);
  }
  return trimmed;
}

function isAllowedHostHeader(req: IncomingMessage): boolean {
  return LOOPBACK_HOSTS.has(extractHostHostname(req.headers.host));
}

function isSameOriginOrLoopback(req: IncomingMessage): boolean {
  const secFetchSite = String(req.headers['sec-fetch-site'] ?? '').trim().toLowerCase();
  if (secFetchSite === 'cross-site') {
    return false;
  }
  const origin = req.headers.origin;
  const host = req.headers.host;
  const hasClientHeader = req.headers['x-dsh-wsl-client'] === '1';
  if (!origin) return true;
  if (origin === 'null') {
    // Electron file:// origin allowed ONLY when explicit custom client header is present
    return hasClientHeader;
  }
  try {
    const parsed = new URL(origin);
    const originHost = parsed.hostname.toLowerCase();
    const isLoopbackOrigin =
      originHost === '127.0.0.1' ||
      originHost === 'localhost' ||
      originHost === '[::1]' ||
      originHost === '::1';
    if (!isLoopbackOrigin) return false;
    if (host && parsed.host.toLowerCase() !== host.toLowerCase()) return false;
    return hasClientHeader;
  } catch {
    return false;
  }
}

async function readJsonBody(req: IncomingMessage, maxBytes = 256 * 1024): Promise<unknown> {
  const method = (req.method ?? 'GET').toUpperCase();
  if (method === 'GET' || method === 'HEAD') return undefined;
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
    total += buf.length;
    if (total > maxBytes) {
      throw new Error(`Request body exceeds ${maxBytes} bytes`);
    }
    chunks.push(buf);
  }
  if (chunks.length === 0) return {};
  const raw = Buffer.concat(chunks).toString('utf8').trim();
  if (!raw) return {};
  return JSON.parse(raw);
}

function wrapNodeResponse(res: ServerResponse): DshHttpResponse {
  let code = 200;
  const headers: Record<string, string> = {
    'Cache-Control': 'no-store',
  };
  const wrapper: DshHttpResponse = {
    status(c: number) {
      code = c;
      return wrapper;
    },
    header(name: string, value: string) {
      headers[name] = value;
      return wrapper;
    },
    json(payload: unknown) {
      const body = JSON.stringify(payload);
      res.writeHead(code, {
        ...headers,
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Length': String(Buffer.byteLength(body, 'utf8')),
      });
      res.end(body);
    },
    html(content: string) {
      res.writeHead(code, {
        ...headers,
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Length': String(Buffer.byteLength(content, 'utf8')),
      });
      res.end(content);
    },
    text(content: string) {
      res.writeHead(code, {
        ...headers,
        'Content-Type': 'text/plain; charset=utf-8',
        'Content-Length': String(Buffer.byteLength(content, 'utf8')),
      });
      res.end(content);
    },
  };
  return wrapper;
}

/**
 * Registers strictly namespaced human-only HTTP routes under `/wsl-sandbox/api/*` and `/wsl-sandbox/ui`
 * on BOTH real `@deepseek-ai/dsh-host-webserver` (`ctx.webServer`) AND generic `ctx.http` test routers.
 */
export function registerWslSandboxWebApi(ctx: DshCordisContext, deps: WebApiDeps): (() => void)[] {
  const disposers: (() => void)[] = [];
  const table: RouteEntry[] = [];
  const httpRouter = deps.skipHttpRouter ? undefined : getOptionalService(ctx, 'http');
  const webServer = deps.skipWebServer ? undefined : getOptionalService(ctx, 'webServer');

  const add = (
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    routePath: string,
    handler: DshHttpHandler,
  ): void => {
    const wrapped = safe(handler);
    const { regex, paramNames } = compilePattern(routePath);
    table.push({ method, pattern: routePath, regex, paramNames, handler: wrapped });
    if (httpRouter) {
      const dispose = httpRouter.route(method, routePath, wrapped);
      if (typeof dispose === 'function') disposers.push(() => void dispose());
    }
  };

  add('GET', '/wsl-sandbox/ui', (_req, res) => {
    res.status(200).html(renderWslSandboxUiHtml());
  });

  const activeLogger = deps.logger ?? deps.sessionManager.getLogger();

  add('GET', '/wsl-sandbox/api/status', (_req, res) => {
    const binding = deps.sessionManager.getBindingSnapshot();
    res.status(200).json({
      ok: true,
      bound: Boolean(binding),
      runnerActive: deps.sessionManager.isRunnerActive(),
      generation: deps.sessionManager.getGeneration(),
      binding: binding ?? null,
      config: deps.configStore.get(),
      nodeRuntime: deps.sessionManager.getNodeRuntimeSummary(),
      bootstrap: deps.sessionManager.getBootstrapChannelState(),
      pendingApprovals: deps.approvalBridge.listPending().length,
      sessionRules: deps.approvalBridge.getSessionRules(),
    });
  });

  // 仅读取静态引导脚本与校验 SHA-256，绝不触发任何宿主子进程或 WSL 启动
  add('GET', '/wsl-sandbox/api/bootstrap-preview', (req, res) => {
    const pluginRoot = findPluginPackageRoot();
    const bootstrap = deps.sessionManager.getBootstrapChannelState();
    const cfg = deps.configStore.get();
    const targetDistro = (req.query.distro ?? bootstrap.targetDistro ?? cfg.distro ?? '<YourDistro>').trim();
    const profile = (req.query.profile ?? cfg.environmentProfile ?? 'standard').trim();
    const mirror = req.query.mirror === 'cn' || (req.query.mirror === undefined && cfg.mirrorCn) ? 'cn' : 'global';

    const specs = [
      { id: 'install-ps1', relPath: 'packages/bootstrap/install-dsh-plugin.ps1', title: 'Windows 安装与探测向导 (PowerShell 7)' },
      { id: 'stage-mjs', relPath: 'scripts/stage-wsl-runner.mjs', title: 'WSL 原生 ext4 Runner 分发器 (Node ESM)' },
      { id: 'provision-sh', relPath: 'packages/bootstrap/provision-wsl.sh', title: 'WSL 2 多发行版幂等置备脚本 (Bash)' },
    ] as const;

    const scripts = specs.map((s) => {
      const absPath = pluginRoot ? path.join(pluginRoot, s.relPath) : s.relPath;
      if (!pluginRoot || !fs.existsSync(absPath)) {
        return {
          id: s.id,
          title: s.title,
          relPath: s.relPath,
          fullPath: absPath,
          exists: false,
          sha256: null,
          bytes: 0,
          lines: 0,
          content: '(script file not found)',
        };
      }
      const rawBuf = fs.readFileSync(absPath);
      const text = rawBuf.toString('utf8');
      return {
        id: s.id,
        title: s.title,
        relPath: s.relPath,
        fullPath: absPath,
        exists: true,
        sha256: createHash('sha256').update(rawBuf).digest('hex'),
        bytes: rawBuf.length,
        lines: text.split(/\r?\n/).length,
        content: text,
      };
    });

    const qDistro = targetDistro.includes(' ') ? `"${targetDistro}"` : targetDistro;
    const dryRunCommand = `.\\packages\\bootstrap\\install-dsh-plugin.ps1 -NonInteractive -Distro ${qDistro} -Profile ${profile} -Mirror ${mirror} -Provision -DryRun`;
    const installCommand = `.\\packages\\bootstrap\\install-dsh-plugin.ps1 -NonInteractive -Distro ${qDistro} -Profile ${profile} -Mirror ${mirror} -Provision`;
    const recommendedSessionPrompt = [
      `请按照 dsh-wsl-env-setup 四步安全协议协助完成目标 WSL 2 发行版「${targetDistro}」的环境初始化：`,
      '1. 先只读探测并向我确认目标发行版、环境档位（core/standard/universal）与国内镜像源；',
      '2. 先独立执行带 -DryRun 的预览命令，并将《安装脚本与变更预览卡片》按固定格式发给我确认；',
      '3. 在我明确确认后再申请真实安装单次审批；',
      '4. 安装完成后运行 dsh-wsl-doctor --strict-wsl2 --json 验收闭环。',
    ].join('\n');

    res.status(200).json({
      ok: true,
      bootstrap,
      targetDistro,
      profile,
      mirror,
      dryRunCommand,
      installCommand,
      recommendedSessionPrompt,
      networkingNote:
        '常规测试与手机/USB 硬件联调推荐保持 WSL 2 默认 NAT 网络模式（无需强制改为 mirrored）；如仅需 WSL 内通过 127.0.0.1 直连宿主机代理且运行在 Win11 22H2+ / WSL >= 2.4，才按需切换 mirrored。',
      scripts,
    });
  });

  add('GET', '/wsl-sandbox/api/bootstrap-session', (_req, res) => {
    res.status(200).json({
      ok: true,
      bootstrap: deps.sessionManager.getBootstrapChannelState(),
    });
  });

  add('POST', '/wsl-sandbox/api/bootstrap-session', (req, res) => {
    const body = (req.body ?? {}) as {
      action?: 'open' | 'close' | 'reload';
      active?: boolean;
      targetDistro?: string;
      ttlMs?: number;
    };
    if (body.action === 'reload') {
      const reloaded = deps.configStore.reloadFromDisk();
      res.status(200).json({
        ok: true,
        config: reloaded,
        bootstrap: deps.sessionManager.getBootstrapChannelState(),
      });
      return;
    }
    const desiredActive =
      body.action === 'close' ? false : body.action === 'open' ? true : Boolean(body.active);
    const bootstrap = deps.sessionManager.setBootstrapChannel({
      active: desiredActive,
      targetDistro: body.targetDistro,
      ttlMs: body.ttlMs,
    });
    res.status(200).json({ ok: true, bootstrap });
  });

  add('GET', '/wsl-sandbox/api/config', (_req, res) => {
    res.status(200).json(deps.configStore.get());
  });

  add('PUT', '/wsl-sandbox/api/config', (req, res) => {
    const body = (req.body ?? {}) as BasicConfigPatch & Record<string, unknown>;
    const updated = deps.configStore.updateBasic(body);
    res.status(200).json({ ok: true, config: updated });
  });

  add('POST', '/wsl-sandbox/api/env-unmask', (req, res) => {
    const body = (req.body ?? {}) as { workspaceRoot?: string; unmasked?: boolean };
    const ws = String(body.workspaceRoot ?? '').trim();
    const cur = deps.configStore.get().unmaskedEnvWorkspaces;
    const next = body.unmasked ? [...new Set([...cur, ws])] : cur.filter((x) => x !== ws);
    const updated = deps.configStore.updateBasic({ unmaskedEnvWorkspaces: next });
    res.status(200).json({ ok: true, config: updated });
  });

  add('POST', '/wsl-sandbox/api/advanced/shares', (req, res) => {
    const raw = (req.body ?? {}) as Partial<AuthorizedShare> & { path?: string };
    const share: AuthorizedShare = {
      id: raw.id ?? `sh-${Date.now().toString(36)}`,
      alias: raw.alias ?? '',
      sourceLinuxPath: String(raw.sourceLinuxPath ?? raw.path ?? ''),
      mode: raw.mode === 'rw' ? 'rw' : 'ro',
      oneShot: Boolean(raw.oneShot),
    };
    const updated = deps.configStore.addShare(share);
    const added = updated.advanced.shares[updated.advanced.shares.length - 1] ?? null;
    activeLogger?.log('info', {
      component: 'shares',
      event: 'share.added',
      message: `Authorized single-directory share /shares/${added?.alias ?? share.alias} (${added?.mode ?? share.mode})`,
      data: { share: added },
    });
    res.status(200).json({ ok: true, share: added, config: updated });
  });

  add('DELETE', '/wsl-sandbox/api/advanced/shares/:id', async (req, res) => {
    const shareId = req.params.id ?? '';
    const updated = deps.configStore.removeShare(shareId);
    const killedCount = await deps.sessionManager.invalidateNow(`Share '${shareId}' revoked`);
    activeLogger?.log('info', {
      component: 'shares',
      event: 'share.revoked',
      message: `Revoked share '${shareId}' and invalidated ${killedCount} active process(es)`,
      data: { shareId, killedCount },
    });
    res.status(200).json({ ok: true, revokedShareId: shareId, killedCount, config: updated });
  });

  interface BackupListItem {
    readonly name: string;
    readonly fullPath: string;
    readonly explorerPath: string;
    readonly sizeBytes: number;
    readonly updatedAt: string;
    readonly source: 'custom-backup-dir' | 'wsl-internal';
  }

  const SAFE_BACKUP_FILE_RE = /\.(?:orig|bak|ini|txt|absent|conf)$/i;
  const BLOCKED_EXEC_EXT_RE = /\.(?:exe|com|bat|cmd|ps1|vbs|js|jse|wsf|wsh|msi|msp|scr|pif|lnk|hta)$/i;

  function resolveEffectiveBackupDir(customInput?: string): string {
    const cfg = deps.configStore.get();
    const candidate = customInput !== undefined && customInput.trim() !== ''
      ? validateBackupDirPath(customInput)
      : cfg.backupDir;
    return path.resolve(candidate ?? getDefaultBackupDir());
  }

  function collectHostBackupItems(
    resolvedBackupDir: string,
    distro: string,
    wslInternalDir?: string,
    wslEntries?: readonly string[],
  ): BackupListItem[] {
    const items: BackupListItem[] = [];
    if (fs.existsSync(resolvedBackupDir)) {
      for (const entry of fs.readdirSync(resolvedBackupDir).sort()) {
        if (BLOCKED_EXEC_EXT_RE.test(entry)) continue;
        const full = path.join(resolvedBackupDir, entry);
        try {
          const st = fs.lstatSync(full);
          if (!st.isFile()) continue;
          items.push({
            name: entry,
            fullPath: full,
            explorerPath: full,
            sizeBytes: st.size,
            updatedAt: new Date(st.mtimeMs).toISOString().replace('T', ' ').slice(0, 19),
            source: 'custom-backup-dir',
          });
        } catch {
          // ignore unreadable item
        }
      }
    }

    if (wslInternalDir && wslEntries && wslEntries.length > 0) {
      const seenNames = new Set(items.map((i) => i.name));
      for (const name of wslEntries) {
        if (seenNames.has(name) || BLOCKED_EXEC_EXT_RE.test(name)) continue;
        const linuxFull = path.posix.join(wslInternalDir, name);
        const explorerPath =
          process.platform === 'win32'
            ? `\\\\wsl.localhost\\${distro}${linuxFull.replace(/\//g, '\\')}`
            : linuxFull;
        if (process.platform !== 'win32' && path.resolve(linuxFull) === path.join(resolvedBackupDir, name)) {
          continue;
        }
        items.push({
          name: `[WSL 内置] ${name}`,
          fullPath: linuxFull,
          explorerPath,
          sizeBytes: 0,
          updatedAt: '-',
          source: 'wsl-internal',
        });
      }
    }
    return items;
  }

  add('GET', '/wsl-sandbox/api/wsl-config/backups', async (req, res) => {
    const cfg = deps.configStore.get();
    const resolvedBackupDir = resolveEffectiveBackupDir(req.query.backupDir);
    let wslInternalDir: string | undefined;
    let wslEntries: string[] = [];
    let automountDisabledInWslConf = false;
    // Only query in-WSL backup directory if runner is ALREADY running (never cold-boot WSL VM or spin VHDX on UI view!)
    if (deps.sessionManager.isRunnerActive()) {
      try {
        const info = (await deps.sessionManager.callRpc('wsl.listBackups', {}, 8_000)) as {
          backupDir?: string;
          entries?: string[];
          automountDisabledInWslConf?: boolean;
        };
        wslInternalDir = info.backupDir;
        wslEntries = info.entries ?? [];
        automountDisabledInWslConf = Boolean(info.automountDisabledInWslConf);
      } catch {
        // ignore
      }
    }
    const items = collectHostBackupItems(resolvedBackupDir, cfg.distro, wslInternalDir, wslEntries);
    res.status(200).json({
      ok: true,
      backupDir: resolvedBackupDir,
      items,
      entries: items.map((i) => i.name),
      sandboxTmpfsMntLocked: true,
      automountDisabledInWslConf,
    });
  });

  add('GET', '/wsl-sandbox/api/distros', async (req, res) => {
    const discovery = await discoverWslDistrosAsync();
    const probeDistro = req.query.probeDistro?.trim();
    const probedUser = probeDistro ? await probeWslDistroUserAsync(probeDistro) : null;
    res.status(200).json({
      ok: true,
      ...discovery,
      probedUser,
    });
  });

  add('GET', '/wsl-sandbox/api/processes', async (_req, res) => {
    try {
      const info = await deps.sessionManager.callRpc('proc.list', {}, 6_000);
      res.status(200).json({ ok: true, ...(typeof info === 'object' && info ? info : {}) });
    } catch {
      res.status(200).json({ ok: true, active: [], terminals: [] });
    }
  });

  add('POST', '/wsl-sandbox/api/wsl-config/backup', async (req, res) => {
    const body = (req.body ?? {}) as { backupDir?: string };
    const resolvedBackupDir = resolveEffectiveBackupDir(body.backupDir);
    if (process.platform === 'win32') {
      const discovery = await discoverWslDistrosAsync();
      const hitDistro = isInsideLxssBasePath(resolvedBackupDir, discovery.distros);
      if (hitDistro) {
        failSandbox(
          'POLICY_BLOCK',
          `Refusing to use WSL distro '${hitDistro}' VHDX storage directory as backupDir: ${resolvedBackupDir}`,
        );
      }
    }
    if (body.backupDir && body.backupDir.trim() !== '' && body.backupDir.trim() !== deps.configStore.get().backupDir) {
      deps.configStore.updateBasic({ backupDir: resolvedBackupDir });
    }
    const cfg = deps.configStore.get();
    fs.mkdirSync(resolvedBackupDir, { recursive: true, mode: 0o700 });
    hardenPrivatePath(resolvedBackupDir, 'dir');

    const savedFiles: string[] = [];
    const sha256Str = (s: string): string => createHash('sha256').update(s, 'utf8').digest('hex');

    const unlockReadOnlyHostFile = (target: string): void => {
      if (!fs.existsSync(target)) return;
      if (process.platform === 'win32') {
        try {
          spawnSync('attrib.exe', ['-R', target], { stdio: 'ignore', windowsHide: true });
        } catch {
          // ignore
        }
      }
      try {
        fs.chmodSync(target, 0o600);
      } catch {
        // ignore
      }
    };

    const writeReadOnlyHostBackup = (dest: string, content: string): void => {
      unlockReadOnlyHostFile(dest);
      fs.writeFileSync(dest, content, { mode: 0o400 });
      hardenPrivatePath(dest, 'readonly-file');
      savedFiles.push(dest);
    };

    const saveDeduplicatedHostSeries = (
      origName: string,
      rollingPrefix: string,
      rollingExt: string,
      timestamp: string,
      content: string,
      maxRolling = 5,
    ): void => {
      const origPath = path.join(resolvedBackupDir, origName);
      if (!fs.existsSync(origPath)) {
        writeReadOnlyHostBackup(origPath, content);
      }
      const existingRolling = fs
        .readdirSync(resolvedBackupDir)
        .filter(
          (f) =>
            f !== origName &&
            f.startsWith(`${rollingPrefix}.`) &&
            f.endsWith(`.${rollingExt}`),
        )
        .sort();

      const compareTarget =
        existingRolling.length > 0
          ? path.join(resolvedBackupDir, existingRolling[existingRolling.length - 1]!)
          : origPath;

      if (fs.existsSync(compareTarget)) {
        try {
          if (sha256Str(fs.readFileSync(compareTarget, 'utf8')) === sha256Str(content)) {
            return;
          }
        } catch {
          // fall through
        }
      }

      writeReadOnlyHostBackup(
        path.join(resolvedBackupDir, `${rollingPrefix}.${timestamp}.${rollingExt}`),
        content,
      );

      const updatedRolling = fs
        .readdirSync(resolvedBackupDir)
        .filter(
          (f) =>
            f !== origName &&
            f.startsWith(`${rollingPrefix}.`) &&
            f.endsWith(`.${rollingExt}`),
        )
        .sort();
      while (updatedRolling.length > maxRolling) {
        const oldest = path.join(resolvedBackupDir, updatedRolling.shift()!);
        unlockReadOnlyHostFile(oldest);
        try {
          fs.rmSync(oldest, { force: true });
        } catch {
          // ignore
        }
      }
    };

    const ts = new Date().toISOString().replace(/[:.]/g, '-');
    const wslCfg = path.join(os.homedir(), '.wslconfig');
    const origHostCfg = path.join(resolvedBackupDir, '.wslconfig.orig');
    const absentHostMarker = path.join(resolvedBackupDir, '.wslconfig.orig.absent');

    if (fs.existsSync(wslCfg)) {
      const hostContent = fs.readFileSync(wslCfg, 'utf8');
      saveDeduplicatedHostSeries('.wslconfig.orig', '.wslconfig', 'bak', ts, hostContent, 5);
    } else if (!fs.existsSync(origHostCfg) && !fs.existsSync(absentHostMarker)) {
      writeReadOnlyHostBackup(
        absentHostMarker,
        `# Host had no %USERPROFILE%\\.wslconfig at initial backup (${ts})\n# Note: WSL Settings & WSL Manager share %USERPROFILE%\\.wslconfig and /etc/wsl.conf.\n`,
      );
    }

    let wslInternalDir: string | undefined;
    if (deps.sessionManager.isRunnerActive() || cfg.transportMode === 'local-linux') {
      try {
        const wslResult = (await deps.sessionManager.callRpc('wsl.backupConfigs', {}, 12_000)) as {
          wslInternalBackupDir?: string;
          wslConfContent?: string | null;
          fstabContent?: string | null;
          drvfsMountsContent?: string | null;
        };
        wslInternalDir = wslResult.wslInternalBackupDir;
        if (typeof wslResult.wslConfContent === 'string') {
          saveDeduplicatedHostSeries(
            `wsl.conf.${cfg.distro}.orig`,
            `wsl.conf.${cfg.distro}`,
            'bak',
            ts,
            wslResult.wslConfContent,
            5,
          );
        } else {
          const distroAbsent = path.join(resolvedBackupDir, `wsl.conf.${cfg.distro}.orig.absent`);
          if (!fs.existsSync(distroAbsent) && !fs.existsSync(path.join(resolvedBackupDir, `wsl.conf.${cfg.distro}.orig`))) {
            writeReadOnlyHostBackup(distroAbsent, `# ${cfg.distro} had no /etc/wsl.conf at initial backup (${ts})\n`);
          }
        }
        if (typeof wslResult.fstabContent === 'string') {
          saveDeduplicatedHostSeries(
            `fstab.${cfg.distro}.orig`,
            `fstab.${cfg.distro}`,
            'bak',
            ts,
            wslResult.fstabContent,
            5,
          );
        }
        if (typeof wslResult.drvfsMountsContent === 'string') {
          saveDeduplicatedHostSeries(
            `drvfs-mounts.${cfg.distro}.orig.txt`,
            `drvfs-mounts.${cfg.distro}`,
            'txt',
            ts,
            wslResult.drvfsMountsContent + '\n',
            5,
          );
        }
      } catch {
        // Runner offline; host backup still succeeded
      }
    }

    const items = collectHostBackupItems(resolvedBackupDir, cfg.distro, wslInternalDir, []);
    res.status(200).json({
      ok: true,
      backupDir: resolvedBackupDir,
      hostBackupDir: resolvedBackupDir,
      savedFiles,
      items,
      sandboxTmpfsMntLocked: true,
    });
  });

  add('POST', '/wsl-sandbox/api/wsl-config/open-explorer', (req, res) => {
    const body = (req.body ?? {}) as { targetPath?: string; backupDir?: string; selectFile?: boolean };
    const resolvedBackupDir = resolveEffectiveBackupDir(body.backupDir);
    const cfg = deps.configStore.get();
    const rawTarget = String(body.targetPath ?? resolvedBackupDir).trim();
    if (!rawTarget || rawTarget.includes('\0')) {
      failSandbox('POLICY_BLOCK', 'Invalid explorer target path');
    }
    if (BLOCKED_EXEC_EXT_RE.test(rawTarget)) {
      failSandbox('POLICY_BLOCK', `Refusing to pass executable file extension to Explorer: ${rawTarget}`);
    }

    const wslUncPrefix = `\\\\wsl.localhost\\${cfg.distro}\\`;
    const isWslInternalBackup =
      rawTarget.toLowerCase().startsWith(wslUncPrefix.toLowerCase()) &&
      rawTarget.replace(/\\/g, '/').includes('/.config/dsh-wsl-sandbox/backups/');

    let finalTarget: string;
    let isFileTarget = Boolean(body.selectFile);

    if (isWslInternalBackup) {
      const baseName = rawTarget.split(/[\\/]/).pop() ?? '';
      if (baseName && !SAFE_BACKUP_FILE_RE.test(baseName)) {
        failSandbox('POLICY_BLOCK', `Refusing to highlight non-backup file in WSL UNC path: ${baseName}`);
      }
      finalTarget = rawTarget;
      isFileTarget = Boolean(body.selectFile);
    } else {
      const resolvedTarget = path.resolve(rawTarget);
      const normDir = resolvedBackupDir.endsWith(path.sep) ? resolvedBackupDir : resolvedBackupDir + path.sep;
      const isDirItself = resolvedTarget === resolvedBackupDir;
      const isChildOfBackupDir = resolvedTarget.startsWith(normDir);
      if (!isDirItself && !isChildOfBackupDir) {
        failSandbox(
          'POLICY_BLOCK',
          `Explorer open is strictly confined to the configured backup directory (${resolvedBackupDir}); rejected: ${resolvedTarget}`,
        );
      }
      if (isDirItself) {
        fs.mkdirSync(resolvedBackupDir, { recursive: true, mode: 0o700 });
        isFileTarget = false;
      } else {
        if (!SAFE_BACKUP_FILE_RE.test(path.basename(resolvedTarget)) || !fs.existsSync(resolvedTarget)) {
          failSandbox('POLICY_BLOCK', `Backup item does not exist or has disallowed extension: ${resolvedTarget}`);
        }
        const st = fs.lstatSync(resolvedTarget);
        if (st.isSymbolicLink() || !st.isFile()) {
          failSandbox('POLICY_BLOCK', `Refusing to highlight symlink or non-regular file: ${resolvedTarget}`);
        }
        isFileTarget = body.selectFile !== false;
      }
      finalTarget = resolvedTarget;
    }

    const explorerArgs = isFileTarget ? [`/select,${finalTarget}`] : [finalTarget];
    let launched = false;
    if (process.env.DSH_WSL_NO_HOST_SPAWN !== '1') {
      if (process.platform === 'win32') {
        const child = spawn('explorer.exe', explorerArgs, {
          shell: false,
          detached: true,
          stdio: 'ignore',
        });
        child.on('error', () => {});
        child.unref();
        launched = true;
      } else if (process.platform === 'darwin') {
        const child = spawn('open', isFileTarget ? ['-R', finalTarget] : [finalTarget], {
          shell: false,
          detached: true,
          stdio: 'ignore',
        });
        child.on('error', () => {});
        child.unref();
        launched = true;
      } else if (process.env.WSL_DISTRO_NAME) {
        // Running inside WSL Linux dev mode: convert path via wslpath -w and launch Windows explorer.exe
        const wp = spawnSync('wslpath', ['-w', finalTarget], { encoding: 'utf8' });
        const winPath = wp.status === 0 ? wp.stdout.trim() : finalTarget;
        const child = spawn('explorer.exe', isFileTarget ? [`/select,${winPath}`] : [winPath], {
          shell: false,
          detached: true,
          stdio: 'ignore',
        });
        child.on('error', () => {});
        child.unref();
        launched = true;
      }
    }

    res.status(200).json({
      ok: true,
      launched,
      platform: process.platform,
      targetPath: finalTarget,
      explorerArgs,
    });
  });

  add('POST', '/wsl-sandbox/api/wsl-config/pick-dir', async (_req, res) => {
    if (process.platform !== 'win32' || isHostSpawnDisabled()) {
      res.status(200).json({
        ok: true,
        supported: false,
        selectedDir: null,
        message: '非 Windows 宿主环境请直接在备份路径输入框中粘贴或填写任意目录路径。',
      });
      return;
    }
    const psScript = [
      'Add-Type -AssemblyName System.Windows.Forms;',
      '$dlg = New-Object System.Windows.Forms.FolderBrowserDialog;',
      '$dlg.Description = "选择原始 WSL 配置文件备份保存目录";',
      '$dlg.ShowNewFolderButton = $true;',
      'if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Write-Output $dlg.SelectedPath }',
    ].join(' ');
    const chosen = await new Promise<string>((resolve) => {
      let child;
      try {
        child = spawn('powershell.exe', ['-NoProfile', '-Sta', '-Command', psScript], {
          stdio: ['ignore', 'pipe', 'ignore'],
          shell: false,
          windowsHide: false,
        });
      } catch {
        resolve('');
        return;
      }
      const chunks: Buffer[] = [];
      let settled = false;
      const timer = setTimeout(() => {
        try { child.kill('SIGKILL'); } catch { /* ignore */ }
        if (!settled) { settled = true; resolve(''); }
      }, 120_000);
      timer.unref();
      child.stdout?.on('data', (c: Buffer) => chunks.push(c));
      child.once('error', () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve('');
      });
      child.once('close', () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(Buffer.concat(chunks).toString('utf8').trim());
      });
    });
    if (chosen) {
      const updated = deps.configStore.updateBasic({ backupDir: chosen });
      res.status(200).json({ ok: true, supported: true, selectedDir: updated.backupDir, config: updated });
      return;
    }
    res.status(200).json({ ok: true, supported: true, selectedDir: null });
  });

  add('PUT', '/wsl-sandbox/api/advanced/devices', async (req, res) => {
    const body = (req.body ?? {}) as { deviceNodes?: AuthorizedDeviceNode[] };
    const updated = deps.configStore.setDeviceNodes(body.deviceNodes ?? []);
    const killedCount = await deps.sessionManager.invalidateNow('Device whitelist updated');
    res.status(200).json({ ok: true, killedCount, config: updated });
  });

  add('PUT', '/wsl-sandbox/api/advanced/network', (req, res) => {
    const body = (req.body ?? {}) as {
      localLabCidrs?: string[];
      localLabPorts?: number[];
      customAllowedDomains?: string[];
    };
    const updated = deps.configStore.updateAdvancedNetwork(body);
    res.status(200).json({ ok: true, config: updated });
  });

  add('GET', '/wsl-sandbox/api/approvals', (_req, res) => {
    res.status(200).json({
      ok: true,
      pending: deps.approvalBridge.listPending(),
      sessionRules: deps.approvalBridge.getSessionRules(),
    });
  });

  add('POST', '/wsl-sandbox/api/approvals/:id/decide', (req, res) => {
    const requestId = req.params.id ?? '';
    const body = (req.body ?? {}) as {
      decision?: ApprovalDecisionKind;
      guidance?: string;
      sessionPrefix?: string[];
    };
    if (!body.decision) {
      res.status(400).json({ ok: false, error: { code: 'INVALID_ACTION', message: 'Missing decision field' } });
      return;
    }
    const found = deps.approvalBridge.decidePending(requestId, body.decision, {
      guidance: body.guidance,
      sessionPrefix: body.sessionPrefix,
    });
    if (!found) {
      res.status(404).json({ ok: false, error: { code: 'NOT_FOUND', message: `Approval '${requestId}' not pending` } });
      return;
    }
    res.status(200).json({ ok: true, requestId, decision: body.decision });
  });

  add('GET', '/wsl-sandbox/api/session-rules', (_req, res) => {
    res.status(200).json({ ok: true, rules: deps.approvalBridge.getSessionRules() });
  });

  add('DELETE', '/wsl-sandbox/api/session-rules', (_req, res) => {
    deps.approvalBridge.clearSessionRules();
    res.status(200).json({ ok: true, rules: [] });
  });

  add('POST', '/wsl-sandbox/api/session/invalidate', async (_req, res) => {
    const killedCount = await deps.sessionManager.invalidateNow('Emergency manual invalidation');
    res.status(200).json({ ok: true, killedCount });
  });

  add('POST', '/wsl-sandbox/api/cache/clear', async (_req, res) => {
    const result = await deps.sessionManager.callRpc('cache.clear', {}, 15_000);
    res.status(200).json({ ok: true, ...(typeof result === 'object' && result ? result : {}) });
  });

  add('GET', '/wsl-sandbox/api/doctor', async (_req, res) => {
    const cfg = deps.configStore.get();
    try {
      const report = await deps.sessionManager.callRpc(
        'env.doctor',
        { upstreamProxy: cfg.upstreamProxy, profile: cfg.environmentProfile },
        25_000,
      );
      res.status(200).json({ ok: true, report });
    } catch (err) {
      if (process.platform === 'linux') {
        const { runDoctor } = await import('../../bootstrap/src/doctor.ts');
        const report = await runDoctor({
          upstreamProxy: cfg.upstreamProxy || undefined,
          profile: cfg.environmentProfile,
        });
        res.status(200).json({ ok: true, report });
        return;
      }
      const errMsg = err instanceof Error ? err.message : String(err);
      res.status(200).json({
        ok: true,
        report: {
          timestamp: new Date().toISOString(),
          verdict: 'blocked',
          selectedProfile: cfg.environmentProfile,
          os: {
            platform: process.platform,
            arch: process.arch,
            kernel: os.release(),
            isWsl2: false,
            drvfsAutomountActive: false,
          },
          user: {
            uid: -1,
            username: cfg.username ?? 'unknown',
            nonRoot: Boolean(cfg.username && cfg.username !== 'root'),
          },
          sandbox: {
            bwrapPath: null,
            bwrapVersion: null,
            unprivilegedUserns: false,
            disableUsernsFlag: false,
            seccompIoUringBlocked: null,
            seccompAfVsockBlocked: null,
            escapeMaskSelfTest: false,
            configMaskSelfTest: false,
            configDirPermsOk: false,
            details: [errMsg],
          },
          hardware: {
            vhciHcdReady: false,
            lsusbPresent: false,
            usbBusNodesCount: 0,
            serialAndHidNodes: [],
            driverNote: '',
          },
          tools: [],
          network: { upstreamProxy: cfg.upstreamProxy || undefined },
          remediation: [errMsg],
        },
      });
    }
  });

  add('GET', '/wsl-sandbox/api/audit', (_req, res) => {
    res.status(200).json({
      ok: true,
      records: deps.approvalBridge.getAuditLog(),
    });
  });

  add('GET', '/wsl-sandbox/api/logs', (req, res) => {
    if (!activeLogger) {
      res.status(200).json({
        ok: true,
        entries: [],
        stats: { level: deps.configStore.get().logLevel, bufferedCount: 0, logFilePath: null, diskFlushCount: 0 },
      });
      return;
    }
    const rawLevel = req.query.level?.trim().toLowerCase();
    const minLevel: LogLevel | undefined = isValidLogLevel(rawLevel) ? rawLevel : undefined;
    const rawSource = req.query.source?.trim().toLowerCase();
    const source: LogSource | 'all' | undefined =
      rawSource === 'host' || rawSource === 'wsl-runner' || rawSource === 'bootstrap' || rawSource === 'all'
        ? rawSource
        : 'all';
    const sinceSeq = req.query.sinceSeq ? Number(req.query.sinceSeq) : undefined;
    const limit = req.query.limit ? Number(req.query.limit) : 200;

    // 100% served from RAM ring buffer — ZERO disk read syscalls!
    const entries = activeLogger.query({
      minLevel,
      source,
      component: req.query.component,
      search: req.query.search,
      sinceSeq: Number.isFinite(sinceSeq) ? sinceSeq : undefined,
      limit: Number.isFinite(limit) ? limit : 200,
    });
    const diskStats = activeLogger.getDiskStats();
    res.status(200).json({
      ok: true,
      entries,
      stats: {
        level: activeLogger.getLevel(),
        bufferedCount: activeLogger.getBufferedCount(),
        logFilePath: activeLogger.getLogFilePath() ?? null,
        logDir: activeLogger.getLogDir() ?? null,
        ...diskStats,
      },
    });
  });

  add('GET', '/wsl-sandbox/api/logs/export', (req, res) => {
    const rawLevel = req.query.level?.trim().toLowerCase();
    const minLevel: LogLevel | undefined = isValidLogLevel(rawLevel) ? rawLevel : undefined;
    const ndjson = activeLogger
      ? activeLogger.exportNdjson({
          minLevel,
          search: req.query.search,
          limit: 1000,
        })
      : '';
    res
      .status(200)
      .header('Content-Type', 'application/x-ndjson; charset=utf-8')
      .header('Content-Disposition', 'attachment; filename="dsh-wsl-sandbox-logs.ndjson"')
      .text(ndjson);
  });

  add('DELETE', '/wsl-sandbox/api/logs', async (_req, res) => {
    const cleared = activeLogger ? activeLogger.clear() : { clearedMemory: 0, removedFiles: 0 };
    if (deps.sessionManager.isRunnerActive()) {
      await deps.sessionManager.callRpc('logs.clear', {}, 4_000).catch(() => {});
    }
    res.status(200).json({ ok: true, ...cleared });
  });

  const updateInstallManifestAgentsMd = (filePath: string, mode: 'add' | 'remove'): void => {
    if (!deps.configStore.isPersistent()) return;
    const manifestPath = path.join(deps.configStore.getConfigDir(), 'install-manifest.json');
    let doc: Record<string, unknown> = {};
    if (fs.existsSync(manifestPath)) {
      try {
        doc = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as Record<string, unknown>;
      } catch {
        doc = {};
      }
    }
    const prevList = Array.isArray(doc.agentsMdFiles)
      ? (doc.agentsMdFiles as string[]).filter((x) => typeof x === 'string')
      : [];
    const set = new Set(prevList);
    if (mode === 'add') set.add(filePath);
    else set.delete(filePath);
    doc.agentsMdFiles = Array.from(set);
    doc.updatedAt = new Date().toISOString();
    fs.mkdirSync(path.dirname(manifestPath), { recursive: true, mode: 0o700 });
    fs.writeFileSync(manifestPath, JSON.stringify(doc, null, 2) + '\n', { mode: 0o600 });
    hardenPrivatePath(manifestPath, 'file');
  };

  const isMissingFileRpcError = (err: unknown): boolean => {
    const code = (err as { code?: unknown })?.code;
    if (code === 'NOT_FOUND' || code === 'ENOENT') return true;
    const msg = err instanceof Error ? err.message : String(err);
    return isSandboxError(err) && err.code === 'POLICY_BLOCK' && /does not exist|not found/i.test(msg);
  };

  add('POST', '/wsl-sandbox/api/agents-md', async (req, res) => {
    const body = (req.body ?? {}) as { projectRoot?: string };
    const cfg = deps.configStore.get();
    const explicitRoot = body.projectRoot?.trim();
    if (explicitRoot || cfg.transportMode !== 'wsl') {
      const targetDir = explicitRoot || cfg.workspaceRoot;
      const result = upsertAgentsMdWslSection(targetDir, {
        distro: cfg.distro,
        workspaceRoot: cfg.workspaceRoot,
      });
      updateInstallManifestAgentsMd(result.filePath, 'add');
      res.status(200).json({ ok: true, ...result });
      return;
    }

    const binding = await deps.sessionManager.ensureBound();
    let existing: string | null = null;
    try {
      const readRes = (await deps.sessionManager.callRpc(
        'fs.read',
        { binding, path: 'AGENTS.md', offset: 1, limit: 10_000, maskEnvSecrets: false },
        10_000,
      )) as { content?: string };
      existing = typeof readRes?.content === 'string' ? readRes.content : '';
    } catch (err) {
      if (!isMissingFileRpcError(err)) throw err;
      existing = null;
    }
    const computed = computeUpsertAgentsMdContent(existing, {
      distro: binding.distribution,
      workspaceRoot: binding.workspaceRoot,
    });
    await deps.sessionManager.callRpc(
      'fs.write',
      { binding, path: 'AGENTS.md', content: computed.content },
      10_000,
    );
    const virtualPath = `wsl:${binding.distribution}:${path.posix.join(binding.workspaceRoot, 'AGENTS.md')}`;
    updateInstallManifestAgentsMd(virtualPath, 'add');
    res.status(200).json({ ok: true, filePath: virtualPath, action: computed.action });
  });

  add('DELETE', '/wsl-sandbox/api/agents-md', async (req, res) => {
    const body = (req.body ?? {}) as { projectRoot?: string };
    const cfg = deps.configStore.get();
    const explicitRoot = body.projectRoot?.trim();
    if (explicitRoot || cfg.transportMode !== 'wsl') {
      const targetDir = explicitRoot || cfg.workspaceRoot;
      const result = removeAgentsMdWslSection(targetDir);
      updateInstallManifestAgentsMd(result.filePath, 'remove');
      res.status(200).json({ ok: true, ...result });
      return;
    }

    const binding = await deps.sessionManager.ensureBound();
    let existing: string | null = null;
    try {
      const readRes = (await deps.sessionManager.callRpc(
        'fs.read',
        { binding, path: 'AGENTS.md', offset: 1, limit: 10_000, maskEnvSecrets: false },
        10_000,
      )) as { content?: string };
      existing = typeof readRes?.content === 'string' ? readRes.content : '';
    } catch (err) {
      if (!isMissingFileRpcError(err)) throw err;
      existing = null;
    }
    const computed = computeRemoveAgentsMdContent(existing);
    if (computed.action === 'deleted-empty-file') {
      await deps.sessionManager.callRpc('fs.delete', { binding, path: 'AGENTS.md' }, 10_000);
    } else if (computed.action === 'removed-section' && computed.nextContent !== undefined) {
      await deps.sessionManager.callRpc(
        'fs.write',
        { binding, path: 'AGENTS.md', content: computed.nextContent },
        10_000,
      );
    }
    const virtualPath = `wsl:${binding.distribution}:${path.posix.join(binding.workspaceRoot, 'AGENTS.md')}`;
    updateInstallManifestAgentsMd(virtualPath, 'remove');
    res.status(200).json({ ok: true, filePath: virtualPath, action: computed.action });
  });

  add('POST', '/wsl-sandbox/api/cache/purge', async (_req, res) => {
    const result = await deps.sessionManager.callRpc('cache.clear', {}, 15_000);
    res.status(200).json({ ok: true, ...(result as Record<string, unknown>) });
  });

  add('GET', '/wsl-sandbox/api/footprint', async (_req, res) => {
    const cfg = deps.configStore.get();
    const hostConfigDir = deps.configStore.getConfigDir();
    const resolvedBackupDir = resolveEffectiveBackupDir(cfg.backupDir);
    const manifestPath = path.join(hostConfigDir, 'install-manifest.json');

    let installManifest: Record<string, unknown> | null = null;
    if (fs.existsSync(manifestPath)) {
      try {
        installManifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as Record<string, unknown>;
      } catch {
        installManifest = null;
      }
    }

    const statDir = (dirPath: string): { path: string; exists: boolean; fileCount: number; totalBytes: number } => {
      if (!fs.existsSync(dirPath)) return { path: dirPath, exists: false, fileCount: 0, totalBytes: 0 };
      let fileCount = 0;
      let totalBytes = 0;
      const walk = (curr: string): void => {
        try {
          const st = fs.lstatSync(curr);
          if (st.isFile() || st.isSymbolicLink()) {
            fileCount++;
            totalBytes += st.size;
          } else if (st.isDirectory()) {
            for (const f of fs.readdirSync(curr)) walk(path.join(curr, f));
          }
        } catch {
          // ignore
        }
      };
      walk(dirPath);
      return { path: dirPath, exists: true, fileCount, totalBytes };
    };

    let wslFootprint: Record<string, unknown> | null = null;
    if (deps.sessionManager.isRunnerActive()) {
      try {
        wslFootprint = (await deps.sessionManager.callRpc('wsl.footprint', {}, 8_000)) as Record<string, unknown>;
      } catch {
        wslFootprint = null;
      }
    }

    res.status(200).json({
      ok: true,
      host: {
        configDir: statDir(hostConfigDir),
        backupDir: statDir(resolvedBackupDir),
        logDir: statDir(path.join(hostConfigDir, 'logs')),
        installManifestPath: manifestPath,
        installManifest,
      },
      wsl: wslFootprint,
      uninstallCommands: {
        windowsSafe: '.\\packages\\bootstrap\\uninstall-dsh-plugin.ps1',
        windowsDryRun: '.\\packages\\bootstrap\\uninstall-dsh-plugin.ps1 -DryRun',
        windowsPurgeToolchains: '.\\packages\\bootstrap\\uninstall-dsh-plugin.ps1 -PurgeToolchains',
        wslOnly: 'bash ~/.local/share/dsh-wsl-sandbox/runner/packages/bootstrap/provision-wsl.sh --uninstall',
      },
    });
  });

  // Real `@deepseek-ai/dsh-host-webserver` (`ctx.webServer`) carrier
  if (webServer && typeof webServer.register === 'function') {
    const dispatchRaw = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
      if (!isAllowedHostHeader(req)) {
        wrapNodeResponse(res).status(403).json({
          ok: false,
          error: { code: 'FORBIDDEN_HOST', message: 'Non-loopback Host header rejected' },
        });
        return;
      }

      const method = (req.method ?? 'GET').toUpperCase();
      const urlObj = new URL(req.url ?? '/', 'http://127.0.0.1');
      const pathname = urlObj.pathname.replace(/\/+$/, '') || '/';

      if (method !== 'GET' && method !== 'HEAD') {
        if (!isSameOriginOrLoopback(req)) {
          wrapNodeResponse(res).status(403).json({
            ok: false,
            error: { code: 'FORBIDDEN_ORIGIN', message: 'Cross-origin mutation rejected' },
          });
          return;
        }
      }

      const matched = table.find((r) => r.method === method && r.regex.test(pathname));
      if (!matched) {
        wrapNodeResponse(res).status(404).json({
          ok: false,
          error: { code: 'NOT_FOUND', message: `No route for ${method} ${pathname}` },
        });
        return;
      }

      const m = matched.regex.exec(pathname)!;
      const params: Record<string, string> = {};
      matched.paramNames.forEach((name, idx) => {
        params[name] = decodeURIComponent(m[idx + 1] ?? '');
      });

      const query: Record<string, string> = {};
      for (const [k, v] of urlObj.searchParams.entries()) {
        query[k] = v;
      }

      const headers: Record<string, string | undefined> = {};
      for (const [k, v] of Object.entries(req.headers)) {
        headers[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : v;
      }

      let body: unknown;
      try {
        body = await readJsonBody(req);
      } catch (err) {
        wrapNodeResponse(res).status(400).json({
          ok: false,
          error: { code: 'INVALID_JSON', message: err instanceof Error ? err.message : String(err) },
        });
        return;
      }

      const dshReq: DshHttpRequest = {
        method,
        path: pathname,
        params,
        query,
        body,
        headers,
      };
      await matched.handler(dshReq, wrapNodeResponse(res));
    };

    const disposeUi = webServer.register({
      kind: 'exact',
      path: '/wsl-sandbox/ui',
      handler: dispatchRaw,
    });
    const disposeApi = webServer.register({
      kind: 'prefix',
      path: '/wsl-sandbox/api',
      handler: dispatchRaw,
    });
    disposers.push(disposeUi, disposeApi);
  }

  return disposers;
}
