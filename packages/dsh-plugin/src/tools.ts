import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path, { posix } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  assertVerifiedProbe,
  evaluateBashCommand,
  failSandbox,
  isPathInside,
  isValidDistroName,
  isValidLinuxUsername,
  type ProbeResponse,
  type ProcExecResult,
  resolveSharedHostNodeRuntime,
  type SandboxMode,
  type SessionBinding,
  type StructuredLogger,
  type TerminalExecResult,
} from '../../core/src/index.ts';
import type { ApprovalBridge } from './approval-bridge.ts';
import type { BasicConfigPatch, ConfigStore, WslSandboxConfig } from './config-store.ts';
import type {
  DshContentBlock,
  DshCordisContext,
  DshToolCallMeta,
  DshToolDefinition,
} from './cordis-types.ts';
import {
  discoverWslDistrosAsync,
  isHostSpawnDisabled,
  type ProbedDistroUser,
  probeWslDistroUserAsync,
  type WslDiscoveryReport,
} from './wsl-discovery.ts';
import { WslTransport } from './wsl-transport.ts';

export type TransportLike = Pick<
  WslTransport,
  'isRunning' | 'getRunnerNodeInfo' | 'call' | 'setRunnerLogLevel' | 'invalidate' | 'dispose'
>;

export interface SessionManagerOptions {
  readonly configStore: ConfigStore;
  readonly approvalBridge: ApprovalBridge;
  readonly sessionId?: string;
  readonly allowLinuxDevMode?: boolean;
  readonly logger?: StructuredLogger;
  readonly onStderr?: (line: string) => void;
  readonly transportFactory?: (cfg: WslSandboxConfig) => TransportLike;
  readonly discoverDistros?: () => Promise<WslDiscoveryReport>;
  readonly probeDistroUser?: (distro: string, username?: string) => Promise<ProbedDistroUser | null>;
  readonly checkStagedVersion?: (
    distro: string,
    username: string | undefined,
    runnerRoot: string,
    runnerMain: string,
  ) => Promise<string | null>;
  readonly stageRunner?: (opts: {
    distro: string;
    username?: string;
  }) => Promise<{ runnerPath: string; version: string }>;
}

export interface NodeRuntimeSummary {
  readonly hostNodeVersion: string;
  readonly hostNodeExecutable: string;
  readonly hostSharedWithDsh: boolean;
  readonly isElectronCarrier: boolean;
  readonly configuredWslNodePath: string;
  readonly wslNodeVersion: string | null;
  readonly wslNodeExecPath: string | null;
}

function renderExecOutcome(value: unknown): DshContentBlock[] {
  if (!value || typeof value !== 'object') {
    return [{ type: 'text', text: JSON.stringify(value ?? null) }];
  }
  const v = value as Partial<ProcExecResult & TerminalExecResult>;
  if (v.stdout && typeof v.stdout.text === 'string') {
    let body = v.stdout.text;
    if (v.stdout.truncated) {
      body += '\n[stdout truncated]';
    }
    if (v.stderr && typeof v.stderr.text === 'string' && v.stderr.text.length > 0) {
      if (body.length > 0 && !body.endsWith('\n')) body += '\n';
      body += `[stderr]\n${v.stderr.text}`;
      if (v.stderr.truncated) body += '\n[stderr truncated]';
    }
    if (body.length === 0) body = '(no output)';
    const markers: string[] = [];
    if (v.timedOut) markers.push('[timed out]');
    if (v.signal) markers.push(`[killed by signal: ${v.signal}]`);
    else if (typeof v.exitCode === 'number' && v.exitCode !== 0) markers.push(`[exit code: ${v.exitCode}]`);
    if (typeof v.cwd === 'string') markers.push(`[cwd: ${v.cwd}]`);
    return [
      {
        type: 'text',
        text: markers.length > 0 ? `${body}${body.endsWith('\n') ? '' : '\n'}${markers.join('\n')}` : body,
      },
    ];
  }
  return [{ type: 'text', text: JSON.stringify(value, null, 2) }];
}

function renderGenericJson(value: unknown): DshContentBlock[] {
  if (value && typeof value === 'object' && 'content' in value && typeof (value as { content?: unknown }).content === 'string') {
    const r = value as {
      content: string;
      truncated?: boolean;
      maskedEnv?: boolean;
      startLine?: number;
      endLine?: number;
      totalLines?: number;
    };
    if (r.maskedEnv) {
      return [{ type: 'text', text: '[.env* secret file masked by dsh-wsl-sandbox policy]' }];
    }
    const footer =
      r.truncated && typeof r.endLine === 'number' && typeof r.totalLines === 'number'
        ? `\n[showing lines ${r.startLine ?? 1}-${r.endLine} of ${r.totalLines}; pass offset=${r.endLine + 1} to continue]`
        : '';
    return [{ type: 'text', text: r.content + footer }];
  }
  return [{ type: 'text', text: typeof value === 'string' ? value : JSON.stringify(value, null, 2) }];
}

function findRepoRoot(): string | undefined {
  let cur = path.resolve(import.meta.dirname);
  for (let i = 0; i < 6; i++) {
    const pkgPath = path.join(cur, 'package.json');
    if (fs.existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')) as { name?: string };
        if (pkg.name === 'dsh-wsl-sandbox') {
          return cur;
        }
      } catch {
        // continue walking up
      }
    }
    const parent = path.dirname(cur);
    if (parent === cur) break;
    cur = parent;
  }
  return undefined;
}

/** 导出插件根目录解析辅助函数，供 Web 预览接口与受控 AI 初始化引导通道使用。 */
export function findPluginPackageRoot(): string | undefined {
  return findRepoRoot();
}

export type BootstrapPhase = 'idle' | '1-probe' | '2-previewed' | '3-installing';

/** 受控 AI 初始化引导通道状态：必须严格按 1 探测 -> 2 -DryRun 预览 -> 3 单次审批安装 -> 4 闭环顺序推进。 */
export interface BootstrapChannelState {
  readonly active: boolean;
  readonly phase: BootstrapPhase;
  readonly previewedDryRun: boolean;
  readonly startedAtMs?: number;
  readonly expiresAtMs?: number;
  readonly remainingMs: number;
  readonly targetDistro?: string;
  readonly pluginRoot?: string;
  readonly installScriptPath?: string;
  readonly stageScriptPath?: string;
  readonly provisionScriptPath?: string;
}

const DEFAULT_BOOTSTRAP_TTL_MS = 20 * 60 * 1000; // 20 分钟限时通道，超时或绑定就绪自动关闸

function readLocalPackageVersion(): string | undefined {
  const root = findRepoRoot();
  if (!root) return undefined;
  try {
    const parsed = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')) as {
      version?: unknown;
    };
    return typeof parsed.version === 'string' && parsed.version.trim() ? parsed.version.trim() : undefined;
  } catch {
    return undefined;
  }
}

async function defaultCheckStagedVersion(
  distro: string,
  username: string | undefined,
  runnerRoot: string,
  runnerMain: string,
): Promise<string | null> {
  if (process.platform !== 'win32' || isHostSpawnDisabled() || !isValidDistroName(distro)) {
    return null;
  }
  const args = ['-d', distro, '--cd', '~'];
  if (username && isValidLinuxUsername(username)) {
    args.push('-u', username);
  }
  args.push(
    '--',
    'sh',
    '-c',
    'if [ -f "$1" ] && [ -f "$2/.staged-version" ]; then cat "$2/.staged-version"; fi',
    'dsh-check-stage',
    runnerMain,
    runnerRoot,
  );
  return new Promise<string | null>((resolve) => {
    let child;
    try {
      child = spawn('wsl.exe', args, {
        stdio: ['ignore', 'pipe', 'ignore'],
        shell: false,
        windowsHide: true,
      });
    } catch {
      resolve(null);
      return;
    }
    const chunks: Buffer[] = [];
    let settled = false;
    const timer = setTimeout(() => {
      try {
        child.kill('SIGKILL');
      } catch {
        // ignore
      }
      if (!settled) {
        settled = true;
        resolve(null);
      }
    }, 6000);
    timer.unref();

    child.stdout?.on('data', (c: Buffer) => chunks.push(c));
    child.once('error', () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(null);
    });
    child.once('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (code !== 0) {
        resolve(null);
        return;
      }
      const ver = Buffer.concat(chunks).toString('utf8').replace(/\r/g, '').trim();
      resolve(ver || null);
    });
  });
}

async function defaultStageRunner(opts: {
  distro: string;
  username?: string;
}): Promise<{ runnerPath: string; version: string }> {
  const root = findRepoRoot();
  if (!root) {
    failSandbox('INVALID_SETUP', 'Could not locate dsh-wsl-sandbox repository root for runner staging');
  }
  const modPath = path.join(root, 'scripts', 'stage-wsl-runner.mjs');
  const mod = (await import(pathToFileURL(modPath).href)) as {
    stageRunnerIntoWslAsync: (o: { distro: string; username?: string }) => Promise<{
      runnerPath: string;
      version: string;
    }>;
  };
  return mod.stageRunnerIntoWslAsync(opts);
}

/**
 * Coordinates the single active verified `SessionBinding`, persistent `WslTransport`,
 * managed in-WSL `UdsAllowlistProxy`, and `ApprovalBridge` across all 7 `wsl_*` tools.
 */
export class WslSandboxSessionManager {
  private readonly options: SessionManagerOptions;
  private readonly configStore: ConfigStore;
  private readonly approvalBridge: ApprovalBridge;
  private readonly sessionId: string;
  private readonly allowLinuxDevMode: boolean;
  private readonly logger?: StructuredLogger;
  private readonly onStderr?: (line: string) => void;

  private transport: TransportLike | undefined;
  private binding: SessionBinding | undefined;
  private boundEffectiveRevision: string | undefined;
  private bindingPromise: Promise<SessionBinding> | undefined;
  private probedHomeDir: string | undefined;
  private bindingConfigUpdateInProgress = false;
  private readonly terminalCwds = new Map<string, string>();
  private generation = 0;
  private proxyConfiguredRevision: string | undefined;
  private unsubscribeConfig: (() => void) | undefined;

  private bootstrapActive = false;
  private bootstrapPhase: BootstrapPhase = 'idle';
  private bootstrapPreviewedDryRun = false;
  private bootstrapStartedAtMs: number | undefined;
  private bootstrapExpiresAtMs: number | undefined;
  private bootstrapTargetDistro: string | undefined;

  constructor(options: SessionManagerOptions) {
    this.options = options;
    this.configStore = options.configStore;
    this.approvalBridge = options.approvalBridge;
    this.sessionId = options.sessionId ?? `dsh-wsl-${randomUUID().slice(0, 8)}`;
    this.allowLinuxDevMode = options.allowLinuxDevMode ?? process.platform === 'linux';
    this.logger = options.logger;
    this.onStderr = options.onStderr;

    this.unsubscribeConfig = this.configStore.onChange((next, prev) => {
      void this.handleConfigChanged(next, prev);
    });
  }

  getLogger(): StructuredLogger | undefined {
    return this.logger;
  }

  getBindingSnapshot(): SessionBinding | undefined {
    return this.binding;
  }

  getTerminalCwd(terminalId: string): string | undefined {
    return this.terminalCwds.get(terminalId);
  }

  setTerminalCwd(terminalId: string, cwd: string): void {
    if (cwd) {
      this.terminalCwds.set(terminalId, cwd);
    }
  }

  clearTerminalCwd(terminalId?: string): void {
    if (terminalId) {
      this.terminalCwds.delete(terminalId);
    } else {
      this.terminalCwds.clear();
    }
  }

  getGeneration(): number {
    return this.generation;
  }

  isRunnerActive(): boolean {
    return Boolean(this.transport?.isRunning());
  }

  /** 读取当前受控 AI 初始化引导通道状态；超时后自动恢复为关闭态。 */
  getBootstrapChannelState(): BootstrapChannelState {
    const now = Date.now();
    if (this.bootstrapActive && this.bootstrapExpiresAtMs !== undefined && now >= this.bootstrapExpiresAtMs) {
      this.bootstrapActive = false;
      this.bootstrapPhase = 'idle';
      this.bootstrapPreviewedDryRun = false;
      this.bootstrapStartedAtMs = undefined;
      this.bootstrapExpiresAtMs = undefined;
      this.bootstrapTargetDistro = undefined;
    }
    const pluginRoot = findRepoRoot();
    return {
      active: this.bootstrapActive,
      phase: this.bootstrapActive ? this.bootstrapPhase : 'idle',
      previewedDryRun: this.bootstrapActive && this.bootstrapPreviewedDryRun,
      startedAtMs: this.bootstrapStartedAtMs,
      expiresAtMs: this.bootstrapExpiresAtMs,
      remainingMs:
        this.bootstrapActive && this.bootstrapExpiresAtMs !== undefined
          ? Math.max(0, this.bootstrapExpiresAtMs - now)
          : 0,
      targetDistro: this.bootstrapTargetDistro,
      pluginRoot,
      installScriptPath: pluginRoot
        ? path.join(pluginRoot, 'packages', 'bootstrap', 'install-dsh-plugin.ps1')
        : undefined,
      stageScriptPath: pluginRoot ? path.join(pluginRoot, 'scripts', 'stage-wsl-runner.mjs') : undefined,
      provisionScriptPath: pluginRoot
        ? path.join(pluginRoot, 'packages', 'bootstrap', 'provision-wsl.sh')
        : undefined,
    };
  }

  /** 开启或关闭受控 AI 初始化引导通道（仅限人工控制台 UI 或宿主机本地接口调用）。 */
  setBootstrapChannel(opts: {
    active: boolean;
    ttlMs?: number;
    targetDistro?: string;
  }): BootstrapChannelState {
    if (!opts.active) {
      this.bootstrapActive = false;
      this.bootstrapPhase = 'idle';
      this.bootstrapPreviewedDryRun = false;
      this.bootstrapStartedAtMs = undefined;
      this.bootstrapExpiresAtMs = undefined;
      this.bootstrapTargetDistro = undefined;
      this.logger?.log('info', {
        component: 'bootstrap',
        event: 'bootstrap.channelClosed',
        message: '受控 AI 初始化引导通道已关闭',
        sessionId: this.sessionId,
      });
      return this.getBootstrapChannelState();
    }

    const now = Date.now();
    const rawTtl = opts.ttlMs ?? DEFAULT_BOOTSTRAP_TTL_MS;
    const ttlMs = Math.max(60_000, Math.min(60 * 60 * 1000, Number.isFinite(rawTtl) ? Math.floor(rawTtl) : DEFAULT_BOOTSTRAP_TTL_MS));
    const trimmedDistro = opts.targetDistro?.trim();
    if (trimmedDistro && !isValidDistroName(trimmedDistro)) {
      failSandbox('INVALID_SETUP', `Invalid targetDistro for bootstrap channel: ${trimmedDistro}`);
    }

    this.bootstrapActive = true;
    this.bootstrapPhase = '1-probe';
    this.bootstrapPreviewedDryRun = false;
    this.bootstrapStartedAtMs = now;
    this.bootstrapExpiresAtMs = now + ttlMs;
    this.bootstrapTargetDistro = trimmedDistro || undefined;

    this.logger?.log('info', {
      component: 'bootstrap',
      event: 'bootstrap.channelOpened',
      message: `已开启受控 AI 初始化引导通道（targetDistro=${this.bootstrapTargetDistro ?? '待探测确认'}, ttl=${Math.round(ttlMs / 60000)}m）`,
      sessionId: this.sessionId,
      data: { targetDistro: this.bootstrapTargetDistro ?? null, ttlMs },
    });
    return this.getBootstrapChannelState();
  }

  /** 记录 `-DryRun` / `--dry-run` 安装预览已由人工审批执行，解锁下一步真实安装审批门禁。 */
  markBootstrapPreviewCompleted(distro?: string): BootstrapChannelState {
    const cur = this.getBootstrapChannelState();
    if (!cur.active) return cur;
    this.bootstrapPreviewedDryRun = true;
    if (this.bootstrapPhase === '1-probe' || this.bootstrapPhase === 'idle') {
      this.bootstrapPhase = '2-previewed';
    }
    const cleanDistro = distro?.trim();
    if (cleanDistro && !this.bootstrapTargetDistro && isValidDistroName(cleanDistro)) {
      this.bootstrapTargetDistro = cleanDistro;
    }
    this.logger?.log('info', {
      component: 'bootstrap',
      event: 'bootstrap.previewCompleted',
      message: `已完成 -DryRun 安装脚本预览（targetDistro=${this.bootstrapTargetDistro ?? 'auto'}），已解锁单次审批安装阶段`,
      sessionId: this.sessionId,
    });
    return this.getBootstrapChannelState();
  }

  /** 记录受控安装步骤已获得人工单次审批并执行，并尝试从磁盘同步最新 config.json。 */
  markBootstrapInstallStarted(): BootstrapChannelState {
    const cur = this.getBootstrapChannelState();
    if (!cur.active) return cur;
    this.bootstrapPhase = '3-installing';
    this.configStore.reloadFromDisk();
    this.logger?.log('info', {
      component: 'bootstrap',
      event: 'bootstrap.installExecuted',
      message: '已完成受控单次审批安装步骤并同步磁盘配置',
      sessionId: this.sessionId,
    });
    return this.getBootstrapChannelState();
  }

  getNodeRuntimeSummary(): NodeRuntimeSummary {
    const host = resolveSharedHostNodeRuntime();
    const runnerInfo = this.transport?.getRunnerNodeInfo();
    const cfg = this.configStore.get();
    return {
      hostNodeVersion: host.nodeVersion,
      hostNodeExecutable: host.executable,
      hostSharedWithDsh: host.sharedWithHostProcess,
      isElectronCarrier: host.isElectronCarrier,
      configuredWslNodePath: cfg.wslNodePath ?? 'auto',
      wslNodeVersion: runnerInfo?.nodeVersion ?? null,
      wslNodeExecPath: runnerInfo?.nodeExecPath ?? null,
    };
  }

  private async handleConfigChanged(next: WslSandboxConfig, prev: WslSandboxConfig): Promise<void> {
    if (this.bindingConfigUpdateInProgress) {
      return;
    }

    if (next.logLevel !== prev.logLevel) {
      this.logger?.setLevel(next.logLevel);
      if (this.transport?.isRunning()) {
        await this.transport.setRunnerLogLevel(next.logLevel);
      }
    }

    // Avoid bumping generation, invalidating ApprovalBridge, or killing active terminals/processes
    // when ONLY logLevel, backupDir, approvalTimeoutMs, or enablePromptInjection changed!
    const onlyNonDisruptiveChanged =
      next.enabled === prev.enabled &&
      next.transportMode === prev.transportMode &&
      next.distro === prev.distro &&
      next.username === prev.username &&
      next.workspaceRoot === prev.workspaceRoot &&
      next.runnerPath === prev.runnerPath &&
      next.wslNodePath === prev.wslNodePath &&
      next.environmentProfile === prev.environmentProfile &&
      next.sandboxMode === prev.sandboxMode &&
      next.approvalPolicyMode === prev.approvalPolicyMode &&
      next.networkMode === prev.networkMode &&
      next.upstreamProxy === prev.upstreamProxy &&
      next.mirrorCn === prev.mirrorCn &&
      next.cacheMode === prev.cacheMode &&
      next.enablePwshGuard === prev.enablePwshGuard &&
      JSON.stringify(next.unmaskedEnvWorkspaces) === JSON.stringify(prev.unmaskedEnvWorkspaces) &&
      JSON.stringify(next.advanced) === JSON.stringify(prev.advanced);

    if (onlyNonDisruptiveChanged) {
      if (this.binding && this.boundEffectiveRevision === prev.revision) {
        this.boundEffectiveRevision = next.revision;
      }
      if (this.proxyConfiguredRevision === prev.revision) {
        this.proxyConfiguredRevision = next.revision;
      }
      this.logger?.log('info', {
        component: 'config',
        event: next.logLevel !== prev.logLevel ? 'config.logLevelChanged' : 'config.nonDisruptiveUpdated',
        message:
          next.logLevel !== prev.logLevel
            ? `Updated log level to '${next.logLevel}'`
            : `Updated non-disruptive setting (${next.revision})`,
        data: { revision: next.revision, logLevel: next.logLevel },
      });
      return;
    }

    this.generation += 1;
    this.binding = undefined;
    this.boundEffectiveRevision = undefined;
    this.proxyConfiguredRevision = undefined;
    this.clearTerminalCwd();
    this.approvalBridge.invalidate(`Configuration changed to ${next.revision}`);

    this.logger?.log('info', {
      component: 'config',
      event: 'config.updated',
      message: `Configuration updated (${next.revision}): distro=${next.distro}, profile=${next.environmentProfile}, mode=${next.sandboxMode}`,
      sessionId: this.sessionId,
      data: {
        revision: next.revision,
        enabled: next.enabled,
        distro: next.distro,
        environmentProfile: next.environmentProfile,
        sandboxMode: next.sandboxMode,
        networkMode: next.networkMode,
      },
    });

    const transportChanged =
      next.transportMode !== prev.transportMode ||
      next.distro !== prev.distro ||
      next.username !== prev.username ||
      next.runnerPath !== prev.runnerPath ||
      next.wslNodePath !== prev.wslNodePath;

    if (transportChanged) {
      this.probedHomeDir = undefined;
    }

    if (this.transport) {
      if (transportChanged || !next.enabled) {
        const old = this.transport;
        this.transport = undefined;
        await old.dispose().catch(() => {});
      } else {
        await this.transport.invalidate(this.generation, { sessionId: this.sessionId });
      }
    }
  }

  private ensureTransport(cfg: WslSandboxConfig): TransportLike {
    if (!cfg.enabled) {
      failSandbox('SANDBOX_UNAVAILABLE', 'dsh-wsl-sandbox is currently disabled in configuration');
    }
    if (!this.transport) {
      this.transport = this.options.transportFactory
        ? this.options.transportFactory(cfg)
        : new WslTransport({
            mode: cfg.transportMode,
            distro: cfg.distro,
            username: cfg.username,
            runnerPath: cfg.runnerPath,
            nodeExecutable: cfg.wslNodePath,
            logLevel: cfg.logLevel,
            logger: this.logger,
            onStderr: this.onStderr,
            onAuthorizeProxyHost: (host, port) => this.authorizeUnknownProxyHost(host, port),
          });
    }
    return this.transport;
  }

  private async authorizeUnknownProxyHost(host: string, port: number): Promise<boolean> {
    try {
      const binding = this.binding ?? (await this.ensureBound());
      const ticket = await this.approvalBridge.requestApproval(
        binding,
        {
          kind: 'network-access',
          summary: `Allow outbound network access to ${host}:${port}`,
          reasons: [`Domain ${host}:${port} is not in the default dev-registry allowlist`],
          requestedDelta: { host, port },
          touchesPhysicalDevice: false,
        },
        {
          requireIndependentFallback: true,
          eligibleForTrustWorkspace: false,
        },
      );
      ticket.assertCurrent();
      ticket.consume();
      if (this.transport) {
        await this.transport.call('proxy.approveDomain', { host }, 5_000).catch(() => {});
      }
      return true;
    } catch {
      return false;
    }
  }

  async ensureBound(): Promise<SessionBinding> {
    const cfg = this.configStore.get();
    if (
      this.binding &&
      (this.binding.revision === cfg.revision || this.boundEffectiveRevision === cfg.revision) &&
      this.transport?.isRunning()
    ) {
      await this.syncProxyPolicy(cfg);
      return this.binding;
    }
    if (this.bindingPromise) {
      return this.bindingPromise;
    }
    this.bindingPromise = this.performBind().finally(() => {
      this.bindingPromise = undefined;
    });
    return this.bindingPromise;
  }

  private async performBind(): Promise<SessionBinding> {
    this.configStore.reloadFromDisk();
    let cfg = this.configStore.get();
    if (!cfg.enabled) {
      failSandbox('SANDBOX_UNAVAILABLE', 'dsh-wsl-sandbox is currently disabled in configuration');
    }

    const shouldAutoPrepareWsl =
      cfg.transportMode === 'wsl' &&
      ((process.platform === 'win32' && !isHostSpawnDisabled()) ||
        Boolean(this.options.stageRunner || this.options.discoverDistros));

    if (shouldAutoPrepareWsl) {
      const needsDiscovery =
        !cfg.username ||
        cfg.distro === 'Ubuntu-26.04' ||
        cfg.workspaceRoot === '/home/dev/workspace' ||
        cfg.runnerPath.includes('/home/dev/.local/share/dsh-wsl-sandbox/runner/');

      if (needsDiscovery) {
        const discover = this.options.discoverDistros ?? discoverWslDistrosAsync;
        const probeUser = this.options.probeDistroUser ?? probeWslDistroUserAsync;
        const report = await discover();

        const exactMatch = report.distros.find(
          (d) => !d.isInternalContainer && d.name.toLowerCase() === cfg.distro.toLowerCase(),
        );
        let targetDistro = exactMatch ? exactMatch.name : cfg.distro;
        if (
          cfg.distro === 'Ubuntu-26.04' &&
          !exactMatch &&
          report.distros.some((d) => d.supported)
        ) {
          targetDistro = report.recommendedDistro;
        }
        const switchedDistro = targetDistro !== cfg.distro;
        const probed = await probeUser(targetDistro, cfg.username);

        const patch: BasicConfigPatch = {};
        if (switchedDistro) {
          patch.distro = targetDistro;
        }
        if (probed && probed.uid > 0) {
          this.probedHomeDir = probed.homeDir;
          if (!cfg.username || cfg.username !== probed.username) {
            patch.username = probed.username;
          }
          if (cfg.workspaceRoot === '/home/dev/workspace' || switchedDistro) {
            const nextWs = posix.join(probed.homeDir, 'workspace');
            if (nextWs !== cfg.workspaceRoot) {
              patch.workspaceRoot = nextWs;
            }
          }
          if (cfg.runnerPath.includes('/.local/share/dsh-wsl-sandbox/runner/')) {
            const nextRunner = posix.join(
              probed.homeDir,
              '.local/share/dsh-wsl-sandbox/runner/dist/packages/wsl-runner/src/main.js',
            );
            if (nextRunner !== cfg.runnerPath) {
              patch.runnerPath = nextRunner;
            }
          }
        }

        if (Object.keys(patch).length > 0) {
          this.bindingConfigUpdateInProgress = true;
          try {
            this.configStore.updateBasic(patch);
            cfg = this.configStore.get();
          } finally {
            this.bindingConfigUpdateInProgress = false;
          }
        }
      }

      const managedMarker = '/.local/share/dsh-wsl-sandbox/runner/';
      const markerIdx = cfg.runnerPath.indexOf(managedMarker);
      if (markerIdx !== -1) {
        const runnerRoot = cfg.runnerPath.slice(
          0,
          markerIdx + '/.local/share/dsh-wsl-sandbox/runner'.length,
        );
        const checkVersion = this.options.checkStagedVersion ?? defaultCheckStagedVersion;
        const stagedVer = await checkVersion(cfg.distro, cfg.username, runnerRoot, cfg.runnerPath);
        const localVer = readLocalPackageVersion();
        if (!stagedVer || (localVer && stagedVer !== localVer)) {
          const stageFn = this.options.stageRunner ?? defaultStageRunner;
          const staged = await stageFn({ distro: cfg.distro, username: cfg.username });
          if (staged.runnerPath && staged.runnerPath !== cfg.runnerPath) {
            this.bindingConfigUpdateInProgress = true;
            try {
              this.configStore.updateBasic({ runnerPath: staged.runnerPath });
              cfg = this.configStore.get();
            } finally {
              this.bindingConfigUpdateInProgress = false;
            }
          }
        }
      }
    }

    const transport = this.ensureTransport(cfg);
    this.generation += 1;

    const probeResult = await transport.call<ProbeResponse>(
      'probe',
      {
        sessionId: this.sessionId,
        distribution: cfg.distro,
        workspaceRoot: cfg.workspaceRoot,
        cwd: cfg.workspaceRoot,
        profile: cfg.sandboxMode,
        revision: cfg.revision,
        allowLinuxDevMode: this.allowLinuxDevMode,
        authorizedShares: cfg.advanced.shares,
        authorizedDevices: cfg.advanced.deviceNodes,
      },
      20_000,
    );

    if (typeof probeResult?.homeDir === 'string' && probeResult.homeDir.startsWith('/')) {
      this.probedHomeDir = probeResult.homeDir;
    }

    const verified = assertVerifiedProbe(probeResult, {
      expectedSessionId: this.sessionId,
      expectedDistribution: cfg.distro,
      expectedWorkspaceRoot: cfg.workspaceRoot,
      expectedCwd: cfg.workspaceRoot,
      expectedProfile: cfg.sandboxMode,
      expectedRevision: cfg.revision,
      generation: this.generation,
      homeDir: this.probedHomeDir,
      authorizedShares: cfg.advanced.shares,
      authorizedDevices: cfg.advanced.deviceNodes,
    });

    this.binding = verified;
    this.boundEffectiveRevision = cfg.revision;
    this.approvalBridge.setBinding(verified);
    await this.syncProxyPolicy(cfg);
    if (verified.sandboxReady && this.getBootstrapChannelState().active) {
      this.setBootstrapChannel({ active: false });
    }
    return verified;
  }

  private async syncProxyPolicy(cfg: WslSandboxConfig): Promise<void> {
    if (!this.transport || this.proxyConfiguredRevision === cfg.revision) return;
    await this.transport.call(
      'proxy.configure',
      {
        enabled: cfg.networkMode === 'allowlist-proxy',
        customAllowedDomains: cfg.advanced.customAllowedDomains,
        upstreamProxy: cfg.upstreamProxy,
        localLabCidrs: cfg.advanced.localLabCidrs,
        localLabPorts: cfg.advanced.localLabPorts,
        enableInteractiveApproval: true,
      },
      10_000,
    );
    this.proxyConfiguredRevision = cfg.revision;
  }

  async invalidateNow(reason = 'Manual invalidation', terminalId?: string): Promise<number> {
    this.generation += 1;
    if (terminalId) {
      this.clearTerminalCwd(terminalId);
    } else {
      this.binding = undefined;
      this.boundEffectiveRevision = undefined;
      this.proxyConfiguredRevision = undefined;
      this.clearTerminalCwd();
      this.approvalBridge.invalidate(reason);
    }
    if (this.transport) {
      return this.transport.invalidate(this.generation, { sessionId: this.sessionId, terminalId });
    }
    return 0;
  }

  async killExec(execId: string): Promise<boolean> {
    if (!this.transport?.isRunning()) return false;
    try {
      const r = await this.transport.call<{ killed: boolean }>('proc.kill', { execId }, 5_000);
      return Boolean(r.killed);
    } catch {
      return false;
    }
  }

  async callRpc<T = unknown>(method: string, params: Record<string, unknown>, timeoutMs?: number): Promise<T> {
    const cfg = this.configStore.get();
    const transport = this.ensureTransport(cfg);
    return transport.call<T>(method, params, timeoutMs);
  }

  computeCacheDir(binding: SessionBinding, cfg: WslSandboxConfig): string | undefined {
    if (cfg.cacheMode !== 'workspace-persistent') return undefined;
    const hash = createHash('sha256').update(binding.workspaceRoot).digest('hex').slice(0, 12);
    const home = this.probedHomeDir ?? `/home/${binding.username}`;
    return `${home}/.cache/dsh-wsl-sandbox/${hash}`;
  }

  async dispose(): Promise<void> {
    this.unsubscribeConfig?.();
    this.unsubscribeConfig = undefined;
    this.binding = undefined;
    this.boundEffectiveRevision = undefined;
    this.proxyConfiguredRevision = undefined;
    this.clearTerminalCwd();
    this.approvalBridge.invalidate('Plugin disposed');
    if (this.transport) {
      const t = this.transport;
      this.transport = undefined;
      await t.dispose();
    }
  }
}

function resolveToolCwd(binding: SessionBinding, requestedCwd?: string): string {
  if (!requestedCwd || requestedCwd.trim() === '') return binding.workspaceRoot;
  const resolved = requestedCwd.startsWith('/')
    ? posix.normalize(requestedCwd)
    : posix.normalize(posix.join(binding.workspaceRoot, requestedCwd));
  if (!isPathInside(binding.workspaceRoot, resolved)) {
    const inShare = binding.authorizedShares.some((s) => isPathInside(`/shares/${s.alias}`, resolved));
    if (!inShare) {
      failSandbox('POLICY_BLOCK', `Requested cwd '${resolved}' is outside bound workspace '${binding.workspaceRoot}'`);
    }
  }
  return resolved;
}

export function createWslSandboxTools(
  sessionManager: WslSandboxSessionManager,
  configStore: ConfigStore,
  approvalBridge: ApprovalBridge,
): DshToolDefinition[] {
  async function executeGuardedCommand(
    params: {
      toolName: string;
      command: string;
      cwd?: string;
      timeoutMs?: number;
      sandboxPermissions?: 'default' | 'escalated';
      justification?: string;
      env?: Record<string, string>;
      terminalId?: string;
    },
    meta?: DshToolCallMeta,
  ): Promise<ProcExecResult | TerminalExecResult> {
    if (meta?.signal?.aborted) {
      failSandbox('REVIEW_CANCELLED', 'Tool call aborted before execution');
    }
    const cfg = configStore.get();
    const binding = await sessionManager.ensureBound();
    const requestedOrSavedCwd =
      params.cwd !== undefined
        ? params.cwd
        : params.terminalId
          ? (sessionManager.getTerminalCwd(params.terminalId) ?? binding.workspaceRoot)
          : undefined;
    const cwd = resolveToolCwd(binding, requestedOrSavedCwd);

    const guard = evaluateBashCommand(params.command, {
      workspaceRoot: binding.workspaceRoot,
      cwd,
      authorizedShares: binding.authorizedShares,
      authorizedDevices: binding.authorizedDevices,
    });

    if (guard.decision === 'deny') {
      sessionManager.getLogger()?.log('warn', {
        component: 'tools',
        event: 'wslGuard.deny',
        message: `Blocked ${params.toolName} command at L0 AST/dialect policy: ${guard.reasons.join('; ')}`,
        sessionId: binding.sessionId,
        data: { toolName: params.toolName, riskLevel: guard.riskLevel, reasons: guard.reasons },
      });
      failSandbox(
        'POLICY_BLOCK',
        `WSL command blocked by L0 zero-token AST/dialect policy: ${guard.reasons.join('; ')}`,
        { riskLevel: guard.riskLevel, reasons: guard.reasons },
      );
    }

    const effectivePhysicalDevice =
      guard.touchesPhysicalDevice || binding.authorizedDevices.length > 0;
    const requestedEscalation = params.sandboxPermissions === 'escalated';
    const needsApproval = guard.decision === 'ask' || effectivePhysicalDevice || requestedEscalation;

    let effectiveMode: SandboxMode = cfg.sandboxMode;
    if (needsApproval) {
      const reasons = [...guard.reasons];
      if (binding.authorizedDevices.length > 0 && !guard.touchesPhysicalDevice) {
        reasons.push(
          `Active physical device passthrough (${binding.authorizedDevices.map((d) => d.path).join(', ')}) enforces manual single-shot approval (Q13)`,
        );
      }
      if (requestedEscalation) {
        reasons.push(
          `Model requested escalated sandbox permissions${params.justification ? `: ${params.justification}` : ''}`,
        );
      }

      const kind = effectivePhysicalDevice
        ? 'physical-device'
        : requestedEscalation
          ? 'sandbox-escalation'
          : guard.externalPaths.length > 0
            ? 'external-path'
            : 'dangerous-command';

      const inWorkspaceOnly =
        guard.externalPaths.length === 0 && !effectivePhysicalDevice && !requestedEscalation;

      const ticket = await approvalBridge.requestApproval(
        binding,
        {
          kind,
          summary: effectivePhysicalDevice
            ? `Physical device command in WSL (${binding.distribution})`
            : requestedEscalation
              ? `Escalated WSL command in ${binding.distribution}`
              : `WSL command requiring approval in ${binding.distribution}`,
          command: params.command,
          canonicalArgv: guard.unwrappedCommands[0],
          reasons,
          touchesPhysicalDevice: effectivePhysicalDevice,
          suggestedPrefix: effectivePhysicalDevice ? undefined : guard.suggestedPrefix,
          requestedDelta: requestedEscalation
            ? { mode: 'workspace-write', justification: params.justification }
            : undefined,
        },
        {
          requireIndependentFallback:
            effectivePhysicalDevice ||
            requestedEscalation ||
            guard.externalPaths.length > 0 ||
            guard.riskLevel === 'high' ||
            guard.riskLevel === 'critical',
          eligibleForTrustWorkspace: inWorkspaceOnly,
          agent: meta?.agent,
          toolName: params.toolName,
          callId: meta?.callId,
          callerSignal: meta?.signal,
        },
      );

      ticket.assertCurrent();
      if (requestedEscalation) {
        effectiveMode = 'workspace-write';
      }
      ticket.consume();
    }

    const execId = randomUUID();
    const execPayload = {
      execId,
      binding,
      command: params.command,
      cwd,
      mode: effectiveMode,
      networkMode: cfg.networkMode,
      env: params.env,
      timeoutMs: params.timeoutMs,
      cacheDir: sessionManager.computeCacheDir(binding, cfg),
      maskEnvSecrets: configStore.isWorkspaceEnvMasked(binding.workspaceRoot),
      mirrorCn: cfg.mirrorCn,
    };

    const onAbort = (): void => {
      void sessionManager.killExec(execId);
    };
    meta?.signal?.addEventListener('abort', onAbort, { once: true });
    try {
      if (params.terminalId) {
        const termRes = await sessionManager.callRpc<TerminalExecResult>(
          'term.exec',
          {
            ...execPayload,
            terminalId: params.terminalId,
            explicitCwd: params.cwd !== undefined,
          },
          (params.timeoutMs ?? 120_000) + 15_000,
        );
        if (typeof termRes?.cwd === 'string' && termRes.cwd.startsWith('/')) {
          sessionManager.setTerminalCwd(params.terminalId, termRes.cwd);
        }
        return termRes;
      }

      return await sessionManager.callRpc<ProcExecResult>(
        'proc.exec',
        execPayload,
        (params.timeoutMs ?? 120_000) + 15_000,
      );
    } finally {
      meta?.signal?.removeEventListener('abort', onAbort);
    }
  }

  return [
    {
      name: 'wsl_bash',
      description:
        'Execute a pure POSIX Bash command inside the isolated WSL 2 Linux guest sandbox (bwrap + seccomp-bpf + prlimit + UDS allowlist proxy). Prefer this over Windows pwsh for directory creation, file moves, coding, git, builds, tests, cross-compilation, and Linux CLI tools. Note: cwd is an isolated Linux guest path (separate from Windows host NTFS; if declaring to cc-safety-net, pass --no-cwd-arg).',
      parameters: {
        type: 'object',
        required: ['command'],
        additionalProperties: false,
        properties: {
          command: { type: 'string', description: 'Pure POSIX Bash command to execute (do not mix PowerShell or CMD syntax)' },
          cwd: { type: 'string', description: 'Linux working directory inside the bound WSL workspace' },
          timeoutMs: { type: 'number', description: 'Timeout in milliseconds (max 600000)' },
          sandbox_permissions: {
            type: 'string',
            enum: ['default', 'escalated'],
            description: 'Optional escalated retry request (requires human approval)',
          },
          justification: { type: 'string', description: 'Reason when requesting escalated permissions' },
          env: {
            type: 'object',
            additionalProperties: true,
            description: 'Optional extra environment variables (sanitized against dangerous loader/proxy keys)',
          },
        },
      },
      output: {
        schema: {
          type: 'object',
          additionalProperties: true,
          description: 'WSL 2 sandboxed Bash execution result',
        },
        render: (_args, value) => renderExecOutcome(value),
      },
      execute: async (input, meta) =>
        executeGuardedCommand(
          {
            toolName: 'wsl_bash',
            command: String(input.command ?? ''),
            cwd: typeof input.cwd === 'string' ? input.cwd : undefined,
            timeoutMs: typeof input.timeoutMs === 'number' ? input.timeoutMs : undefined,
            sandboxPermissions: input.sandbox_permissions === 'escalated' ? 'escalated' : 'default',
            justification: typeof input.justification === 'string' ? input.justification : undefined,
            env:
              input.env && typeof input.env === 'object'
                ? (input.env as Record<string, string>)
                : undefined,
          },
          meta,
        ),
    },
    {
      name: 'wsl_read',
      description:
        'Read a file inside the bound WSL 2 workspace by 1-based line offset and line limit (native ext4, zero 9P overhead, honors .env* secret masking).',
      parameters: {
        type: 'object',
        required: ['path'],
        additionalProperties: false,
        properties: {
          path: { type: 'string', description: 'Relative or absolute Linux path inside the workspace' },
          offset: { type: 'number', description: '1-based starting line number (default: 1)' },
          limit: { type: 'number', description: 'Maximum lines to return (default: 2000)' },
        },
      },
      isConcurrencySafe: () => true,
      output: {
        schema: {
          type: 'object',
          additionalProperties: true,
          description: 'WSL 2 file read result',
        },
        render: (_args, value) => renderGenericJson(value),
      },
      execute: async (input) => {
        const binding = await sessionManager.ensureBound();
        return sessionManager.callRpc('fs.read', {
          binding,
          path: String(input.path ?? ''),
          offset: typeof input.offset === 'number' ? input.offset : undefined,
          limit: typeof input.limit === 'number' ? input.limit : undefined,
          maskEnvSecrets: configStore.isWorkspaceEnvMasked(binding.workspaceRoot),
        });
      },
    },
    {
      name: 'wsl_write',
      description:
        'Write a file atomically inside the bound WSL 2 workspace (enforces read-only mode, symlink containment, and Checklist B locks).',
      parameters: {
        type: 'object',
        required: ['path', 'content'],
        additionalProperties: false,
        properties: {
          path: { type: 'string', description: 'Relative or absolute Linux path inside the workspace' },
          content: { type: 'string', description: 'UTF-8 file content to write' },
        },
      },
      output: {
        schema: {
          type: 'object',
          additionalProperties: true,
          description: 'WSL 2 file write result',
        },
        render: (_args, value) => renderGenericJson(value),
      },
      execute: async (input) => {
        const binding = await sessionManager.ensureBound();
        return sessionManager.callRpc('fs.write', {
          binding,
          path: String(input.path ?? ''),
          content: String(input.content ?? ''),
        });
      },
    },
    {
      name: 'wsl_edit',
      description:
        'Perform targeted string replacement in a file inside the bound WSL 2 workspace.',
      parameters: {
        type: 'object',
        required: ['path', 'oldText', 'newText'],
        additionalProperties: false,
        properties: {
          path: { type: 'string' },
          oldText: { type: 'string' },
          newText: { type: 'string' },
          replaceAll: { type: 'boolean' },
        },
      },
      output: {
        schema: {
          type: 'object',
          additionalProperties: true,
          description: 'WSL 2 file edit result',
        },
        render: (_args, value) => renderGenericJson(value),
      },
      execute: async (input) => {
        const binding = await sessionManager.ensureBound();
        return sessionManager.callRpc('fs.edit', {
          binding,
          path: String(input.path ?? ''),
          oldText: String(input.oldText ?? ''),
          newText: String(input.newText ?? ''),
          replaceAll: Boolean(input.replaceAll),
        });
      },
    },
    {
      name: 'wsl_glob',
      description: 'Find files matching a glob pattern inside the bound WSL 2 workspace.',
      parameters: {
        type: 'object',
        required: ['pattern'],
        additionalProperties: false,
        properties: {
          pattern: { type: 'string' },
          cwd: { type: 'string' },
          maxResults: { type: 'number' },
        },
      },
      isConcurrencySafe: () => true,
      output: {
        schema: {
          type: 'object',
          additionalProperties: true,
          description: 'WSL 2 glob search result',
        },
        render: (_args, value) => renderGenericJson(value),
      },
      execute: async (input) => {
        const binding = await sessionManager.ensureBound();
        return sessionManager.callRpc('fs.glob', {
          binding,
          pattern: String(input.pattern ?? '*'),
          cwd: typeof input.cwd === 'string' ? input.cwd : undefined,
          maxResults: typeof input.maxResults === 'number' ? input.maxResults : undefined,
        });
      },
    },
    {
      name: 'wsl_grep',
      description:
        'Search text/regex across files in the bound WSL 2 workspace (honors .env* secret masking).',
      parameters: {
        type: 'object',
        required: ['query'],
        additionalProperties: false,
        properties: {
          query: { type: 'string' },
          cwd: { type: 'string' },
          regex: { type: 'boolean' },
          maxMatches: { type: 'number' },
        },
      },
      isConcurrencySafe: () => true,
      output: {
        schema: {
          type: 'object',
          additionalProperties: true,
          description: 'WSL 2 grep search result',
        },
        render: (_args, value) => renderGenericJson(value),
      },
      execute: async (input) => {
        const binding = await sessionManager.ensureBound();
        return sessionManager.callRpc('fs.grep', {
          binding,
          query: String(input.query ?? ''),
          cwd: typeof input.cwd === 'string' ? input.cwd : undefined,
          regex: Boolean(input.regex),
          maxMatches: typeof input.maxMatches === 'number' ? input.maxMatches : undefined,
          maskEnvSecrets: configStore.isWorkspaceEnvMasked(binding.workspaceRoot),
        });
      },
    },
    {
      name: 'wsl_terminal',
      description:
        'Stateful sandboxed WSL 2 Linux shell session that tracks working directory across commands via EXIT trap while keeping every command inside the same bwrap + seccomp + approval boundary. Note: cwd is an isolated Linux guest path (for cc-safety-net tool declarations, pass --no-cwd-arg).',
      parameters: {
        type: 'object',
        required: ['command'],
        additionalProperties: false,
        properties: {
          terminalId: { type: 'string', description: 'Logical terminal session ID (default: "default")' },
          command: { type: 'string', description: 'Pure POSIX Bash command to execute in this stateful terminal' },
          cwd: { type: 'string' },
          timeoutMs: { type: 'number' },
          reset: { type: 'boolean', description: 'Reset saved working directory before executing' },
        },
      },
      output: {
        schema: {
          type: 'object',
          additionalProperties: true,
          description: 'WSL 2 stateful terminal execution result',
        },
        render: (_args, value) => renderExecOutcome(value),
      },
      execute: async (input, meta) => {
        const terminalId =
          typeof input.terminalId === 'string' && input.terminalId.trim()
            ? input.terminalId.trim()
            : 'default';
        if (input.reset) {
          const binding = await sessionManager.ensureBound();
          sessionManager.clearTerminalCwd(terminalId);
          await sessionManager.callRpc('term.reset', { terminalId, sessionId: binding.sessionId });
        }
        return executeGuardedCommand(
          {
            toolName: 'wsl_terminal',
            terminalId,
            command: String(input.command ?? ''),
            cwd: typeof input.cwd === 'string' ? input.cwd : undefined,
            timeoutMs: typeof input.timeoutMs === 'number' ? input.timeoutMs : undefined,
          },
          meta,
        );
      },
    },
  ];
}

export function registerWslSandboxTools(
  ctx: DshCordisContext,
  sessionManager: WslSandboxSessionManager,
  configStore: ConfigStore,
  approvalBridge: ApprovalBridge,
): (() => void)[] {
  const disposers: (() => void)[] = [];
  if (!ctx.tools) return disposers;

  const tools = createWslSandboxTools(sessionManager, configStore, approvalBridge);
  const logger = sessionManager.getLogger();
  for (const tool of tools) {
    if (typeof ctx.tools.has === 'function' && ctx.tools.has(tool.name)) {
      logger?.log('warn', {
        component: 'tools',
        event: 'tools.duplicateSkipped',
        message: `Tool '${tool.name}' already registered; skipping duplicate registration`,
        data: { toolName: tool.name },
      });
      continue;
    }
    try {
      const dispose = ctx.tools.register(tool);
      if (typeof dispose === 'function') {
        disposers.push(dispose);
      }
    } catch (err) {
      logger?.log('warn', {
        component: 'tools',
        event: 'tools.registerFailed',
        message: `Failed registering tool '${tool.name}': ${err instanceof Error ? err.message : String(err)}`,
        data: { toolName: tool.name },
      });
    }
  }
  return disposers;
}
