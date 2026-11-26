import path from 'node:path';
import {
  type LogLevel,
  resolveSharedHostNodeRuntime,
  RotatingNdjsonSink,
  StructuredLogger,
} from '../../core/src/index.ts';
import { ApprovalBridge } from './approval-bridge.ts';
import { ConfigStore, hardenPrivatePath, type WslSandboxConfig } from './config-store.ts';
import { type DshCordisContext, getOptionalService } from './cordis-types.ts';
import { registerWslPromptSection } from './prompt-injector.ts';
import { registerHostPwshGuardHook } from './pwsh-hook.ts';
import { registerWslSandboxTools, WslSandboxSessionManager } from './tools.ts';
import { registerWslSandboxWebApi } from './web-api.ts';

export const name = 'dsh-wsl-sandbox';

/**
 * Cordis injection list MUST be a string array (`[]`), NEVER an object (`{ optional: [...] }`)!
 * Optional/surface-specific services (`tools`, `systemPrompt`, `approval`, `webServer`) are
 * bound both directly (when already present) and reactively via `ctx.inject([...], ...)` so
 * headless, TUI, Desktop, and Web profiles all boot cleanly without ever parking on missing services.
 */
export const inject: string[] = [];

export interface WslSandboxPluginOptions {
  readonly configPath?: string;
  readonly persistConfig?: boolean;
  /** Optional override for disk log persistence (`false` keeps logs in RAM only; defaults to `persistConfig ?? true`). */
  readonly persistLogs?: boolean;
  /** Custom flush interval for SSD-friendly batched disk writes (default: 2500ms). */
  readonly logFlushIntervalMs?: number;
  readonly initialConfig?: Partial<WslSandboxConfig>;
  readonly sessionId?: string;
  readonly allowLinuxDevMode?: boolean;
  readonly bypassInstantThresholdMs?: number;
  // Direct cordis.patch.yml config fields
  readonly enabled?: boolean;
  readonly defaultDistro?: string;
  readonly distro?: string;
  readonly workspaceRoot?: string;
  readonly wslNodePath?: string;
  readonly environmentProfile?: WslSandboxConfig['environmentProfile'];
  readonly sandboxMode?: WslSandboxConfig['sandboxMode'];
  readonly approvalPolicyMode?: WslSandboxConfig['approvalPolicyMode'];
  readonly approvalTimeoutMs?: number;
  readonly networkMode?: WslSandboxConfig['networkMode'];
  readonly upstreamProxy?: string;
  readonly mirrorCn?: boolean;
  readonly cacheMode?: WslSandboxConfig['cacheMode'];
  readonly logLevel?: LogLevel;
  readonly injectSystemPromptSection?: boolean;
  readonly enableHostPwshGuard?: boolean;
  readonly advanced?: Partial<WslSandboxConfig['advanced']>;
}

export interface WslSandboxPluginHandle {
  readonly configStore: ConfigStore;
  readonly approvalBridge: ApprovalBridge;
  readonly sessionManager: WslSandboxSessionManager;
  readonly logger: StructuredLogger;
  readonly dispose: () => Promise<void>;
}

function resolveInitialConfig(options: WslSandboxPluginOptions): Partial<WslSandboxConfig> {
  const fromYaml: Partial<WslSandboxConfig> = {};
  const mutable = fromYaml as Record<string, unknown>;
  if (options.enabled !== undefined) mutable.enabled = options.enabled;
  if (options.distro ?? options.defaultDistro) mutable.distro = options.distro ?? options.defaultDistro;
  if (options.workspaceRoot !== undefined) mutable.workspaceRoot = options.workspaceRoot;
  if (options.wslNodePath !== undefined) mutable.wslNodePath = options.wslNodePath;
  if (options.environmentProfile !== undefined) mutable.environmentProfile = options.environmentProfile;
  if (options.sandboxMode !== undefined) mutable.sandboxMode = options.sandboxMode;
  if (options.approvalPolicyMode !== undefined) mutable.approvalPolicyMode = options.approvalPolicyMode;
  if (options.approvalTimeoutMs !== undefined) mutable.approvalTimeoutMs = options.approvalTimeoutMs;
  if (options.networkMode !== undefined) mutable.networkMode = options.networkMode;
  if (options.upstreamProxy !== undefined) mutable.upstreamProxy = options.upstreamProxy;
  if (options.mirrorCn !== undefined) mutable.mirrorCn = options.mirrorCn;
  if (options.cacheMode !== undefined) mutable.cacheMode = options.cacheMode;
  if (options.logLevel !== undefined) mutable.logLevel = options.logLevel;
  if (options.injectSystemPromptSection !== undefined) {
    mutable.enablePromptInjection = options.injectSystemPromptSection;
  }
  if (options.enableHostPwshGuard !== undefined) {
    mutable.enablePwshGuard = options.enablePwshGuard;
  }
  if (options.advanced !== undefined) {
    mutable.advanced = {
      shares: options.advanced.shares ?? [],
      deviceNodes: options.advanced.deviceNodes ?? [],
      localLabCidrs: options.advanced.localLabCidrs ?? [],
      localLabPorts: options.advanced.localLabPorts ?? [],
      customAllowedDomains: options.advanced.customAllowedDomains ?? [],
    };
  }
  return { ...fromYaml, ...(options.initialConfig ?? {}) };
}

function registerSafeEffect(ctx: DshCordisContext, cleanup: () => void | Promise<void>): void {
  if (typeof ctx.effect !== 'function') return;
  if ('fiber' in (ctx as object) || typeof ctx.inject === 'function') {
    ctx.effect(() => () => {
      void cleanup();
    });
  } else {
    ctx.effect(cleanup);
  }
}

export function apply(
  ctx: DshCordisContext,
  options: WslSandboxPluginOptions = {},
): WslSandboxPluginHandle {
  const persistConfig = options.persistConfig ?? true;
  const configStore = new ConfigStore({
    filePath: options.configPath,
    persistToDisk: persistConfig,
    initial: resolveInitialConfig(options),
  });

  const hostLoggerService = getOptionalService(ctx, 'logger');
  const persistLogs = options.persistLogs ?? persistConfig;
  const logSink = persistLogs
    ? new RotatingNdjsonSink({
        logDir: path.join(configStore.getConfigDir(), 'logs'),
        fileName: 'host.ndjson',
        maxBytes: 5 * 1024 * 1024,
        maxFiles: 3,
        flushIntervalMs: options.logFlushIntervalMs ?? 2500,
        hardenPath: (target, kind) => hardenPrivatePath(target, kind),
      })
    : undefined;

  const logger = new StructuredLogger({
    source: 'host',
    level: configStore.get().logLevel,
    fileSink: logSink,
    preloadFromDisk: persistLogs,
    onEntry: (entry) => {
      if (!hostLoggerService) return;
      if (entry.level === 'error') {
        hostLoggerService.error(`[dsh-wsl-sandbox][${entry.component}] ${entry.message}`);
      } else if (entry.level === 'warn') {
        hostLoggerService.warn(`[dsh-wsl-sandbox][${entry.component}] ${entry.message}`);
      }
    },
  });

  const approvalBridge = new ApprovalBridge({
    getPolicyMode: () => configStore.get().approvalPolicyMode,
    ttlMs: configStore.get().approvalTimeoutMs,
    hostApproval: getOptionalService(ctx, 'approval'),
    logger,
    bypassInstantThresholdMs: options.bypassInstantThresholdMs,
  });

  const sessionManager = new WslSandboxSessionManager({
    configStore,
    approvalBridge,
    sessionId: options.sessionId,
    allowLinuxDevMode: options.allowLinuxDevMode,
    logger,
    onStderr: (line) => hostLoggerService?.warn(`[dsh-wsl-runner] ${line}`),
  });

  const disposers: Array<() => void | Promise<void>> = [];

  const waterfallDispose = approvalBridge.attachCordisWaterfall(ctx);
  if (waterfallDispose) disposers.push(waterfallDispose);

  const isRealCordis = typeof ctx.inject === 'function';

  // 1. Tools + Host Shell Guard
  if (isRealCordis) {
    ctx.inject!(['tools'], (toolCtx) => {
      const toolDisposers = registerWslSandboxTools(toolCtx, sessionManager, configStore, approvalBridge);
      const pwshDispose = registerHostPwshGuardHook(toolCtx, {
        getConfig: () => configStore.get(),
        getBinding: () => sessionManager.ensureBound(),
        approvalBridge,
        logger,
      });
      registerSafeEffect(toolCtx, () => {
        for (const fn of toolDisposers.splice(0)) fn();
        pwshDispose?.();
      });
    });
  } else {
    const pwshDispose = registerHostPwshGuardHook(ctx, {
      getConfig: () => configStore.get(),
      getBinding: () => sessionManager.ensureBound(),
      approvalBridge,
      logger,
    });
    if (pwshDispose) disposers.push(pwshDispose);
    disposers.push(...registerWslSandboxTools(ctx, sessionManager, configStore, approvalBridge));
  }

  // 2. SystemPrompt Routing Section (order: 4200, interpolate: false)
  if (isRealCordis) {
    ctx.inject!(['systemPrompt'], (spCtx) => {
      const promptDispose = registerWslPromptSection(spCtx, () => configStore.get());
      registerSafeEffect(spCtx, () => promptDispose?.());
    });
  } else {
    const promptDispose = registerWslPromptSection(ctx, () => configStore.get());
    if (promptDispose) disposers.push(promptDispose);
  }

  // 3. Optional Host Approval Service (`@deepseek-ai/dsh-user-approval`)
  if (isRealCordis) {
    ctx.inject!(['approval'], (apCtx) => {
      approvalBridge.setHostApproval(apCtx.approval);
      registerSafeEffect(apCtx, () => approvalBridge.setHostApproval(undefined));
    });
  }

  // 4. Web UI & Control API (`ctx.webServer` on real DSH Web, `ctx.http` on standalone harnesses)
  if (isRealCordis) {
    ctx.inject!(['webServer'], (webCtx) => {
      const webDisposers = registerWslSandboxWebApi(webCtx, {
        configStore,
        sessionManager,
        approvalBridge,
        logger,
      });
      registerSafeEffect(webCtx, () => {
        for (const fn of webDisposers.splice(0)) fn();
      });
    });
    if (getOptionalService(ctx, 'http')) {
      disposers.push(...registerWslSandboxWebApi(ctx, { configStore, sessionManager, approvalBridge, logger }));
    }
  } else {
    disposers.push(...registerWslSandboxWebApi(ctx, { configStore, sessionManager, approvalBridge, logger }));
  }

  const dispose = async (): Promise<void> => {
    for (const fn of disposers.splice(0)) {
      await fn();
    }
    await sessionManager.dispose();
    logger.log('info', {
      component: 'plugin',
      event: 'plugin.disposed',
      message: 'dsh-wsl-sandbox unloaded cleanly (zero residual runners or open file handles)',
    });
    logger.dispose();
  };

  registerSafeEffect(ctx, dispose);

  const hostRuntime = resolveSharedHostNodeRuntime();
  const cfg = configStore.get();
  logger.log('info', {
    component: 'plugin',
    event: 'plugin.loaded',
    message: `Loaded dsh-wsl-sandbox (distro=${cfg.distro}, profile=${cfg.environmentProfile}, hostNode=${hostRuntime.nodeVersion} sharedWithDsh=${hostRuntime.sharedWithHostProcess})`,
    data: {
      distro: cfg.distro,
      environmentProfile: cfg.environmentProfile,
      approvalPolicyMode: cfg.approvalPolicyMode,
      networkMode: cfg.networkMode,
      hostNodeVersion: hostRuntime.nodeVersion,
      hostSharedWithDsh: hostRuntime.sharedWithHostProcess,
      isElectronCarrier: hostRuntime.isElectronCarrier,
      logFilePath: logger.getLogFilePath() ?? null,
    },
  });
  hostLoggerService?.info(
    `[dsh-wsl-sandbox] loaded (distro=${cfg.distro}, approval=${cfg.approvalPolicyMode}, network=${cfg.networkMode}, hostNode=${hostRuntime.nodeVersion})`,
  );

  return {
    configStore,
    approvalBridge,
    sessionManager,
    logger,
    dispose,
  };
}

export * from './cordis-types.ts';
export * from './config-store.ts';
export * from './wsl-transport.ts';
export * from './wsl-discovery.ts';
export * from './approval-bridge.ts';
export * from './prompt-injector.ts';
export * from './pwsh-hook.ts';
export * from './tools.ts';
export * from './web-api.ts';
export * from './web-ui-entry.ts';
