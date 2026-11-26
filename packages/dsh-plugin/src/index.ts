import { ApprovalBridge } from './approval-bridge.ts';
import { ConfigStore, type WslSandboxConfig } from './config-store.ts';
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
  readonly initialConfig?: Partial<WslSandboxConfig>;
  readonly sessionId?: string;
  readonly allowLinuxDevMode?: boolean;
  readonly bypassInstantThresholdMs?: number;
  // Direct cordis.patch.yml config fields
  readonly enabled?: boolean;
  readonly defaultDistro?: string;
  readonly distro?: string;
  readonly workspaceRoot?: string;
  readonly environmentProfile?: WslSandboxConfig['environmentProfile'];
  readonly sandboxMode?: WslSandboxConfig['sandboxMode'];
  readonly approvalPolicyMode?: WslSandboxConfig['approvalPolicyMode'];
  readonly approvalTimeoutMs?: number;
  readonly networkMode?: WslSandboxConfig['networkMode'];
  readonly upstreamProxy?: string;
  readonly mirrorCn?: boolean;
  readonly cacheMode?: WslSandboxConfig['cacheMode'];
  readonly injectSystemPromptSection?: boolean;
  readonly enableHostPwshGuard?: boolean;
  readonly advanced?: Partial<WslSandboxConfig['advanced']>;
}

export interface WslSandboxPluginHandle {
  readonly configStore: ConfigStore;
  readonly approvalBridge: ApprovalBridge;
  readonly sessionManager: WslSandboxSessionManager;
  readonly dispose: () => Promise<void>;
}

function resolveInitialConfig(options: WslSandboxPluginOptions): Partial<WslSandboxConfig> {
  const fromYaml: Partial<WslSandboxConfig> = {};
  const mutable = fromYaml as Record<string, unknown>;
  if (options.enabled !== undefined) mutable.enabled = options.enabled;
  if (options.distro ?? options.defaultDistro) mutable.distro = options.distro ?? options.defaultDistro;
  if (options.workspaceRoot !== undefined) mutable.workspaceRoot = options.workspaceRoot;
  if (options.environmentProfile !== undefined) mutable.environmentProfile = options.environmentProfile;
  if (options.sandboxMode !== undefined) mutable.sandboxMode = options.sandboxMode;
  if (options.approvalPolicyMode !== undefined) mutable.approvalPolicyMode = options.approvalPolicyMode;
  if (options.approvalTimeoutMs !== undefined) mutable.approvalTimeoutMs = options.approvalTimeoutMs;
  if (options.networkMode !== undefined) mutable.networkMode = options.networkMode;
  if (options.upstreamProxy !== undefined) mutable.upstreamProxy = options.upstreamProxy;
  if (options.mirrorCn !== undefined) mutable.mirrorCn = options.mirrorCn;
  if (options.cacheMode !== undefined) mutable.cacheMode = options.cacheMode;
  if (options.injectSystemPromptSection !== undefined) {
    mutable.enablePromptInjection = options.injectSystemPromptSection;
  }
  if (options.enableHostPwshGuard !== undefined) {
    mutable.enablePwshGuard = options.enableHostPwshGuard;
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
  // Real `@deepseek-ai/cordis` (`@cordisjs/core` v4) invokes `ctx.effect((ctx) => disposer)` immediately
  // during plugin mount to obtain the disposer! Lightweight mocks in tests may push `fn` directly.
  // Detect real Cordis fiber presence (`'fiber' in ctx` or `typeof ctx.inject === 'function'`) vs bare mock:
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
  const configStore = new ConfigStore({
    filePath: options.configPath,
    persistToDisk: options.persistConfig ?? true,
    initial: resolveInitialConfig(options),
  });

  const logger = getOptionalService(ctx, 'logger');
  const approvalBridge = new ApprovalBridge({
    getPolicyMode: () => configStore.get().approvalPolicyMode,
    ttlMs: configStore.get().approvalTimeoutMs,
    hostApproval: getOptionalService(ctx, 'approval'),
    bypassInstantThresholdMs: options.bypassInstantThresholdMs,
  });

  const sessionManager = new WslSandboxSessionManager({
    configStore,
    approvalBridge,
    sessionId: options.sessionId,
    allowLinuxDevMode: options.allowLinuxDevMode,
    onStderr: (line) => logger?.warn(`[dsh-wsl-runner] ${line}`),
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
      });
      registerSafeEffect(webCtx, () => {
        for (const fn of webDisposers.splice(0)) fn();
      });
    });
    if (getOptionalService(ctx, 'http')) {
      disposers.push(...registerWslSandboxWebApi(ctx, { configStore, sessionManager, approvalBridge }));
    }
  } else {
    disposers.push(...registerWslSandboxWebApi(ctx, { configStore, sessionManager, approvalBridge }));
  }

  const dispose = async (): Promise<void> => {
    for (const fn of disposers.splice(0)) {
      await fn();
    }
    await sessionManager.dispose();
  };

  registerSafeEffect(ctx, dispose);
  logger?.info(
    `[dsh-wsl-sandbox] loaded (distro=${configStore.get().distro}, approval=${configStore.get().approvalPolicyMode}, network=${configStore.get().networkMode})`,
  );

  return {
    configStore,
    approvalBridge,
    sessionManager,
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
