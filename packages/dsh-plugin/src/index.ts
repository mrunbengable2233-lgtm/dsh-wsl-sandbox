import { ApprovalBridge } from './approval-bridge.ts';
import { ConfigStore, type WslSandboxConfig } from './config-store.ts';
import type { DshCordisContext } from './cordis-types.ts';
import { registerWslPromptSection } from './prompt-injector.ts';
import { registerHostPwshGuardHook } from './pwsh-hook.ts';
import { registerWslSandboxTools, WslSandboxSessionManager } from './tools.ts';
import { registerWslSandboxWebApi } from './web-api.ts';

export const name = 'dsh-wsl-sandbox';

/**
 * Cordis optional injections — NEVER provides or overwrites stock DSH services
 * (`system-prompt`, `fs-local`, `subprocess-local`, `sandbox-local`, `pwsh-local`).
 */
export const inject = {
  optional: ['tools', 'systemPrompt', 'approval', 'http', 'logger'],
} as const;

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

/**
 * Cordis plugin entry point (`dsh-wsl-sandbox`).
 * Registers additive `wsl_*` tools, non-invasive `ctx.systemPrompt` routing section,
 * host PowerShell/CMD guard hook, `dsh-purge`-compatible approval bridge, and `/wsl-sandbox/api/*` routes.
 */
export function apply(
  ctx: DshCordisContext,
  options: WslSandboxPluginOptions = {},
): WslSandboxPluginHandle {
  const configStore = new ConfigStore({
    filePath: options.configPath,
    persistToDisk: options.persistConfig ?? true,
    initial: resolveInitialConfig(options),
  });

  const approvalBridge = new ApprovalBridge({
    getPolicyMode: () => configStore.get().approvalPolicyMode,
    ttlMs: configStore.get().approvalTimeoutMs,
    hostApproval: ctx.approval,
    bypassInstantThresholdMs: options.bypassInstantThresholdMs,
  });

  const sessionManager = new WslSandboxSessionManager({
    configStore,
    approvalBridge,
    sessionId: options.sessionId,
    allowLinuxDevMode: options.allowLinuxDevMode,
    onStderr: (line) => ctx.logger?.warn(`[dsh-wsl-runner] ${line}`),
  });

  const disposers: Array<() => void | Promise<void>> = [];

  const waterfallDispose = approvalBridge.attachCordisWaterfall(ctx);
  if (waterfallDispose) disposers.push(waterfallDispose);

  const promptDispose = registerWslPromptSection(ctx, () => configStore.get());
  if (promptDispose) disposers.push(promptDispose);

  const pwshDispose = registerHostPwshGuardHook(ctx, {
    getConfig: () => configStore.get(),
    getBinding: () => sessionManager.ensureBound(),
    approvalBridge,
  });
  if (pwshDispose) disposers.push(pwshDispose);

  disposers.push(...registerWslSandboxTools(ctx, sessionManager, configStore, approvalBridge));
  disposers.push(...registerWslSandboxWebApi(ctx, { configStore, sessionManager, approvalBridge }));

  const dispose = async (): Promise<void> => {
    for (const fn of disposers.splice(0)) {
      await fn();
    }
    await sessionManager.dispose();
  };

  ctx.effect?.(dispose);
  ctx.logger?.info(
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
export * from './approval-bridge.ts';
export * from './prompt-injector.ts';
export * from './pwsh-hook.ts';
export * from './tools.ts';
export * from './web-api.ts';
export * from './web-ui-entry.ts';
