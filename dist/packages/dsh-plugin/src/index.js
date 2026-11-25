import { ApprovalBridge } from './approval-bridge.js';
import { ConfigStore,                       } from './config-store.js';
import {                        getOptionalService } from './cordis-types.js';
import { registerWslPromptSection } from './prompt-injector.js';
import { registerHostPwshGuardHook } from './pwsh-hook.js';
import { registerWslSandboxTools, WslSandboxSessionManager } from './tools.js';
import { registerWslSandboxWebApi } from './web-api.js';

export const name = 'dsh-wsl-sandbox';

/**
 * Cordis injection list MUST be a string array (`[]`), NEVER an object (`{ optional: [...] }`)!
 * Optional/surface-specific services (`tools`, `systemPrompt`, `approval`, `webServer`) are
 * bound both directly (when already present) and reactively via `ctx.inject([...], ...)` so
 * headless, TUI, Desktop, and Web profiles all boot cleanly without ever parking on missing services.
 */
export const inject           = [];

                                          
                               
                                   
                                                     
                              
                                       
                                             
                                          
                             
                                  
                           
                                  
                                                         
                                                                       
                                      
                                                         
                                  
                              
                                                     
                                               
                                         
                                                            
 

                                         
                                    
                                          
                                                    
                                        
 

function resolveInitialConfig(options                         )                            {
  const fromYaml                            = {};
  const mutable = fromYaml                           ;
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

function registerSafeEffect(ctx                  , cleanup                            )       {
  if (typeof ctx.effect !== 'function') return;
  // Real `@deepseek-ai/cordis` (`@cordisjs/core` v4) invokes `ctx.effect((ctx) => disposer)` immediately
  // during plugin mount to obtain the disposer! Lightweight mocks in tests may push `fn` directly.
  // Detect real Cordis fiber presence (`'fiber' in ctx` or `typeof ctx.inject === 'function'`) vs bare mock:
  if ('fiber' in (ctx          ) || typeof ctx.inject === 'function') {
    ctx.effect(() => () => {
      void cleanup();
    });
  } else {
    ctx.effect(cleanup);
  }
}

export function apply(
  ctx                  ,
  options                          = {},
)                         {
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

  const disposers                                    = [];

  const waterfallDispose = approvalBridge.attachCordisWaterfall(ctx);
  if (waterfallDispose) disposers.push(waterfallDispose);

  const isRealCordis = typeof ctx.inject === 'function';

  // 1. Tools + Host Shell Guard
  if (isRealCordis) {
    ctx.inject (['tools'], (toolCtx) => {
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
    ctx.inject (['systemPrompt'], (spCtx) => {
      const promptDispose = registerWslPromptSection(spCtx, () => configStore.get());
      registerSafeEffect(spCtx, () => promptDispose?.());
    });
  } else {
    const promptDispose = registerWslPromptSection(ctx, () => configStore.get());
    if (promptDispose) disposers.push(promptDispose);
  }

  // 3. Optional Host Approval Service (`@deepseek-ai/dsh-user-approval`)
  if (isRealCordis) {
    ctx.inject (['approval'], (apCtx) => {
      approvalBridge.setHostApproval(apCtx.approval);
      registerSafeEffect(apCtx, () => approvalBridge.setHostApproval(undefined));
    });
  }

  // 4. Web UI & Control API (`ctx.webServer` on real DSH Web, `ctx.http` on standalone harnesses)
  if (isRealCordis) {
    ctx.inject (['webServer'], (webCtx) => {
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

  const dispose = async ()                => {
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

export * from './cordis-types.js';
export * from './config-store.js';
export * from './wsl-transport.js';
export * from './approval-bridge.js';
export * from './prompt-injector.js';
export * from './pwsh-hook.js';
export * from './tools.js';
export * from './web-api.js';
export * from './web-ui-entry.js';
