import { performance } from 'node:perf_hooks';
import {
                      
                           
  ApprovalController,
                            
                                
                          
                               
                               
  failSandbox,
                      
} from '../../core/src/index.js';
                                                                              

                                   
                             
                              
                                        
                           
                            
                                      
                                          
                                           
                                               
                               
                               
                                
                                 
                                      
 

                           
                                  
                                                             
                                        
 

                                        
                                                   
                          
                                             
                                                                                                           
                                             
                                                             
                                                                                                       
                                                           
 

                                       
                                                                                                                                   
                                                
                                                                                                                    
                                               
                           
                             
                           
                                      
 

/**
 * Bridges `ApprovalController` with DSH's host `ctx.approval` service while guaranteeing
 * 100% coexistence with `dsh-purge` (`hooksDenyBypass: true`) and unconditional manual
 * `allow-once` enforcement for physical devices (Q4=A, Q9=A, Q13=A).
 */
export class ApprovalBridge {
                   controller                    ;
                   getPolicyMode                          ;
          hostApproval                     ;
                   bypassInstantThresholdMs        ;
                   onPendingAdded                                   ;
                   onPendingResolved                                                                          ;

                   queue = new Map                         ();
                   requestMeta = new Map                              ();

  constructor(options                       ) {
    this.getPolicyMode = options.getPolicyMode;
    this.hostApproval = options.hostApproval;
    this.bypassInstantThresholdMs = options.bypassInstantThresholdMs ?? 15;
    this.onPendingAdded = options.onPendingAdded;
    this.onPendingResolved = options.onPendingResolved;

    this.controller = new ApprovalController({
      ttlMs: options.ttlMs ?? 60_000,
      onAudit: options.onAudit,
      reviewer: (envelope) => this.reviewEnvelope(envelope),
    });
  }

  setHostApproval(service                                )       {
    this.hostApproval = service;
  }

  /**
   * Register a polite `approval/request` waterfall listener on Cordis context:
   * passes every non-`dsh-wsl-sandbox` request untouched via `return next()`.
   */
  attachCordisWaterfall(ctx                  )                           {
    if (!ctx.waterfall) return undefined;
    const dispose = ctx.waterfall                              ('approval/request', async (req, next) => {
      if (req?.source !== 'dsh-wsl-sandbox') {
        return typeof next === 'function' ? next() : undefined;
      }
      return typeof next === 'function' ? next() : undefined;
    });
    return typeof dispose === 'function' ? () => void dispose() : undefined;
  }

  setBinding(binding                )       {
    this.controller.bind(binding);
  }

  invalidate(reason         )         {
    for (const [id, waiting] of this.queue) {
      this.queue.delete(id);
      this.onPendingResolved?.(id, 'aborted');
      waiting.reject(new Error(reason ?? 'Approval invalidated'));
    }
    return this.controller.invalidate();
  }

  listPending()                     {
    return Array.from(this.queue.values()).map((w) => w.item);
  }

  getAuditLog()                                 {
    return this.controller.getAuditLog();
  }

  getSessionRules()                      {
    return this.controller.getSessionRules();
  }

  clearSessionRules()       {
    this.controller.clearSessionRules();
  }

  decidePending(
    requestId        ,
    decision                      ,
    options                                                           ,
  )          {
    const waiting = this.queue.get(requestId);
    if (!waiting) return false;
    this.queue.delete(requestId);
    this.onPendingResolved?.(requestId, decision);
    waiting.resolve({
      requestId,
      actionHash: waiting.item.actionHash,
      decision,
      guidance: options?.guidance,
      sessionPrefix: options?.sessionPrefix,
    });
    return true;
  }

  async requestApproval                                (
    binding                ,
    action         ,
    opts                       ,
  )                                            {
    const mode = this.getPolicyMode();
    const isHighRiskBypassProtected =
      opts?.requireIndependentFallback ??
      (action.touchesPhysicalDevice ||
        action.kind === 'physical-device' ||
        action.kind === 'sandbox-escalation' ||
        action.kind === 'external-path' ||
        action.kind === 'network-access' ||
        action.kind === 'host-pwsh-command');

    if (
      mode === 'trust-workspace' &&
      opts?.eligibleForTrustWorkspace &&
      !action.touchesPhysicalDevice &&
      !isHighRiskBypassProtected
    ) {
      let consumed = false;
      return {
        requestId: `trust-ws-${Date.now()}`,
        actionHash: 'trust-workspace',
        binding,
        action,
        assertCurrent: () => {
          if (consumed) failSandbox('GRANT_CONSUMED', 'Approval ticket already consumed');
        },
        consume: () => {
          if (consumed) failSandbox('GRANT_CONSUMED', 'Approval ticket already consumed');
          consumed = true;
        },
      };
    }

    if (this.controller.getBinding() !== binding) {
      this.controller.bind(binding);
    }

    const metaKey = `${binding.generation}:${action.kind}:${action.summary}:${action.command ?? ''}`;
    this.requestMeta.set(metaKey, {
      requireIndependentFallback: isHighRiskBypassProtected,
      eligibleForTrustWorkspace: opts?.eligibleForTrustWorkspace,
      agent: opts?.agent,
      toolName: opts?.toolName,
      callId: opts?.callId,
    });

    try {
      return await this.controller.authorize(action, opts?.callerSignal);
    } finally {
      this.requestMeta.delete(metaKey);
    }
  }

          async reviewEnvelope(envelope                         )                                    {
    const mode = this.getPolicyMode();
    const metaKey = `${envelope.binding.generation}:${envelope.action.kind}:${envelope.action.summary}:${envelope.action.command ?? ''}`;
    const meta = this.requestMeta.get(metaKey);
    const requiresFallback = Boolean(
      meta?.requireIndependentFallback ||
        envelope.action.touchesPhysicalDevice ||
        envelope.action.kind === 'physical-device' ||
        envelope.action.kind === 'host-pwsh-command' ||
        envelope.action.kind === 'sandbox-escalation' ||
        envelope.action.kind === 'external-path' ||
        envelope.action.kind === 'network-access',
    );

    if (mode === 'strict' || !this.hostApproval) {
      return this.enqueueIndependent(envelope, false);
    }

    const startedMs = performance.now();
    try {
      const hostResRaw = await this.hostApproval.request({
        source: 'dsh-wsl-sandbox',
        requestId: envelope.requestId,
        kind: envelope.action.kind,
        summary: envelope.action.summary,
        command: envelope.action.command,
        reasons: envelope.action.reasons,
        touchesPhysicalDevice: envelope.action.touchesPhysicalDevice,
        allowSessionRule: envelope.allowSessionRuleOption,
        ...(meta?.agent !== undefined ? { agent: meta.agent } : {}),
        toolName: meta?.toolName ?? `wsl_sandbox:${envelope.action.kind}`,
        ...(meta?.callId !== undefined ? { callId: meta.callId } : {}),
        reason: `${envelope.action.summary}${envelope.action.command ? ` — ${envelope.action.command}` : ''}`,
        signal: envelope.signal,
      });

      const elapsedMs = performance.now() - startedMs;

      // Real `@deepseek-ai/dsh-user-approval` returns string outcomes
      if (typeof hostResRaw === 'string') {
        if (hostResRaw === 'unavailable') {
          return this.enqueueIndependent(envelope, true);
        }
        const decisionFromStr                       =
          hostResRaw === 'allowed-once' ? 'allow-once' : 'deny';
        if (
          decisionFromStr === 'allow-once' &&
          elapsedMs < this.bypassInstantThresholdMs &&
          requiresFallback
        ) {
          return this.enqueueIndependent(envelope, true);
        }
        return {
          requestId: envelope.requestId,
          actionHash: envelope.actionHash,
          decision: decisionFromStr,
        };
      }

      const hostRes = hostResRaw;
      const isSyntheticBypass =
        Boolean(hostRes.bypassed || hostRes.hooksDenyBypass) ||
        (hostRes.source === 'dsh-purge' && !hostRes.humanVerified) ||
        (!hostRes.humanVerified &&
          (hostRes.decision === 'allow-once' || hostRes.decision === 'allow-session-rule') &&
          elapsedMs < this.bypassInstantThresholdMs);

      if (isSyntheticBypass && requiresFallback) {
        return this.enqueueIndependent(envelope, true);
      }

      const normalizedDecision                       =
        envelope.action.touchesPhysicalDevice && hostRes.decision === 'allow-session-rule'
          ? 'allow-once'
          : hostRes.decision;

      return {
        requestId: envelope.requestId,
        actionHash: envelope.actionHash,
        decision: normalizedDecision,
        guidance: hostRes.guidance,
        sessionPrefix: normalizedDecision === 'allow-session-rule' ? hostRes.sessionPrefix : undefined,
      };
    } catch {
      return this.enqueueIndependent(envelope, true);
    }
  }

          enqueueIndependent(
    envelope                         ,
    routedViaFallback         ,
  )                                    {
    return new Promise                          ((resolve, reject) => {
      if (envelope.signal.aborted) {
        reject(new Error('Approval request aborted'));
        return;
      }

      const item                   = {
        requestId: envelope.requestId,
        actionHash: envelope.actionHash,
        kind: envelope.action.kind,
        summary: envelope.action.summary,
        command: envelope.action.command,
        reasons: envelope.action.reasons,
        touchesPhysicalDevice: envelope.action.touchesPhysicalDevice,
        allowSessionRuleOption: envelope.allowSessionRuleOption,
        suggestedPrefix: envelope.action.suggestedPrefix,
        createdAtMs: envelope.createdAtMs,
        expiresAtMs: envelope.expiresAtMs,
        distribution: envelope.binding.distribution,
        workspaceRoot: envelope.binding.workspaceRoot,
        routedViaFallback,
      };

      const onAbort = ()       => {
        if (this.queue.delete(envelope.requestId)) {
          this.onPendingResolved?.(envelope.requestId, 'aborted');
          reject(new Error('Approval request timed out or aborted'));
        }
      };

      envelope.signal.addEventListener('abort', onAbort, { once: true });

      this.queue.set(envelope.requestId, {
        item,
        resolve: (resp) => {
          envelope.signal.removeEventListener('abort', onAbort);
          resolve(resp);
        },
        reject: (err) => {
          envelope.signal.removeEventListener('abort', onAbort);
          reject(err);
        },
      });

      this.onPendingAdded?.(item);
    });
  }
}
