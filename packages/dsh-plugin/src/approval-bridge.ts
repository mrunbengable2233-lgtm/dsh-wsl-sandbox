import { performance } from 'node:perf_hooks';
import {
  type ApprovalAction,
  type ApprovalAuditRecord,
  ApprovalController,
  type ApprovalDecisionKind,
  type ApprovalDecisionResponse,
  type ApprovalPolicyMode,
  type ApprovalRequestEnvelope,
  type ApprovedExecutionTicket,
  failSandbox,
  type SessionBinding,
  type StructuredLogger,
} from '../../core/src/index.ts';
import type { ConfigStore } from './config-store.ts';
import type { DshApprovalService, DshCordisContext } from './cordis-types.ts';

export interface PendingQueueItem {
  readonly requestId: string;
  readonly actionHash: string;
  readonly kind: ApprovalAction['kind'];
  readonly summary: string;
  readonly command?: string;
  readonly reasons: readonly string[];
  readonly touchesPhysicalDevice: boolean;
  readonly allowSessionRuleOption: boolean;
  readonly suggestedPrefix?: readonly string[];
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
  readonly distribution: string;
  readonly workspaceRoot: string;
  readonly routedViaFallback: boolean;
}

interface WaitingDecision {
  readonly item: PendingQueueItem;
  readonly resolve: (resp: ApprovalDecisionResponse) => void;
  readonly reject: (err: Error) => void;
}

export interface ApprovalBridgeOptions {
  readonly getPolicyMode?: () => ApprovalPolicyMode;
  readonly configStore?: ConfigStore;
  readonly ttlMs?: number;
  readonly hostApproval?: DshApprovalService;
  readonly logger?: StructuredLogger;
  /** Minimum elapsed ms to treat a host approval without `humanVerified` as genuine interactive review. */
  readonly bypassInstantThresholdMs?: number;
  readonly onPendingAdded?: (item: PendingQueueItem) => void;
  readonly onPendingResolved?: (requestId: string, decision: ApprovalDecisionKind | 'aborted') => void;
  readonly onAudit?: (record: ApprovalAuditRecord) => void;
}

export interface BridgeRequestOptions {
  /** If true, bypassed host auto-approvals (e.g. `dsh-purge` `hooksDenyBypass`) are caught and routed to our independent queue. */
  readonly requireIndependentFallback?: boolean;
  /** If true, this command is strictly in-workspace and non-hardware (eligible for `trust-workspace` auto-pass). */
  readonly eligibleForTrustWorkspace?: boolean;
  readonly agent?: unknown;
  readonly toolName?: string;
  readonly callId?: string;
  readonly callerSignal?: AbortSignal;
}

/**
 * Bridges `ApprovalController` with DSH's host `ctx.approval` service while guaranteeing
 * 100% coexistence with `dsh-purge` (`hooksDenyBypass: true`) and unconditional manual
 * `allow-once` enforcement for physical devices (Q4=A, Q9=A, Q13=A).
 */
export class ApprovalBridge {
  private readonly controller: ApprovalController;
  private readonly getPolicyMode: () => ApprovalPolicyMode;
  private hostApproval?: DshApprovalService;
  private readonly logger?: StructuredLogger;
  private readonly bypassInstantThresholdMs: number;
  private readonly onPendingAdded?: (item: PendingQueueItem) => void;
  private readonly onPendingResolved?: (requestId: string, decision: ApprovalDecisionKind | 'aborted') => void;

  private readonly queue = new Map<string, WaitingDecision>();
  private readonly requestMeta = new Map<string, BridgeRequestOptions>();

  constructor(options: ApprovalBridgeOptions) {
    this.getPolicyMode =
      options.getPolicyMode ??
      (options.configStore ? () => options.configStore!.get().approvalPolicyMode : () => 'balanced');
    this.hostApproval = options.hostApproval;
    this.logger = options.logger;
    this.bypassInstantThresholdMs = options.bypassInstantThresholdMs ?? 15;
    this.onPendingAdded = options.onPendingAdded;
    this.onPendingResolved = options.onPendingResolved;

    this.controller = new ApprovalController({
      ttlMs: options.ttlMs ?? options.configStore?.get().approvalTimeoutMs ?? 60_000,
      onAudit: (rec) => {
        options.onAudit?.(rec);
        const outcome = String(rec.outcome ?? 'unknown');
        this.logger?.log(outcome.startsWith('allowed') ? 'info' : 'warn', {
          component: 'approval',
          event: 'approval.audit',
          message: `Approval ${outcome} for ${rec.kind}: ${rec.summary}`,
          data: {
            requestId: rec.requestId,
            kind: rec.kind,
            outcome,
          },
        });
      },
      reviewer: (envelope) => this.reviewEnvelope(envelope),
    });
  }

  setHostApproval(service: DshApprovalService | undefined): void {
    this.hostApproval = service;
  }

  /**
   * Register a polite `approval/request` waterfall listener on Cordis context:
   * passes every non-`dsh-wsl-sandbox` request untouched via `return next()`.
   */
  attachCordisWaterfall(ctx: DshCordisContext): (() => void) | undefined {
    if (!ctx.waterfall) return undefined;
    const dispose = ctx.waterfall<{ source?: string }, unknown>('approval/request', async (req, next) => {
      if (req?.source !== 'dsh-wsl-sandbox') {
        return typeof next === 'function' ? next() : undefined;
      }
      return typeof next === 'function' ? next() : undefined;
    });
    return typeof dispose === 'function' ? () => void dispose() : undefined;
  }

  setBinding(binding: SessionBinding): void {
    this.controller.bind(binding);
  }

  invalidate(reason?: string): number {
    for (const [id, waiting] of this.queue) {
      this.queue.delete(id);
      this.onPendingResolved?.(id, 'aborted');
      waiting.reject(new Error(reason ?? 'Approval invalidated'));
    }
    return this.controller.invalidate();
  }

  listPending(): PendingQueueItem[] {
    return Array.from(this.queue.values()).map((w) => w.item);
  }

  getAuditLog(): readonly ApprovalAuditRecord[] {
    return this.controller.getAuditLog();
  }

  getSessionRules(): readonly string[][] {
    return this.controller.getSessionRules();
  }

  clearSessionRules(): void {
    this.controller.clearSessionRules();
  }

  decidePending(
    requestId: string,
    decision: ApprovalDecisionKind,
    options?: { guidance?: string; sessionPrefix?: readonly string[] },
  ): boolean {
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

  async requestApproval<TAction extends ApprovalAction>(
    binding: SessionBinding,
    action: TAction,
    opts?: BridgeRequestOptions,
  ): Promise<ApprovedExecutionTicket<TAction>> {
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

  private async reviewEnvelope(envelope: ApprovalRequestEnvelope): Promise<ApprovalDecisionResponse> {
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
        const decisionFromStr: ApprovalDecisionKind =
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

      const normalizedDecision: ApprovalDecisionKind =
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

  private enqueueIndependent(
    envelope: ApprovalRequestEnvelope,
    routedViaFallback: boolean,
  ): Promise<ApprovalDecisionResponse> {
    return new Promise<ApprovalDecisionResponse>((resolve, reject) => {
      if (envelope.signal.aborted) {
        reject(new Error('Approval request aborted'));
        return;
      }

      const item: PendingQueueItem = {
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

      const onAbort = (): void => {
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

      this.logger?.log(routedViaFallback ? 'warn' : 'info', {
        component: 'approval',
        event: routedViaFallback ? 'approval.bypassCaught' : 'approval.queued',
        message: routedViaFallback
          ? `Caught unverified/bypassed host approval; routed '${item.summary}' to independent human queue`
          : `Queued '${item.summary}' for human approval`,
        sessionId: envelope.binding.sessionId,
        data: {
          requestId: item.requestId,
          kind: item.kind,
          touchesPhysicalDevice: item.touchesPhysicalDevice,
          routedViaFallback,
        },
      });
      this.onPendingAdded?.(item);
    });
  }
}
