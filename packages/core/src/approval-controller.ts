import { createHash, randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { isBannedPrefix } from './bash-ast-guard.ts';
import type { SessionBinding } from './binding.ts';
import { failSandbox } from './errors.ts';

export type ApprovalActionKind =
  | 'dangerous-command'
  | 'sandbox-escalation'
  | 'network-access'
  | 'external-path'
  | 'physical-device'
  | 'host-pwsh-command';

export type ApprovalDecisionKind =
  | 'allow-once'
  | 'allow-session-rule'
  | 'deny'
  | 'deny-with-guidance';

export interface ApprovalAction {
  readonly kind: ApprovalActionKind;
  readonly summary: string;
  readonly command?: string;
  readonly canonicalArgv?: readonly string[];
  readonly requestedDelta?: Readonly<Record<string, unknown>>;
  readonly reasons: readonly string[];
  readonly touchesPhysicalDevice: boolean;
  readonly suggestedPrefix?: readonly string[];
}

export interface ApprovalRequestEnvelope {
  readonly requestId: string;
  readonly actionHash: string;
  readonly binding: SessionBinding;
  readonly action: ApprovalAction;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
  readonly allowSessionRuleOption: boolean;
  readonly signal: AbortSignal;
}

export interface ApprovalDecisionResponse {
  readonly requestId: string;
  readonly actionHash: string;
  readonly decision: ApprovalDecisionKind;
  readonly guidance?: string;
  readonly sessionPrefix?: readonly string[];
}

export interface ApprovalAuditRecord {
  readonly requestId: string;
  readonly actionHash: string;
  readonly kind: ApprovalActionKind;
  readonly summary: string;
  readonly outcome:
    | 'allowed-once'
    | 'allowed-session-rule'
    | 'denied'
    | 'timeout'
    | 'cancelled'
    | 'stale'
    | 'invalid'
    | 'unavailable';
  readonly guidance?: string;
  readonly timestamp: string;
}

export interface ApprovedExecutionTicket<TAction extends ApprovalAction = ApprovalAction> {
  readonly requestId: string;
  readonly actionHash: string;
  readonly binding: SessionBinding;
  readonly action: TAction;
  readonly assertCurrent: () => void;
  readonly consume: () => void;
}

export type ApprovalReviewerFn = (
  envelope: ApprovalRequestEnvelope,
) => Promise<ApprovalDecisionResponse> | ApprovalDecisionResponse;

export interface ApprovalControllerOptions {
  readonly ttlMs?: number;
  readonly reviewer: ApprovalReviewerFn;
  readonly onAudit?: (record: ApprovalAuditRecord) => void;
}

interface PendingEntry {
  readonly requestId: string;
  readonly actionHash: string;
  readonly controller: AbortController;
  readonly envelope: ApprovalRequestEnvelope;
  readonly generation: number;
}

function canonicalStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalStringify).join(',') + ']';
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalStringify(record[k])).join(',') + '}';
}

export function computeActionHash(binding: SessionBinding, action: ApprovalAction): string {
  const payload = {
    binding: {
      sessionId: binding.sessionId,
      distribution: binding.distribution,
      uid: binding.uid,
      cwd: binding.cwd,
      workspaceRoot: binding.workspaceRoot,
      profile: binding.profile,
      revision: binding.revision,
      generation: binding.generation,
      runnerId: binding.runnerId,
    },
    action: {
      kind: action.kind,
      summary: action.summary,
      command: action.command ?? null,
      canonicalArgv: action.canonicalArgv ?? null,
      requestedDelta: action.requestedDelta ?? null,
      touchesPhysicalDevice: action.touchesPhysicalDevice,
    },
  };
  return createHash('sha256').update(canonicalStringify(payload)).digest('hex');
}

function prefixKey(prefix: readonly string[]): string {
  return JSON.stringify(prefix.map((t) => t.toLowerCase()));
}

/**
 * Concurrent, single-use action-bound approval control plane.
 * Fixes the single-slot `REVIEW_BUSY` bug via `Map<requestId, PendingEntry>`,
 * enforces `BANNED_PREFIX_SUGGESTIONS`, and unconditionally forces manual `allow-once`
 * for physical-device operations (Q13).
 */
export class ApprovalController {
  private readonly ttlMs: number;
  private readonly reviewer: ApprovalReviewerFn;
  private readonly onAudit?: (record: ApprovalAuditRecord) => void;

  private generation = 0;
  private currentBinding: SessionBinding | undefined;
  private readonly pending = new Map<string, PendingEntry>();
  private readonly sessionPrefixes = new Set<string>();
  private readonly auditLog: ApprovalAuditRecord[] = [];
  private readonly usedGrants = new Set<string>();

  constructor(options: ApprovalControllerOptions) {
    const ttlMs = options.ttlMs ?? 60_000;
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 1 || ttlMs > 600_000) {
      failSandbox('INVALID_SETUP', `Invalid approval ttlMs: ${ttlMs}`);
    }
    this.ttlMs = ttlMs;
    this.reviewer = options.reviewer;
    this.onAudit = options.onAudit;
  }

  getGeneration(): number {
    return this.generation;
  }

  getBinding(): SessionBinding | undefined {
    return this.currentBinding;
  }

  getPendingRequests(): readonly ApprovalRequestEnvelope[] {
    return Array.from(this.pending.values()).map((e) => e.envelope);
  }

  getAuditLog(): readonly ApprovalAuditRecord[] {
    return [...this.auditLog];
  }

  getSessionRules(): readonly string[][] {
    return Array.from(this.sessionPrefixes).map((k) => JSON.parse(k) as string[]);
  }

  clearSessionRules(): void {
    this.sessionPrefixes.clear();
  }

  bind(binding: SessionBinding): void {
    this.invalidate();
    this.currentBinding = binding;
  }

  invalidate(): number {
    this.generation++;
    this.currentBinding = undefined;
    this.sessionPrefixes.clear();
    const abortedCount = this.pending.size;
    for (const entry of this.pending.values()) {
      entry.controller.abort(new Error('STALE_BINDING'));
    }
    this.pending.clear();
    return abortedCount;
  }

  private recordAudit(record: ApprovalAuditRecord): void {
    this.auditLog.push(record);
    if (this.auditLog.length > 500) {
      this.auditLog.shift();
    }
    this.onAudit?.(record);
  }

  private matchesSessionPrefix(action: ApprovalAction): boolean {
    // Physical hardware operations NEVER auto-match session rules (Q13)
    if (action.touchesPhysicalDevice || action.kind === 'physical-device') {
      return false;
    }
    const prefix = action.suggestedPrefix;
    if (!prefix || prefix.length === 0 || isBannedPrefix(prefix)) {
      return false;
    }
    return this.sessionPrefixes.has(prefixKey(prefix));
  }

  async authorize<TAction extends ApprovalAction>(
    action: TAction,
    callerSignal?: AbortSignal,
  ): Promise<ApprovedExecutionTicket<TAction>> {
    const bound = this.currentBinding;
    if (!bound) {
      failSandbox('BACKEND_UNAVAILABLE', 'No active verified WSL session binding');
    }
    if (callerSignal?.aborted) {
      failSandbox('REVIEW_CANCELLED', 'Caller cancelled before approval started');
    }

    const requestId = randomUUID();
    const actionHash = computeActionHash(bound, action);
    let consumed = false;

    const makeTicket = (deadlinePerfMs: number): ApprovedExecutionTicket<TAction> => {
      const assertCurrent = (): void => {
        if (this.currentBinding !== bound) {
          failSandbox('STALE_BINDING', 'Session binding or policy changed since approval');
        }
        if (performance.now() >= deadlinePerfMs) {
          failSandbox('REVIEW_TIMEOUT', 'Approval ticket expired before execution');
        }
      };
      const consume = (): void => {
        assertCurrent();
        if (consumed || this.usedGrants.has(requestId)) {
          failSandbox('GRANT_CONSUMED', 'One-shot approval grant was already consumed');
        }
        consumed = true;
        this.usedGrants.add(requestId);
        if (this.usedGrants.size > 2000) {
          const oldest = this.usedGrants.values().next().value;
          if (oldest) this.usedGrants.delete(oldest);
        }
      };
      return Object.freeze({
        requestId,
        actionHash,
        binding: bound,
        action,
        assertCurrent,
        consume,
      });
    };

    // Fast path: matched a non-banned, non-hardware session rule
    if (this.matchesSessionPrefix(action)) {
      this.recordAudit({
        requestId,
        actionHash,
        kind: action.kind,
        summary: action.summary,
        outcome: 'allowed-session-rule',
        timestamp: new Date().toISOString(),
      });
      return makeTicket(Infinity);
    }

    const allowSessionRuleOption =
      !action.touchesPhysicalDevice &&
      action.kind !== 'physical-device' &&
      Boolean(action.suggestedPrefix && action.suggestedPrefix.length > 0 && !isBannedPrefix(action.suggestedPrefix));

    const controller = new AbortController();
    const nowWall = Date.now();
    const deadlinePerf = performance.now() + this.ttlMs;

    const envelope: ApprovalRequestEnvelope = Object.freeze({
      requestId,
      actionHash,
      binding: bound,
      action,
      createdAtMs: nowWall,
      expiresAtMs: nowWall + this.ttlMs,
      allowSessionRuleOption,
      signal: controller.signal,
    });

    this.pending.set(requestId, {
      requestId,
      actionHash,
      controller,
      envelope,
      generation: bound.generation,
    });

    const abortedReason = Symbol('aborted');
    let timedOut = false;
    let callerCancelled = false;

    const onCallerAbort = (): void => {
      callerCancelled = true;
      controller.abort(new Error('REVIEW_CANCELLED'));
    };
    callerSignal?.addEventListener('abort', onCallerAbort, { once: true });

    let onAbortResolve: (() => void) | undefined;
    const abortPromise = new Promise<typeof abortedReason>((resolve) => {
      onAbortResolve = () => resolve(abortedReason);
      controller.signal.addEventListener('abort', onAbortResolve, { once: true });
    });

    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort(new Error('REVIEW_TIMEOUT'));
    }, this.ttlMs);

    let answer: ApprovalDecisionResponse | typeof abortedReason;
    try {
      answer = await Promise.race([
        Promise.resolve().then(() => {
          if (this.currentBinding !== bound) failSandbox('STALE_BINDING');
          return this.reviewer(envelope);
        }),
        abortPromise,
      ]);
    } catch (err) {
      if (this.currentBinding !== bound) {
        this.recordAudit({
          requestId,
          actionHash,
          kind: action.kind,
          summary: action.summary,
          outcome: 'stale',
          timestamp: new Date().toISOString(),
        });
        failSandbox('STALE_BINDING', 'Session binding invalidated during review');
      }
      this.recordAudit({
        requestId,
        actionHash,
        kind: action.kind,
        summary: action.summary,
        outcome: 'unavailable',
        timestamp: new Date().toISOString(),
      });
      failSandbox('REVIEW_ERROR', err instanceof Error ? err.message : 'Reviewer failed');
    } finally {
      clearTimeout(timer);
      if (onAbortResolve) {
        controller.signal.removeEventListener('abort', onAbortResolve);
      }
      callerSignal?.removeEventListener('abort', onCallerAbort);
      this.pending.delete(requestId);
    }

    // Re-check binding BEFORE trusting any reviewer result
    if (this.currentBinding !== bound) {
      this.recordAudit({
        requestId,
        actionHash,
        kind: action.kind,
        summary: action.summary,
        outcome: 'stale',
        timestamp: new Date().toISOString(),
      });
      failSandbox('STALE_BINDING', 'Session binding changed while awaiting approval');
    }

    if (callerCancelled) {
      this.recordAudit({
        requestId,
        actionHash,
        kind: action.kind,
        summary: action.summary,
        outcome: 'cancelled',
        timestamp: new Date().toISOString(),
      });
      failSandbox('REVIEW_CANCELLED', 'Approval request cancelled by caller');
    }

    if (answer === abortedReason || timedOut || controller.signal.aborted) {
      this.recordAudit({
        requestId,
        actionHash,
        kind: action.kind,
        summary: action.summary,
        outcome: 'timeout',
        timestamp: new Date().toISOString(),
      });
      failSandbox('REVIEW_TIMEOUT', `Approval timed out after ${this.ttlMs}ms`);
    }

    if (!answer || answer.requestId !== requestId || answer.actionHash !== actionHash) {
      this.recordAudit({
        requestId,
        actionHash,
        kind: action.kind,
        summary: action.summary,
        outcome: 'invalid',
        timestamp: new Date().toISOString(),
      });
      failSandbox('REVIEW_INVALID', 'Approval response requestId or actionHash mismatch');
    }

    if (answer.decision === 'deny' || answer.decision === 'deny-with-guidance') {
      this.recordAudit({
        requestId,
        actionHash,
        kind: action.kind,
        summary: action.summary,
        outcome: 'denied',
        guidance: answer.guidance,
        timestamp: new Date().toISOString(),
      });
      failSandbox(
        'REVIEW_DENIED',
        answer.guidance ? `Denied by user: ${answer.guidance}` : 'Command denied by user',
        answer.guidance ? { guidance: answer.guidance } : undefined,
      );
    }

    if (answer.decision === 'allow-session-rule') {
      const candidatePrefix = answer.sessionPrefix ?? action.suggestedPrefix;
      // Enforce BOTH hardware-device ban AND BANNED_PREFIX_SUGGESTIONS!
      if (
        allowSessionRuleOption &&
        candidatePrefix &&
        candidatePrefix.length > 0 &&
        !isBannedPrefix(candidatePrefix)
      ) {
        this.sessionPrefixes.add(prefixKey(candidatePrefix));
        this.recordAudit({
          requestId,
          actionHash,
          kind: action.kind,
          summary: action.summary,
          outcome: 'allowed-session-rule',
          timestamp: new Date().toISOString(),
        });
      } else {
        // Silently downgrade banned/hardware session-rule attempt to strictly single-shot allow-once
        this.recordAudit({
          requestId,
          actionHash,
          kind: action.kind,
          summary: action.summary,
          outcome: 'allowed-once',
          timestamp: new Date().toISOString(),
        });
      }
      return makeTicket(deadlinePerf);
    }

    if (answer.decision === 'allow-once') {
      this.recordAudit({
        requestId,
        actionHash,
        kind: action.kind,
        summary: action.summary,
        outcome: 'allowed-once',
        timestamp: new Date().toISOString(),
      });
      return makeTicket(deadlinePerf);
    }

    this.recordAudit({
      requestId,
      actionHash,
      kind: action.kind,
      summary: action.summary,
      outcome: 'invalid',
      timestamp: new Date().toISOString(),
    });
    failSandbox('REVIEW_INVALID', `Unknown approval decision: ${String(answer.decision)}`);
  }
}
