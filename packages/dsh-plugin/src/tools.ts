import { createHash, randomUUID } from 'node:crypto';
import { posix } from 'node:path';
import {
  assertVerifiedProbe,
  evaluateBashCommand,
  failSandbox,
  isPathInside,
  type ProbeResponse,
  type ProcExecResult,
  type SandboxMode,
  type SessionBinding,
  type TerminalExecResult,
} from '../../core/src/index.ts';
import type { ApprovalBridge } from './approval-bridge.ts';
import type { ConfigStore, WslSandboxConfig } from './config-store.ts';
import type {
  DshContentBlock,
  DshCordisContext,
  DshToolCallMeta,
  DshToolDefinition,
} from './cordis-types.ts';
import { WslTransport } from './wsl-transport.ts';

export interface SessionManagerOptions {
  readonly configStore: ConfigStore;
  readonly approvalBridge: ApprovalBridge;
  readonly sessionId?: string;
  readonly allowLinuxDevMode?: boolean;
  readonly onStderr?: (line: string) => void;
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

/**
 * Coordinates the single active verified `SessionBinding`, persistent `WslTransport`,
 * managed in-WSL `UdsAllowlistProxy`, and `ApprovalBridge` across all 7 `wsl_*` tools.
 */
export class WslSandboxSessionManager {
  private readonly configStore: ConfigStore;
  private readonly approvalBridge: ApprovalBridge;
  private readonly sessionId: string;
  private readonly allowLinuxDevMode: boolean;
  private readonly onStderr?: (line: string) => void;

  private transport: WslTransport | undefined;
  private binding: SessionBinding | undefined;
  private generation = 0;
  private proxyConfiguredRevision: string | undefined;
  private unsubscribeConfig: (() => void) | undefined;

  constructor(options: SessionManagerOptions) {
    this.configStore = options.configStore;
    this.approvalBridge = options.approvalBridge;
    this.sessionId = options.sessionId ?? `dsh-wsl-${randomUUID().slice(0, 8)}`;
    this.allowLinuxDevMode = options.allowLinuxDevMode ?? process.platform === 'linux';
    this.onStderr = options.onStderr;

    this.unsubscribeConfig = this.configStore.onChange((next, prev) => {
      void this.handleConfigChanged(next, prev);
    });
  }

  getBindingSnapshot(): SessionBinding | undefined {
    return this.binding;
  }

  getGeneration(): number {
    return this.generation;
  }

  private async handleConfigChanged(next: WslSandboxConfig, prev: WslSandboxConfig): Promise<void> {
    this.generation += 1;
    this.binding = undefined;
    this.proxyConfiguredRevision = undefined;
    this.approvalBridge.invalidate(`Configuration changed to ${next.revision}`);

    const transportChanged =
      next.transportMode !== prev.transportMode ||
      next.distro !== prev.distro ||
      next.username !== prev.username ||
      next.runnerPath !== prev.runnerPath;

    if (this.transport) {
      if (transportChanged || !next.enabled) {
        const old = this.transport;
        this.transport = undefined;
        await old.dispose().catch(() => {});
      } else {
        await this.transport.invalidate(this.generation);
      }
    }
  }

  private ensureTransport(cfg: WslSandboxConfig): WslTransport {
    if (!cfg.enabled) {
      failSandbox('SANDBOX_UNAVAILABLE', 'dsh-wsl-sandbox is currently disabled in configuration');
    }
    if (!this.transport) {
      this.transport = new WslTransport({
        mode: cfg.transportMode,
        distro: cfg.distro,
        username: cfg.username,
        runnerPath: cfg.runnerPath,
        onStderr: this.onStderr,
        onAuthorizeProxyHost: (host, port) => this.authorizeUnknownProxyHost(host, port),
      });
    }
    return this.transport;
  }

  private async authorizeUnknownProxyHost(host: string, port: number): Promise<boolean> {
    try {
      const binding = await this.ensureBound();
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
    if (this.binding && this.binding.revision === cfg.revision && this.transport?.isRunning()) {
      await this.syncProxyPolicy(cfg);
      return this.binding;
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

    const verified = assertVerifiedProbe(probeResult, {
      expectedSessionId: this.sessionId,
      expectedDistribution: cfg.distro,
      expectedWorkspaceRoot: cfg.workspaceRoot,
      expectedCwd: cfg.workspaceRoot,
      expectedProfile: cfg.sandboxMode,
      expectedRevision: cfg.revision,
      generation: this.generation,
      authorizedShares: cfg.advanced.shares,
      authorizedDevices: cfg.advanced.deviceNodes,
    });

    this.binding = verified;
    this.approvalBridge.setBinding(verified);
    await this.syncProxyPolicy(cfg);
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

  async invalidateNow(reason = 'Manual invalidation'): Promise<number> {
    this.generation += 1;
    this.binding = undefined;
    this.proxyConfiguredRevision = undefined;
    this.approvalBridge.invalidate(reason);
    if (this.transport) {
      return this.transport.invalidate(this.generation);
    }
    return 0;
  }

  async callRpc<T = unknown>(method: string, params: Record<string, unknown>, timeoutMs?: number): Promise<T> {
    const cfg = this.configStore.get();
    const transport = this.ensureTransport(cfg);
    return transport.call<T>(method, params, timeoutMs);
  }

  computeCacheDir(binding: SessionBinding, cfg: WslSandboxConfig): string | undefined {
    if (cfg.cacheMode !== 'workspace-persistent') return undefined;
    const hash = createHash('sha256').update(binding.workspaceRoot).digest('hex').slice(0, 12);
    return `/home/${binding.username}/.cache/dsh-wsl-sandbox/${hash}`;
  }

  async dispose(): Promise<void> {
    this.unsubscribeConfig?.();
    this.unsubscribeConfig = undefined;
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
    const cwd = resolveToolCwd(binding, params.cwd);

    const guard = evaluateBashCommand(params.command, {
      workspaceRoot: binding.workspaceRoot,
      cwd,
      authorizedShares: binding.authorizedShares,
      authorizedDevices: binding.authorizedDevices,
    });

    if (guard.decision === 'deny') {
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

    const execPayload = {
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

    if (params.terminalId) {
      return sessionManager.callRpc<TerminalExecResult>(
        'term.exec',
        { ...execPayload, terminalId: params.terminalId },
        (params.timeoutMs ?? 120_000) + 15_000,
      );
    }

    return sessionManager.callRpc<ProcExecResult>(
      'proc.exec',
      execPayload,
      (params.timeoutMs ?? 120_000) + 15_000,
    );
  }

  return [
    {
      name: 'wsl_bash',
      description:
        'Execute a pure POSIX Bash command inside the isolated WSL 2 Linux guest sandbox (bwrap + seccomp-bpf + prlimit + UDS allowlist proxy). Prefer this over Windows pwsh for directory creation, file moves, coding, git, builds, tests, ESP32 compilation, and Linux/Kali tools. Note: cwd is an isolated Linux guest path (separate from Windows host NTFS; if declaring to cc-safety-net, pass --no-cwd-arg).',
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
        schema: { description: 'WSL 2 sandboxed Bash execution result' },
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
        schema: { description: 'WSL 2 file read result' },
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
        schema: { description: 'WSL 2 file write result' },
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
        schema: { description: 'WSL 2 file edit result' },
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
        schema: { description: 'WSL 2 glob search result' },
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
        schema: { description: 'WSL 2 grep search result' },
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
        schema: { description: 'WSL 2 stateful terminal execution result' },
        render: (_args, value) => renderExecOutcome(value),
      },
      execute: async (input, meta) => {
        const terminalId =
          typeof input.terminalId === 'string' && input.terminalId.trim()
            ? input.terminalId.trim()
            : 'default';
        if (input.reset) {
          await sessionManager.ensureBound();
          await sessionManager.callRpc('term.reset', { terminalId });
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
  for (const tool of tools) {
    const dispose = ctx.tools.register(tool);
    if (typeof dispose === 'function') {
      disposers.push(dispose);
    }
  }
  return disposers;
}
