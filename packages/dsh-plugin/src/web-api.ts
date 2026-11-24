import {
  type ApprovalDecisionKind,
  type AuthorizedDeviceNode,
  type AuthorizedShare,
  isSandboxError,
} from '../../core/src/index.ts';
import type { ApprovalBridge } from './approval-bridge.ts';
import type { BasicConfigPatch, ConfigStore } from './config-store.ts';
import type { DshCordisContext, DshHttpHandler, DshHttpResponse } from './cordis-types.ts';
import { upsertAgentsMdWslSection } from './prompt-injector.ts';
import type { WslSandboxSessionManager } from './tools.ts';
import { renderWslSandboxUiHtml } from './web-ui-entry.ts';

export interface WebApiDeps {
  readonly configStore: ConfigStore;
  readonly sessionManager: WslSandboxSessionManager;
  readonly approvalBridge: ApprovalBridge;
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

/**
 * Registers strictly namespaced human-only HTTP routes under `/wsl-sandbox/api/*` and `/wsl-sandbox/ui`.
 * Never overrides any stock DSH or `dsh-purge` routes.
 */
export function registerWslSandboxWebApi(ctx: DshCordisContext, deps: WebApiDeps): (() => void)[] {
  const disposers: (() => void)[] = [];
  if (!ctx.http) return disposers;

  const add = (
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    routePath: string,
    handler: DshHttpHandler,
  ): void => {
    const dispose = ctx.http!.route(method, routePath, safe(handler));
    if (typeof dispose === 'function') disposers.push(dispose);
  };

  add('GET', '/wsl-sandbox/ui', (_req, res) => {
    res.status(200).html(renderWslSandboxUiHtml());
  });

  add('GET', '/wsl-sandbox/api/status', (_req, res) => {
    const binding = deps.sessionManager.getBindingSnapshot();
    res.status(200).json({
      ok: true,
      bound: Boolean(binding),
      generation: deps.sessionManager.getGeneration(),
      binding: binding ?? null,
      config: deps.configStore.get(),
      pendingApprovals: deps.approvalBridge.listPending().length,
    });
  });

  add('GET', '/wsl-sandbox/api/config', (_req, res) => {
    res.status(200).json(deps.configStore.get());
  });

  add('PUT', '/wsl-sandbox/api/config', (req, res) => {
    const body = (req.body ?? {}) as BasicConfigPatch & Record<string, unknown>;
    const updated = deps.configStore.updateBasic(body);
    res.status(200).json({ ok: true, config: updated });
  });

  add('POST', '/wsl-sandbox/api/advanced/shares', (req, res) => {
    const share = (req.body ?? {}) as AuthorizedShare;
    const updated = deps.configStore.addShare(share);
    res.status(200).json({ ok: true, config: updated });
  });

  add('DELETE', '/wsl-sandbox/api/advanced/shares/:id', async (req, res) => {
    const shareId = req.params.id ?? '';
    const updated = deps.configStore.removeShare(shareId);
    const killedCount = await deps.sessionManager.invalidateNow(`Share '${shareId}' revoked`);
    res.status(200).json({ ok: true, revokedShareId: shareId, killedCount, config: updated });
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

  add('GET', '/wsl-sandbox/api/audit', (_req, res) => {
    res.status(200).json({
      ok: true,
      records: deps.approvalBridge.getAuditLog(),
    });
  });

  add('POST', '/wsl-sandbox/api/agents-md', (req, res) => {
    const body = (req.body ?? {}) as { projectRoot?: string };
    const cfg = deps.configStore.get();
    const targetDir = body.projectRoot?.trim() || cfg.workspaceRoot;
    const result = upsertAgentsMdWslSection(targetDir, {
      distro: cfg.distro,
      workspaceRoot: cfg.workspaceRoot,
    });
    res.status(200).json({ ok: true, ...result });
  });

  return disposers;
}
