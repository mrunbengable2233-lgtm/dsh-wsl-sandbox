import {
  evaluatePwshCommand,
  failSandbox,
  type SessionBinding,
} from '../../core/src/index.ts';
import type { ApprovalBridge } from './approval-bridge.ts';
import type { WslSandboxConfig } from './config-store.ts';
import type { DshCordisContext, DshToolPreExecutePayload } from './cordis-types.ts';

/**
 * Host Windows shell tool names guarded by `PwshGuard`.
 * Explicitly excludes `wsl_*`, `dsh-purge*`, MCP tools, and non-shell tools.
 */
const HOST_WINDOWS_SHELL_TOOLS = new Set([
  'pwsh',
  'powershell',
  'cmd',
  'cmd_exec',
  'windows_shell',
  'local_shell',
  'host_shell',
  'shell',
]);

export function isHostWindowsShellTool(toolName: string): boolean {
  const lower = toolName.trim().toLowerCase();
  if (lower.startsWith('wsl_') || lower.startsWith('dsh-purge') || lower.startsWith('dsh_purge') || lower.startsWith('mcp__')) {
    return false;
  }
  return HOST_WINDOWS_SHELL_TOOLS.has(lower);
}

function extractShellCommand(input: Record<string, unknown>): string | undefined {
  for (const key of ['command', 'script', 'cmd', 'code', 'input']) {
    const val = input[key];
    if (typeof val === 'string' && val.trim().length > 0) {
      return val;
    }
  }
  if (Array.isArray(input.argv) && input.argv.every((x) => typeof x === 'string')) {
    return (input.argv as string[]).join(' ');
  }
  return undefined;
}

export interface PwshHookOptions {
  readonly getConfig: () => WslSandboxConfig;
  readonly getBinding: () => Promise<SessionBinding>;
  readonly approvalBridge: ApprovalBridge;
}

/**
 * Registers a polite `tools/pre-execute` waterfall listener guarding ONLY Windows host shell tools
 * (`pwsh`, `powershell`, `cmd`, `shell`) with zero-token `PwshGuard` (Q15=A + Q13=A).
 *
 * - Never interferes with `wsl_*`, `dsh-purge`, MCP, or non-shell tools (immediate `return next()`).
 * - L0 critical commands & WSL config/root tampering -> hard `POLICY_BLOCK`.
 * - L3 high-risk commands, `wsl.exe` sandbox bypasses, & physical USBIP/flashing -> `ApprovalBridge`
 *   with `requireIndependentFallback: true` (and `touchesPhysicalDevice: true` forcing manual `allow-once`).
 */
export function registerHostPwshGuardHook(
  ctx: DshCordisContext,
  options: PwshHookOptions,
): (() => void) | undefined {
  if (!ctx.waterfall) return undefined;

  const dispose = ctx.waterfall<DshToolPreExecutePayload, unknown>(
    'tools/pre-execute',
    async (payload, next) => {
      const cfg = options.getConfig();
      if (!cfg.enabled || !cfg.enablePwshGuard) {
        return next();
      }
      if (!payload || !isHostWindowsShellTool(payload.toolName)) {
        return next();
      }

      const command = extractShellCommand(payload.input ?? {});
      if (!command) {
        return next();
      }

      const verdict = evaluatePwshCommand(command);
      if (verdict.decision === 'allow') {
        return next();
      }

      if (verdict.decision === 'deny') {
        failSandbox(
          'POLICY_BLOCK',
          `Host PowerShell/CMD command blocked by dsh-wsl-sandbox L0 policy: ${verdict.reasons.join('; ')}`,
          {
            toolName: payload.toolName,
            riskLevel: verdict.riskLevel,
            reasons: verdict.reasons,
          },
        );
      }

      // `ask` -> route through ApprovalBridge (independent fallback catches `dsh-purge` bypass)
      const binding = await options.getBinding();
      const ticket = await options.approvalBridge.requestApproval(
        binding,
        {
          kind: verdict.touchesPhysicalDevice ? 'physical-device' : 'host-pwsh-command',
          summary: verdict.touchesPhysicalDevice
            ? `Host physical device operation via ${payload.toolName}`
            : `Host Windows shell command via ${payload.toolName}`,
          command,
          canonicalArgv: verdict.unwrappedCommands[0],
          reasons: verdict.reasons,
          touchesPhysicalDevice: verdict.touchesPhysicalDevice,
          suggestedPrefix: verdict.suggestedPrefix,
        },
        {
          requireIndependentFallback: true,
          eligibleForTrustWorkspace: false,
        },
      );

      ticket.assertCurrent();
      ticket.consume();
      return next();
    },
  );

  return typeof dispose === 'function' ? dispose : undefined;
}
