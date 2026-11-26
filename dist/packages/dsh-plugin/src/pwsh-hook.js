import {
  evaluateBashCommand,
  evaluatePwshCommand,
  failSandbox,
                       
  isSandboxError,
                      
} from '../../core/src/index.js';
                                                           
                                                          
             
                   
                     
                           
                           

/**
 * Host Windows PowerShell/CMD shell tool names guarded with PowerShell/CMD Single-Shell Purity + Dialect Linter.
 * Includes `dsh-windows-mcp`'s optional `mcp__windows__powershell` tool while keeping all GUI `mcp__*` tools untouched!
 */
const HOST_PWSH_SHELL_TOOLS = new Set([
  'pwsh',
  'pwsh_persistent',
  'powershell',
  'cmd',
  'cmd_exec',
  'windows_shell',
  'local_shell',
  'host_shell',
  'shell',
  'mcp__windows__powershell',
  'mcp__windows__powershell-tool',
  'mcp__windows__powershell_tool',
]);

/**
 * Host POSIX Bash tools on Windows (`@linxin666/dsh-win-bash` -> `win_bash`, `dsh-ops` -> `ops_bash`).
 * They speak POSIX Bash (never PowerShell dialect!), but execute on the Windows host outside WSL 2 `bwrap`,
 * so we guard them against host WSL-escape / `.wslconfig` tampering / physical `usbipd` bypass using POSIX tokenization!
 */
const HOST_POSIX_BASH_TOOLS = new Set(['win_bash', 'ops_bash']);

                                                                        

export function classifyHostShellTool(toolName        )                {
  const lower = toolName.trim().toLowerCase();
  if (
    lower.startsWith('wsl_') ||
    lower.startsWith('dsh-purge') ||
    lower.startsWith('dsh_purge') ||
    lower.startsWith('redteam_') ||
    lower.startsWith('rw_') ||
    lower.startsWith('ssh_')
  ) {
    return 'none';
  }
  if (HOST_PWSH_SHELL_TOOLS.has(lower)) {
    return 'pwsh-dialect';
  }
  if (lower.startsWith('mcp__')) {
    return 'none';
  }
  if (HOST_POSIX_BASH_TOOLS.has(lower)) {
    return 'host-posix-bash';
  }
  return 'none';
}

export function isHostWindowsShellTool(toolName        )          {
  return classifyHostShellTool(toolName) !== 'none';
}

function extractShellCommand(input         )                     {
  if (!input || typeof input !== 'object') return undefined;
  const rec = input                           ;
  for (const key of ['command', 'script', 'cmd', 'code', 'input']) {
    const val = rec[key];
    if (typeof val === 'string' && val.trim().length > 0) {
      return val;
    }
  }
  if (Array.isArray(rec.argv) && rec.argv.every((x) => typeof x === 'string')) {
    return (rec.argv            ).join(' ');
  }
  return undefined;
}

/**
 * Evaluates a host POSIX Bash tool (`win_bash` / `ops_bash`) using POSIX Bash AST parsing +
 * host-side WSL escape & physical USBIP checks (never PowerShell syntax linting!).
 */
export function evaluateHostPosixBashOnWindows(command        )                  {
  if (/(?:\\\\|\/\/)wsl(?:\$|\.localhost)(?:\\|\/)/i.test(command)) {
    return {
      decision: 'deny',
      riskLevel: 'critical',
      code: 'POLICY_BLOCK',
      reasons: [
        'Accessing WSL filesystem via Windows UNC share (\\\\wsl$\\ or \\\\wsl.localhost\\) from host shell bypasses bwrap read-only locks and is forbidden',
      ],
      unwrappedCommands: [],
      touchesPhysicalDevice: false,
      requiresSessionRuleBlocked: true,
      externalPaths: [],
    };
  }
  if (/\.wslconfig\b/i.test(command)) {
    return {
      decision: 'deny',
      riskLevel: 'critical',
      code: 'POLICY_BLOCK',
      reasons: ['Modifying .wslconfig from host shell is forbidden'],
      unwrappedCommands: [],
      touchesPhysicalDevice: false,
      requiresSessionRuleBlocked: true,
      externalPaths: [],
    };
  }
  if (/\busbipd(?:\.exe)?\b[^\n;|&]*\b(?:bind|unbind|attach|detach)\b/i.test(command)) {
    return {
      decision: 'ask',
      riskLevel: 'high',
      reasons: ['Physical USBIP device bind/attach/detach requires manual single-shot approval'],
      unwrappedCommands: [['usbipd']],
      touchesPhysicalDevice: true,
      requiresSessionRuleBlocked: true,
      externalPaths: [],
    };
  }
  if (
    /\bpnputil(?:\.exe)?\b[^\n;|&]*(?:\/(?:add-driver|delete-driver|install|enable-device|disable-device|restart-device|remove-device)\b|\s-[adi]\b)|\b(?:devcon(?:\.exe)?\b[^\n;|&]*\b(?:install|update|remove|enable|disable|restart)\b|zadig(?:\.exe)?\b)/i.test(
      command,
    )
  ) {
    return {
      decision: 'ask',
      riskLevel: 'high',
      reasons: ['Windows driver / PnP device mutation requires manual single-shot approval'],
      unwrappedCommands: [['pnputil']],
      touchesPhysicalDevice: true,
      requiresSessionRuleBlocked: true,
      externalPaths: [],
    };
  }
  return evaluateBashCommand(command, { workspaceRoot: '/host-workspace' });
}

function evaluateByKind(kind               , command        )                              {
  if (kind === 'pwsh-dialect') {
    return evaluatePwshCommand(command);
  }
  if (kind === 'host-posix-bash') {
    return evaluateHostPosixBashOnWindows(command);
  }
  return undefined;
}

                                  
                                             
                                                     
                                          
 

/**
 * Registers BOTH:
 *  1. Monotonic `ctx.tools.guard(...)` (real `@deepseek-ai/dsh-tools@0.2.2-rc.5`): enforces L0 destructive,
 *     Single-Shell Purity, and Pre-Execution Shell Dialect denials AFTER all `tools/pre-execute` listeners
 *     (mathematically unbypassable by `dsh-purge` `hooksDenyBypass` or listener ordering!).
 *  2. Polite `tools/pre-execute` waterfall listener: handles L0 denials and routes L3 / `usbipd` physical
 *     hardware requests through `ApprovalBridge` while delegating all other tools cleanly via `next()`.
 */
export function registerHostPwshGuardHook(
  ctx                  ,
  options                 ,
)                           {
  const disposers                    = [];

  // 1. Monotonic `ctx.tools.guard` for L0 + Single-Shell Purity + Dialect Alignment
  if (ctx.tools?.guard) {
    const guardDispose = ctx.tools.guard((exec) => {
      const cfg = options.getConfig();
      if (!cfg.enabled || !cfg.enablePwshGuard) return undefined;
      const toolName = String(exec?.name ?? '');
      const kind = classifyHostShellTool(toolName);
      if (kind === 'none') return undefined;
      const command = extractShellCommand(exec?.arguments);
      if (!command) return undefined;

      const verdict = evaluateByKind(kind, command);
      if (verdict?.decision === 'deny') {
        return {
          reason: `Host shell command blocked by dsh-wsl-sandbox policy: ${verdict.reasons.join('; ')}`,
          info: {
            name: 'SandboxError',
            code: 'POLICY_BLOCK',
          },
        };
      }
      return undefined;
    });
    if (typeof guardDispose === 'function') {
      disposers.push(guardDispose);
    }
  }

  // 2. Polite `tools/pre-execute` waterfall listener
  if (ctx.waterfall) {
    const wfDispose = ctx.waterfall                                   (
      'tools/pre-execute',
      async (payload, next) => {
        const passThrough = () =>
          typeof next === 'function' ? next() : ({ kind: 'allow' }                             );

        const cfg = options.getConfig();
        if (!cfg.enabled || !cfg.enablePwshGuard || !payload) {
          return passThrough();
        }

        const isRealDshExec = typeof payload.name === 'string' && payload.toolName === undefined;
        const toolName = String(payload.name ?? payload.toolName ?? '');
        const kind = classifyHostShellTool(toolName);
        if (kind === 'none') {
          return passThrough();
        }

        const rawInput = isRealDshExec ? payload.arguments : payload.input;
        const command = extractShellCommand(rawInput);
        if (!command) {
          return passThrough();
        }

        const verdict = evaluateByKind(kind, command);
        if (!verdict || verdict.decision === 'allow') {
          return passThrough();
        }

        if (verdict.decision === 'deny') {
          const message = `Host shell command blocked by dsh-wsl-sandbox L0 policy: ${verdict.reasons.join('; ')}`;
          if (isRealDshExec) {
            return {
              kind: 'deny',
              reason: message,
              info: { name: 'SandboxError', code: 'POLICY_BLOCK' },
            }                             ;
          }
          failSandbox('POLICY_BLOCK', message, {
            toolName,
            riskLevel: verdict.riskLevel,
            reasons: verdict.reasons,
          });
        }

        // `ask` -> route through ApprovalBridge
        try {
          const binding = await options.getBinding();
          const ticket = await options.approvalBridge.requestApproval(
            binding,
            {
              kind: verdict.touchesPhysicalDevice ? 'physical-device' : 'host-pwsh-command',
              summary: verdict.touchesPhysicalDevice
                ? `Host physical device operation via ${toolName}`
                : `Host Windows shell command via ${toolName}`,
              command,
              canonicalArgv: verdict.unwrappedCommands[0],
              reasons: verdict.reasons,
              touchesPhysicalDevice: verdict.touchesPhysicalDevice,
              suggestedPrefix: verdict.suggestedPrefix,
            },
            {
              requireIndependentFallback: true,
              eligibleForTrustWorkspace: false,
              agent: payload.agent,
              toolName,
              callId: payload.callId,
              callerSignal: payload.signal,
            },
          );

          ticket.assertCurrent();
          ticket.consume();
          return passThrough();
        } catch (err) {
          if (isRealDshExec && isSandboxError(err)) {
            return {
              kind: 'deny',
              reason: err.message,
              info: { name: 'SandboxError', code: err.code },
            }                             ;
          }
          throw err;
        }
      },
    );
    if (typeof wfDispose === 'function') {
      disposers.push(() => void wfDispose());
    }
  }

  if (disposers.length === 0) return undefined;
  return () => {
    for (const d of disposers.splice(0)) {
      d();
    }
  };
}
