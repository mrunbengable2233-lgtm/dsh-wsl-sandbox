import {
  evaluateBashCommand,
  evaluatePwshCommand,
  evaluatePwshCommandWithSystemAst,
  extractBashNonProseTargets,
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

const HOST_WSL_UNC_RE = /(?:\\\\|\/\/)(?:[?.][\\/]unc[\\/])?wsl(?:\$|\.localhost)(?:[\\/]|$)/i;
const HOST_WSL_CONFIG_RE = /(?:^|[\\/])(?:\.wslconfig|etc[\\/]wsl\.conf|etc[\\/]fstab)$/i;

/**
 * Evaluates a host POSIX Bash tool (`win_bash` / `ops_bash`) using POSIX Bash AST parsing +
 * host-side WSL escape & physical USBIP checks (never PowerShell syntax linting!).
 */
export function evaluateHostPosixBashOnWindows(command        )                  {
  const base = evaluateBashCommand(command, { workspaceRoot: '/host-workspace' });
  const targets = extractBashNonProseTargets(command);

  const reasons = [...base.reasons];
  let decision                           = base.decision;
  let riskLevel                                            = base.riskLevel;
  let touchesPhysicalDevice = base.touchesPhysicalDevice;
  let requiresSessionRuleBlocked = base.requiresSessionRuleBlocked;

  const escalate = (
    nextDecision                ,
    nextRisk                                  ,
    reason        ,
  )       => {
    if (!reasons.includes(reason)) reasons.push(reason);
    requiresSessionRuleBlocked = true;
    if (nextDecision === 'deny') {
      decision = 'deny';
      riskLevel = 'critical';
    } else if (decision !== 'deny') {
      decision = 'ask';
      const order = { safe: 0, elevated: 1, high: 2, critical: 3 };
      if (order[nextRisk] > order[riskLevel]) riskLevel = nextRisk;
    }
  };

  for (const candidate of [...targets.nonProseArgs, ...targets.redirectionTargets]) {
    if (HOST_WSL_UNC_RE.test(candidate)) {
      escalate(
        'deny',
        'critical',
        'Accessing WSL filesystem via Windows UNC share (\\\\wsl$\\ or \\\\wsl.localhost\\) from host shell bypasses bwrap read-only locks and is forbidden',
      );
    }
    if (HOST_WSL_CONFIG_RE.test(candidate)) {
      escalate('deny', 'critical', 'Modifying .wslconfig / wsl.conf / fstab from host shell is forbidden');
    }
  }

  for (const argv of base.unwrappedCommands) {
    const head = (argv[0] ?? '').replace(/^.*\//, '').toLowerCase();
    const args = argv.slice(1);
    if (head === 'wsl' || head === 'wsl.exe' || head === 'bash.exe') {
      let hasAdminOrRoot = false;
      for (let i = 0; i < args.length; i++) {
        const a = args[i] .toLowerCase();
        if (
          a === '--import' ||
          a === '--unregister' ||
          a === '--shutdown' ||
          a === '--set-default' ||
          a === '--terminate' ||
          a === '--mount' ||
          a === '--user=root' ||
          ((a === '-u' || a === '--user') && args[i + 1]?.toLowerCase() === 'root')
        ) {
          hasAdminOrRoot = true;
          break;
        }
      }
      if (hasAdminOrRoot) {
        escalate(
          'deny',
          'critical',
          'Managing/destroying WSL distributions or spawning root shell via wsl.exe from host shell is forbidden',
        );
      } else {
        escalate(
          'ask',
          'high',
          'Invoking wsl/wsl.exe/bash.exe from host POSIX shell bypasses the WSL sandbox; use wsl_bash or approve explicitly',
        );
      }
    }

    if (head === 'pnputil' || head === 'pnputil.exe') {
      const joined = args.join(' ');
      if (/\/(?:add-driver|delete-driver|install|enable-device|disable-device|restart-device|remove-device)\b|(?:^|\s)-[adi]\b/i.test(joined)) {
        touchesPhysicalDevice = true;
        escalate('ask', 'high', 'Windows driver / PnP device mutation requires manual single-shot approval');
      }
    } else if (head === 'devcon' || head === 'devcon.exe') {
      if (args.some((a) => /^(?:install|update|remove|enable|disable|restart)$/i.test(a))) {
        touchesPhysicalDevice = true;
        escalate('ask', 'high', 'Windows driver / PnP device mutation requires manual single-shot approval');
      }
    } else if (head === 'zadig' || head === 'zadig.exe') {
      touchesPhysicalDevice = true;
      escalate('ask', 'high', 'Windows driver / PnP device mutation requires manual single-shot approval');
    }
  }

  return {
    decision,
    riskLevel,
    code: decision === 'deny' ? 'POLICY_BLOCK' : undefined,
    reasons,
    unwrappedCommands: base.unwrappedCommands,
    touchesPhysicalDevice,
    requiresSessionRuleBlocked,
    suggestedPrefix: requiresSessionRuleBlocked ? undefined : base.suggestedPrefix,
    externalPaths: base.externalPaths,
  };
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

async function evaluateByKindAsync(kind               , command        )                                       {
  if (kind === 'pwsh-dialect') {
    return evaluatePwshCommandWithSystemAst(command);
  }
  if (kind === 'host-posix-bash') {
    return evaluateHostPosixBashOnWindows(command);
  }
  return undefined;
}

function createHostFallbackBinding(cfg                  )                 {
  return Object.freeze({
    sessionId: 'host-pwsh-fallback',
    backend: 'wsl',
    wslVersion: 2,
    distribution: cfg.distro || 'Ubuntu-26.04',
    uid: 1000,
    username: cfg.username || 'host',
    arch: process.arch === 'arm64' ? 'aarch64' : 'x86_64',
    workspaceRoot: cfg.workspaceRoot || '/home/host/workspace',
    cwd: cfg.workspaceRoot || '/home/host/workspace',
    profile: cfg.sandboxMode,
    revision: cfg.revision,
    generation: 0,
    runnerId: 'host-fallback',
    sandboxReady: true,
    enforcement: 'partial',
    supportsDisableUserns: false,
    probedSockets: Object.freeze([]),
    authorizedShares: Object.freeze([]),
    authorizedDevices: Object.freeze([]),
  });
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
  let cachedFallbackBinding                            ;

  const getHostBindingOrFallback = async ()                          => {
    try {
      return await options.getBinding();
    } catch {
      const cfg = options.getConfig();
      if (!cachedFallbackBinding || cachedFallbackBinding.revision !== cfg.revision) {
        cachedFallbackBinding = createHostFallbackBinding(cfg);
      }
      return cachedFallbackBinding;
    }
  };

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
        options.logger?.log('warn', {
          component: 'pwsh-guard',
          event: 'pwshGuard.deny',
          message: `Blocked host shell '${toolName}' at L0 monotonic guard: ${verdict.reasons.join('; ')}`,
          data: { toolName, kind, riskLevel: verdict.riskLevel, reasons: verdict.reasons },
        });
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

        const verdict = await evaluateByKindAsync(kind, command);
        if (!verdict || verdict.decision === 'allow') {
          return passThrough();
        }

        if (verdict.decision === 'deny') {
          options.logger?.log('warn', {
            component: 'pwsh-guard',
            event: 'pwshGuard.deny',
            message: `Blocked host shell '${toolName}' at L0 pre-execute: ${verdict.reasons.join('; ')}`,
            data: { toolName, kind, riskLevel: verdict.riskLevel, reasons: verdict.reasons },
          });
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
          const binding = await getHostBindingOrFallback();
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
