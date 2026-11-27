import {
  deobfuscatePowerShell,
  evaluateBashCommand,
  evaluatePwshCommand,
  evaluatePwshCommandWithSystemAst,
  extractBashNonProseTargets,
  failSandbox,
  type GuardEvaluation,
  isSandboxError,
  type SessionBinding,
  splitCompoundWindowsCommands,
} from '../../core/src/index.ts';
import type { ApprovalBridge } from './approval-bridge.ts';
import type { WslSandboxConfig } from './config-store.ts';
import {
  type DshCordisContext,
  type DshPreToolDecision,
  type DshToolPreExecutePayload,
  subscribeCordisWaterfall,
} from './cordis-types.ts';
import type { BootstrapChannelState } from './tools.ts';

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

export type HostShellKind = 'none' | 'pwsh-dialect' | 'host-posix-bash';

export function classifyHostShellTool(toolName: string): HostShellKind {
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

export function isHostWindowsShellTool(toolName: string): boolean {
  return classifyHostShellTool(toolName) !== 'none';
}

function extractShellCommand(input: unknown): string | undefined {
  if (!input || typeof input !== 'object') return undefined;
  const rec = input as Record<string, unknown>;
  for (const key of ['command', 'script', 'cmd', 'code', 'input']) {
    const val = rec[key];
    if (typeof val === 'string' && val.trim().length > 0) {
      return val;
    }
  }
  if (Array.isArray(rec.argv) && rec.argv.every((x) => typeof x === 'string')) {
    return (rec.argv as string[]).join(' ');
  }
  return undefined;
}

const HOST_WSL_UNC_RE = /(?:\\\\|\/\/)(?:[?.][\\/]unc[\\/])?wsl(?:\$|\.localhost)(?:[\\/]|$)/i;
const HOST_WSL_CONFIG_RE = /(?:^|[\\/])(?:\.wslconfig|etc[\\/]wsl\.conf|etc[\\/]fstab)$/i;

/**
 * Evaluates a host POSIX Bash tool (`win_bash` / `ops_bash`) using POSIX Bash AST parsing +
 * host-side WSL escape & physical USBIP checks (never PowerShell syntax linting!).
 */
export function evaluateHostPosixBashOnWindows(command: string): GuardEvaluation {
  const base = evaluateBashCommand(command, { workspaceRoot: '/host-workspace' });
  const targets = extractBashNonProseTargets(command);

  const reasons = [...base.reasons];
  let decision: 'allow' | 'ask' | 'deny' = base.decision;
  let riskLevel: 'safe' | 'elevated' | 'high' | 'critical' = base.riskLevel;
  let touchesPhysicalDevice = base.touchesPhysicalDevice;
  let requiresSessionRuleBlocked = base.requiresSessionRuleBlocked;

  const escalate = (
    nextDecision: 'ask' | 'deny',
    nextRisk: 'elevated' | 'high' | 'critical',
    reason: string,
  ): void => {
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
        const a = args[i]!.toLowerCase();
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

export interface BootstrapGateEvaluation {
  readonly verdict: GuardEvaluation;
  readonly bootstrapAction: 'none' | 'probe' | 'preview' | 'install' | 'terminate' | 'uninstall-dry-run';
  readonly detectedDistro?: string;
}

const INSTALL_PS1_RE = /(?:^|[\\/\s"'])(?:install-dsh-plugin\.ps1)(?=$|[\s"'])/i;
const UNINSTALL_PS1_RE = /(?:^|[\\/\s"'])(?:uninstall-dsh-plugin\.ps1)(?=$|[\s"'])/i;
const STAGE_MJS_RE = /(?:^|[\\/\s"'])(?:stage-wsl-runner\.mjs)(?=$|[\s"'])/i;
const PROVISION_SH_RE = /(?:^|[\\/\s"'])(?:provision-wsl\.sh)(?=$|[\s"'])/i;
const READONLY_TEXT_HEADS = new Set([
  'rg', 'grep', 'egrep', 'fgrep', 'findstr', 'select-string', 'sls',
  'git', 'get-content', 'gc', 'cat', 'type', 'test-path', 'get-item',
  'resolve-path', 'split-path', 'select-object', 'format-table',
  'echo', 'write-output', 'write-host',
]);

function stripQuotedTextForStructureCheck(cmd: string): string {
  let out = '';
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i]!;
    if (!inDouble && ch === "'") {
      if (inSingle && cmd[i + 1] === "'") {
        i++;
        continue;
      }
      inSingle = !inSingle;
      out += ' ';
      continue;
    }
    if (!inSingle && ch === '"') {
      if (inDouble && cmd[i + 1] === '"') {
        i++;
        continue;
      }
      inDouble = !inDouble;
      out += ' ';
      continue;
    }
    if (inDouble && ch === '`' && i + 1 < cmd.length) {
      i++;
      continue;
    }
    if (inSingle || inDouble) continue;
    out += ch;
  }
  return out;
}

function hasUnsafeBootstrapStructure(cleanCmd: string): boolean {
  if (splitCompoundWindowsCommands(cleanCmd).length !== 1) return true;
  const unquoted = stripQuotedTextForStructureCheck(cleanCmd)
    .trimStart()
    .replace(/^(?:&|\.)\s+/, '');
  return /[;|]|&&|\|\||\$\(|`|>/.test(unquoted);
}

function collectCommandTokens(command: string, baseVerdict: GuardEvaluation): string[] {
  const tokens: string[] = [];
  for (const argv of baseVerdict.unwrappedCommands) {
    for (const t of argv) {
      tokens.push(t);
    }
  }
  if (tokens.length > 0) return tokens;
  const clean = deobfuscatePowerShell(command).trim();
  const re = /'([^']*)'|"([^"]*)"|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(clean)) !== null) {
    tokens.push((m[1] ?? m[2] ?? m[3] ?? '').trim());
  }
  return tokens;
}

function extractTargetDistroFromTokens(tokens: readonly string[]): string | undefined {
  for (let i = 0; i < tokens.length; i++) {
    const raw = tokens[i]!;
    const lower = raw.toLowerCase();
    if (
      lower === '-distro' ||
      lower === '--distro' ||
      lower === '-d' ||
      lower === '--distribution' ||
      lower === '--terminate' ||
      lower === '-t'
    ) {
      const next = tokens[i + 1];
      if (next && !next.startsWith('-')) return next;
    }
    const eq = raw.match(/^(?:-distro|--distro|--distribution|--terminate)[:=](.+)$/i);
    if (eq?.[1]) return eq[1].replace(/^['"]|['"]$/g, '');
  }
  // `wsl.exe --install Ubuntu-26.04` 位置参数写法
  const installIdx = tokens.findIndex((t) => t.toLowerCase() === '--install');
  if (installIdx !== -1) {
    const cand = tokens[installIdx + 1];
    if (cand && !cand.startsWith('-')) return cand;
  }
  return undefined;
}

/**
 * 宿主机受控 AI 初始化引导与卸载脚本顺序门禁（独立于核心 Guard 之外叠加执行，不影响 246 条红队矩阵）：
 * 1. 非 `-DryRun`/`--dry-run` 的 `uninstall-dsh-plugin.ps1` 与 `provision-wsl.sh --uninstall` 永远 L0 deny；
 * 2. 引导通道关闭态下（`!bootstrap?.active`），AI 调用 `install-dsh-plugin.ps1` / `stage-wsl-runner.mjs` / `provision-wsl.sh` 一律 L0 deny；
 * 3. 引导通道开启态下（`bootstrap.active === true`），必须严格按「只读探测 -> -DryRun/--dry-run 预览（L3 ask 解锁）-> 分步单次审批安装（L3 ask）」顺序执行，
 *    未完成 `-DryRun` 预览前任何真实安装/部署/`wsl --install`/单发行版 `--terminate` 均被 L0 机械拦截，且禁止跨发行版或拼接注入。
 */
export function evaluateBootstrapCommandGate(
  command: string,
  baseVerdict: GuardEvaluation,
  bootstrap?: BootstrapChannelState | null,
): BootstrapGateEvaluation {
  const cleanCmd = deobfuscatePowerShell(command);
  const tokens = collectCommandTokens(command, baseVerdict);
  const headBase = (tokens[0] ?? '').replace(/^.*[/\\]/, '').toLowerCase();

  // 对纯粹的只读文本检查命令（非 `pwsh`/`bash`/`wsl`/`iex` 执行体），直接沿用基础判决
  const hasAnyExecHead = baseVerdict.unwrappedCommands.some((argv) => {
    const b = (argv[0] ?? '').replace(/^.*[/\\]/, '').toLowerCase();
    return !READONLY_TEXT_HEADS.has(b);
  });

  const mentionsInstallPs1 = INSTALL_PS1_RE.test(cleanCmd) || tokens.some((t) => INSTALL_PS1_RE.test(t));
  const mentionsUninstallPs1 = UNINSTALL_PS1_RE.test(cleanCmd) || tokens.some((t) => UNINSTALL_PS1_RE.test(t));
  const mentionsStageMjs = STAGE_MJS_RE.test(cleanCmd) || tokens.some((t) => STAGE_MJS_RE.test(t));
  const mentionsProvisionSh = PROVISION_SH_RE.test(cleanCmd) || tokens.some((t) => PROVISION_SH_RE.test(t));
  const mentionsAnyScript = mentionsInstallPs1 || mentionsUninstallPs1 || mentionsStageMjs || mentionsProvisionSh;

  const isWslBin = headBase === 'wsl' || headBase === 'wsl.exe' || headBase === 'bash.exe';

  const makeVerdict = (
    decision: 'allow' | 'ask' | 'deny',
    riskLevel: 'safe' | 'elevated' | 'high' | 'critical',
    reason: string,
    requiresSessionRuleBlocked = true,
  ): GuardEvaluation => ({
    ...baseVerdict,
    decision,
    riskLevel,
    code: decision === 'deny' ? 'POLICY_BLOCK' : undefined,
    reasons: [reason, ...baseVerdict.reasons.filter((r) => r !== reason)],
    requiresSessionRuleBlocked,
    suggestedPrefix: requiresSessionRuleBlocked ? undefined : baseVerdict.suggestedPrefix,
  });

  if (!hasAnyExecHead && baseVerdict.unwrappedCommands.length > 0 && !mentionsUninstallPs1) {
    return { verdict: baseVerdict, bootstrapAction: 'none' };
  }

  const lowerTokens = tokens.map((t) => t.toLowerCase());
  const hasPsDryRun = lowerTokens.some((t) => /^-dryrun(?::\$?true)?$/.test(t));
  const hasPosixDryRun = lowerTokens.includes('--dry-run');
  const isDryRun = hasPsDryRun || hasPosixDryRun;

  // 1. 卸载与危险还原脚本硬门禁
  const isProvisionDestructiveAction =
    mentionsProvisionSh &&
    lowerTokens.some((t) =>
      t === '--uninstall' ||
      t === '--purge-toolchains' ||
      t === '--restore-configs' ||
      t === '--disable-automount',
    );
  const isInstallScriptDestructiveAction =
    mentionsInstallPs1 &&
    lowerTokens.some((t) =>
      t === '-restorewslconfig' ||
      t === '-unregisterplugindistro' ||
      t === '-purgetoolchains' ||
      t === '-registerdshplugin',
    );

  if (mentionsUninstallPs1 || isProvisionDestructiveAction || isInstallScriptDestructiveAction) {
    if (isDryRun && !hasUnsafeBootstrapStructure(cleanCmd) && baseVerdict.decision !== 'deny' && !isInstallScriptDestructiveAction) {
      return {
        verdict: makeVerdict(
          'ask',
          'high',
          '允许对卸载/配置恢复脚本仅执行 Dry-Run 只读预览（仍需人类单次审批）',
          true,
        ),
        bootstrapAction: 'uninstall-dry-run',
      };
    }
    return {
      verdict: makeVerdict(
        'deny',
        'critical',
        'L0 策略拦截：严禁由 AI 模型直接执行卸载插件、清空工具链、修改或还原系统 WSL 配置等高危运维命令（只允许人类在终端手动操作）。',
        true,
      ),
      bootstrapAction: 'none',
    };
  }

  // 2. 安装 / 原生 ext4 部署 / provision-wsl.sh 脚本通道门禁
  if (mentionsInstallPs1 || mentionsStageMjs || mentionsProvisionSh) {
    if (baseVerdict.decision === 'deny') {
      return { verdict: baseVerdict, bootstrapAction: 'none' };
    }
    if (!bootstrap?.active) {
      return {
        verdict: makeVerdict(
          'deny',
          'critical',
          '受控 AI 初始化引导通道未开启：禁止在未授权状态下直接运行 install-dsh-plugin.ps1 / stage-wsl-runner.mjs / provision-wsl.sh。请在 DSH「设置 -> WSL 2 沙箱」中先预览脚本与 SHA-256 并点击开启引导通道，或由人类自己在终端运行。',
          true,
        ),
        bootstrapAction: 'none',
      };
    }
    if (hasUnsafeBootstrapStructure(cleanCmd)) {
      return {
        verdict: makeVerdict(
          'deny',
          'critical',
          '受控引导通道门禁：禁止在安装命令中使用分号、管道、&&/||、$() 子表达式或输出重定向拼接其他指令，必须逐条独立申请审批。',
          true,
        ),
        bootstrapAction: 'none',
      };
    }
    if (
      lowerTokens.some((t) =>
        ['--shutdown', '--unregister', '--import', '--mount', '--set-default', '--user=root'].includes(t),
      ) ||
      /(?:^|\s)(?:-u|--user)\s+root(?:\s|$)/i.test(cleanCmd)
    ) {
      return {
        verdict: makeVerdict(
          'deny',
          'critical',
          '受控引导通道门禁：禁止使用 --shutdown / --unregister / --import / --mount / root 身份等危险参数。',
          true,
        ),
        bootstrapAction: 'none',
      };
    }

    const explicitDistro = extractTargetDistroFromTokens(tokens);
    if (
      bootstrap.targetDistro &&
      explicitDistro &&
      explicitDistro.toLowerCase() !== bootstrap.targetDistro.toLowerCase()
    ) {
      return {
        verdict: makeVerdict(
          'deny',
          'critical',
          `目标发行版不匹配：受控引导通道当前仅授权操作「${bootstrap.targetDistro}」，禁止操作其他 WSL 发行版「${explicitDistro}」。`,
          true,
        ),
        bootstrapAction: 'none',
      };
    }

    const expectedDryRun = mentionsInstallPs1 ? hasPsDryRun : hasPosixDryRun;
    if (expectedDryRun) {
      return {
        verdict: makeVerdict(
          'ask',
          'elevated',
          '受控初始化【步骤 2/4 预览】：执行 Dry-Run 预演安装脚本与 SHA-256 计划，不改写系统配置，需人工批准后解锁安装。',
          true,
        ),
        bootstrapAction: 'preview',
        detectedDistro: explicitDistro ?? bootstrap.targetDistro,
      };
    }

    if (!bootstrap.previewedDryRun) {
      return {
        verdict: makeVerdict(
          'deny',
          'critical',
          '顺序门禁拦截：必须先执行一次带 -DryRun / --dry-run 的预览命令并经人工确认通过后，才能申请真实安装或部署执行（禁止跳过步骤 2）。',
          true,
        ),
        bootstrapAction: 'none',
      };
    }

    if ((mentionsInstallPs1 || mentionsStageMjs) && bootstrap.targetDistro && !explicitDistro) {
      return {
        verdict: makeVerdict(
          'deny',
          'high',
          `受控引导通道已锁定目标发行版「${bootstrap.targetDistro}」，执行真实安装或部署时必须显式指定 -Distro / --distro "${bootstrap.targetDistro}"。`,
          true,
        ),
        bootstrapAction: 'none',
      };
    }

    return {
      verdict: makeVerdict(
        'ask',
        'high',
        `受控初始化【步骤 3/4 安装】：已完成 Dry-Run 预览，本次真实安装/部署「${explicitDistro ?? bootstrap.targetDistro ?? 'target'}」强制人工单次审批（allow-once）。`,
        true,
      ),
      bootstrapAction: 'install',
      detectedDistro: explicitDistro ?? bootstrap.targetDistro,
    };
  }

  // 3. 受控引导通道开启态下的 standalone `wsl.exe` / `bash.exe` 命令约束
  if (!mentionsAnyScript && isWslBin && bootstrap?.active) {
    if (hasUnsafeBootstrapStructure(cleanCmd)) {
      return {
        verdict: makeVerdict(
          'deny',
          'critical',
          '受控引导通道门禁：禁止对 wsl.exe 命令使用复合拼接、管道或重定向。',
          true,
        ),
        bootstrapAction: 'none',
      };
    }

    const hasAlwaysForbiddenWslFlag =
      lowerTokens.some((t) => ['--shutdown', '--unregister', '--import', '--mount', '--set-default', '--user=root'].includes(t)) ||
      /(?:^|\s)(?:-u|--user)\s+root(?:\s|$)/i.test(cleanCmd);
    if (hasAlwaysForbiddenWslFlag) {
      return { verdict: baseVerdict, bootstrapAction: 'none' };
    }

    const explicitDistro = extractTargetDistroFromTokens(tokens);
    if (
      bootstrap.targetDistro &&
      explicitDistro &&
      explicitDistro.toLowerCase() !== bootstrap.targetDistro.toLowerCase()
    ) {
      return {
        verdict: makeVerdict(
          'deny',
          'critical',
          `目标发行版不匹配：引导通道已锁定「${bootstrap.targetDistro}」，禁止探测或修改「${explicitDistro}」。`,
          true,
        ),
        bootstrapAction: 'none',
      };
    }

    const isTerminate = lowerTokens.includes('--terminate') || lowerTokens.includes('-t');
    if (isTerminate) {
      if (!explicitDistro || (bootstrap.targetDistro && explicitDistro.toLowerCase() !== bootstrap.targetDistro.toLowerCase())) {
        return { verdict: baseVerdict, bootstrapAction: 'none' };
      }
      if (!bootstrap.previewedDryRun) {
        return {
          verdict: makeVerdict(
            'deny',
            'critical',
            '顺序门禁拦截：完成 Dry-Run 预览前禁止调用单发行版 wsl --terminate。',
            true,
          ),
          bootstrapAction: 'none',
        };
      }
      return {
        verdict: makeVerdict(
          'ask',
          'high',
          `受控初始化：仅重启目标 WSL 发行版「${explicitDistro}」（wsl.exe --terminate，不影响其他发行版，需人工单次确认）。`,
          true,
        ),
        bootstrapAction: 'terminate',
        detectedDistro: explicitDistro,
      };
    }

    if (lowerTokens.includes('--install')) {
      if (!bootstrap.previewedDryRun) {
        return {
          verdict: makeVerdict(
            'deny',
            'critical',
            '顺序门禁拦截：必须先完成 install-dsh-plugin.ps1 -DryRun 预览，才可申请 wsl.exe --install 安装发行版。',
            true,
          ),
          bootstrapAction: 'none',
        };
      }
      return {
        verdict: makeVerdict(
          'ask',
          'high',
          `受控初始化：安装全新 WSL 2 发行版「${explicitDistro ?? bootstrap.targetDistro ?? ''}」（需人工单次审批）。`,
          true,
        ),
        bootstrapAction: 'install',
        detectedDistro: explicitDistro ?? bootstrap.targetDistro,
      };
    }

    return {
      verdict: makeVerdict(
        'ask',
        'elevated',
        '受控初始化【步骤 1/4 只读探测】：通过 wsl.exe 查询发行版状态或基础环境（需人工单次审批）。',
        true,
      ),
      bootstrapAction: 'probe',
      detectedDistro: explicitDistro ?? bootstrap.targetDistro,
    };
  }

  return { verdict: baseVerdict, bootstrapAction: 'none' };
}

function evaluateByKind(
  kind: HostShellKind,
  command: string,
  bootstrap?: BootstrapChannelState | null,
): BootstrapGateEvaluation | undefined {
  let base: GuardEvaluation | undefined;
  if (kind === 'pwsh-dialect') {
    base = evaluatePwshCommand(command);
  } else if (kind === 'host-posix-bash') {
    base = evaluateHostPosixBashOnWindows(command);
  }
  if (!base) return undefined;
  return evaluateBootstrapCommandGate(command, base, bootstrap);
}

async function evaluateByKindAsync(
  kind: HostShellKind,
  command: string,
  bootstrap?: BootstrapChannelState | null,
): Promise<BootstrapGateEvaluation | undefined> {
  let base: GuardEvaluation | undefined;
  if (kind === 'pwsh-dialect') {
    base = await evaluatePwshCommandWithSystemAst(command);
  } else if (kind === 'host-posix-bash') {
    base = evaluateHostPosixBashOnWindows(command);
  }
  if (!base) return undefined;
  return evaluateBootstrapCommandGate(command, base, bootstrap);
}

function createHostFallbackBinding(cfg: WslSandboxConfig): SessionBinding {
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

export interface PwshHookOptions {
  readonly getConfig: () => WslSandboxConfig;
  readonly getBinding: () => SessionBinding | undefined | Promise<SessionBinding | undefined>;
  readonly getBootstrapState?: () => BootstrapChannelState;
  readonly onBootstrapPreviewExecuted?: (distro?: string) => void;
  readonly onBootstrapInstallExecuted?: () => void;
  readonly approvalBridge: ApprovalBridge;
  readonly logger?: import('../../core/src/index.ts').StructuredLogger;
}

function commandTouchesBootstrapOrUninstall(command: string): boolean {
  const clean = deobfuscatePowerShell(command);
  return (
    INSTALL_PS1_RE.test(clean) ||
    UNINSTALL_PS1_RE.test(clean) ||
    STAGE_MJS_RE.test(clean) ||
    PROVISION_SH_RE.test(clean)
  );
}

/**
 * Registers BOTH:
 *  1. Monotonic `ctx.tools.guard(...)` (real `@deepseek-ai/dsh-tools@0.2.2-rc.5`): enforces L0 destructive,
 *     Single-Shell Purity, Pre-Execution Shell Dialect, and Controlled Bootstrap Channel order denials
 *     AFTER all `tools/pre-execute` listeners (mathematically unbypassable by `dsh-purge`).
 *  2. Polite `tools/pre-execute` waterfall listener: handles L0 denials and routes L3 / `usbipd` / bootstrap
 *     single-shot requests through `ApprovalBridge` while delegating all other tools cleanly via `next()`.
 */
export function registerHostPwshGuardHook(
  ctx: DshCordisContext,
  options: PwshHookOptions,
): (() => void) | undefined {
  const disposers: Array<() => void> = [];
  let cachedFallbackBinding: SessionBinding | undefined;

  const getHostBindingOrFallback = async (): Promise<SessionBinding> => {
    try {
      const active = await options.getBinding();
      if (active) return active;
    } catch {
      // Fall through to bridge binding / cached fallback binding
    }
    const cfg = options.getConfig();
    const bridgeBinding = options.approvalBridge.getBinding();
    if (bridgeBinding && bridgeBinding.revision === cfg.revision) {
      return bridgeBinding;
    }
    if (!cachedFallbackBinding || cachedFallbackBinding.revision !== cfg.revision) {
      cachedFallbackBinding = createHostFallbackBinding(cfg);
    }
    return cachedFallbackBinding;
  };

  // 1. Monotonic `ctx.tools.guard` for L0 + Single-Shell Purity + Dialect Alignment + Bootstrap Order Gate
  if (ctx.tools?.guard) {
    const guardDispose = ctx.tools.guard((exec) => {
      const cfg = options.getConfig();
      if (!cfg.enablePwshGuard) return undefined;
      const toolName = String(exec?.name ?? '');
      const kind = classifyHostShellTool(toolName);
      if (kind === 'none') return undefined;
      const command = extractShellCommand(exec?.arguments);
      if (!command) return undefined;

      const bootstrap = options.getBootstrapState?.();
      if (!cfg.enabled && !bootstrap?.active && !commandTouchesBootstrapOrUninstall(command)) {
        return undefined;
      }

      const gated = evaluateByKind(kind, command, bootstrap);
      const verdict = gated?.verdict;
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

  // 2. 礼貌订阅 `tools/pre-execute` 瀑布流监听（通过 Cordis `ctx.on` 安全挂载）
  const wfDispose = subscribeCordisWaterfall<DshToolPreExecutePayload, unknown>(
    ctx,
    'tools/pre-execute',
    async (payload, next) => {
        const passThrough = () =>
          typeof next === 'function' ? next() : ({ kind: 'allow' } satisfies DshPreToolDecision);

        const cfg = options.getConfig();
        if (!cfg.enablePwshGuard || !payload) {
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

        const bootstrap = options.getBootstrapState?.();
        if (!cfg.enabled && !bootstrap?.active && !commandTouchesBootstrapOrUninstall(command)) {
          return passThrough();
        }

        const gated = await evaluateByKindAsync(kind, command, bootstrap);
        const verdict = gated?.verdict;
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
            } satisfies DshPreToolDecision;
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
                : gated?.bootstrapAction === 'preview'
                  ? `[Bootstrap Preview] 预览安装脚本 (-DryRun) via ${toolName}`
                  : gated?.bootstrapAction === 'install'
                    ? `[Bootstrap Install] 受控单次安装/部署 via ${toolName}`
                    : gated?.bootstrapAction === 'terminate'
                      ? `[Bootstrap Terminate] 仅重启目标发行版 (${gated.detectedDistro ?? ''}) via ${toolName}`
                      : `Host Windows shell command via ${toolName}`,
              command,
              canonicalArgv: verdict.unwrappedCommands[0],
              reasons: verdict.reasons,
              touchesPhysicalDevice: verdict.touchesPhysicalDevice,
              suggestedPrefix: verdict.requiresSessionRuleBlocked ? undefined : verdict.suggestedPrefix,
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
          const out = await passThrough();
          if (gated?.bootstrapAction === 'preview') {
            options.onBootstrapPreviewExecuted?.(gated.detectedDistro);
          } else if (gated?.bootstrapAction === 'install') {
            options.onBootstrapInstallExecuted?.();
          }
          return out;
        } catch (err) {
          if (isRealDshExec && isSandboxError(err)) {
            return {
              kind: 'deny',
              reason: err.message,
              info: { name: 'SandboxError', code: err.code },
            } satisfies DshPreToolDecision;
          }
          throw err;
        }
      },
    );
  if (typeof wfDispose === 'function') {
    disposers.push(() => void wfDispose());
  }

  if (disposers.length === 0) return undefined;
  return () => {
    for (const d of disposers.splice(0)) {
      d();
    }
  };
}
