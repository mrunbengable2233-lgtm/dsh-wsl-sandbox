import { posix } from 'node:path';
import { isPathInside } from './binding.ts';

/**
 * Checklist A: Zero-token deterministic Bash lexer/AST guard with 8-layer wrapper peeling,
 * dangerous command detection, external path tracking, physical-device detection,
 * and Codex BANNED_PREFIX_SUGGESTIONS enforcement.
 */

export const MAX_GUARD_CHARS = 64 * 1024;
export const MAX_WRAPPER_DEPTH = 8;

export interface GuardEvaluation {
  readonly decision: 'allow' | 'ask' | 'deny';
  readonly riskLevel: 'safe' | 'elevated' | 'high' | 'critical';
  readonly code?: 'POLICY_BLOCK';
  readonly reasons: readonly string[];
  readonly unwrappedCommands: readonly (readonly string[])[];
  readonly touchesPhysicalDevice: boolean;
  readonly requiresSessionRuleBlocked: boolean;
  readonly suggestedPrefix?: readonly string[];
  readonly externalPaths: readonly string[];
}

export const BANNED_PREFIX_SUGGESTIONS: readonly (readonly string[])[] = [
  ['/bin/bash'], ['/bin/bash', '-c'], ['/bin/bash', '-lc'],
  ['/bin/sh'], ['/bin/sh', '-c'], ['/bin/sh', '-lc'],
  ['/bin/zsh'], ['/bin/zsh', '-c'], ['/bin/zsh', '-lc'],
  ['bash'], ['bash', '-c'], ['bash', '-lc'],
  ['sh'], ['sh', '-c'], ['sh', '-lc'],
  ['zsh'], ['zsh', '-c'], ['zsh', '-lc'],
  ['dash'], ['dash', '-c'],
  ['fish'], ['fish', '-c'],
  ['ksh'], ['ash'], ['busybox'],
  ['env'], ['git'], ['eval'], ['exec'], ['sudo'], ['doas'], ['xargs'], ['awk'],
  ['rm'], ['rmdir'], ['chmod'], ['chown'],
  ['bun'], ['bun', '-e'], ['bun', 'run'],
  ['deno'], ['deno', 'eval'],
  ['node', '-e'], ['node', '--eval'],
  ['python', '-c'], ['python3', '-c'],
  ['perl', '-e'], ['ruby', '-e'], ['php', '-r'],
  ['Rscript'], ['julia'], ['julia', '-e'],
  // Windows / PowerShell trampolines & destructive/mutation aliases
  ['cmd'], ['cmd', '/c'], ['cmd', '/k'], ['cmd', '/r'],
  ['cmd.exe'], ['cmd.exe', '/c'], ['cmd.exe', '/k'], ['cmd.exe', '/r'],
  ['pwsh'], ['pwsh.exe'], ['powershell'], ['powershell.exe'],
  ['wsl'], ['wsl.exe'], ['iex'], ['invoke-expression'], ['start-process'], ['saps'],
  ['remove-item'], ['del'], ['erase'], ['rd'],
  ['move'], ['move-item'], ['mv'], ['mi'], ['mklink'], ['robocopy'], ['xcopy'],
];

const SHELL_BINARIES = new Set(['sh', 'bash', 'dash', 'zsh', 'ksh', 'ash', 'fish', 'busybox']);

const SIMPLE_WRAPPERS = new Set([
  'sudo', 'doas', 'command', 'exec', 'nohup', 'nice', 'ionice',
  'time', 'stdbuf', 'setsid', 'runuser', 'xargs',
]);

const WRAPPER_VALUE_FLAGS: Readonly<Record<string, ReadonlySet<string>>> = {
  sudo: new Set(['-u', '-g', '-C', '-D', '-h', '-p', '-r', '-t', '-U']),
  doas: new Set(['-u', '-C']),
  nice: new Set(['-n']),
  ionice: new Set(['-c', '-n', '-p']),
  stdbuf: new Set(['-i', '-o', '-e']),
  runuser: new Set(['-u', '-g', '-s', '-c']),
  timeout: new Set(['-k', '-s', '--kill-after', '--signal']),
  xargs: new Set(['-n', '-L', '-P', '-I', '-d', '-E', '-s']),
};

const POWER_TOOLS = new Set(['shutdown', 'poweroff', 'reboot', 'halt']);
const SYSTEMCTL_POWER_VERBS = new Set([
  'poweroff', 'reboot', 'halt', 'suspend', 'hibernate',
  'hybrid-sleep', 'suspend-then-hibernate', 'kexec', 'soft-reboot',
  'emergency', 'rescue',
]);

const DISK_WIPE_ALWAYS_DENY = new Set(['mkswap', 'wipefs', 'sfdisk', 'gdisk', 'sgdisk', 'blkdiscard', 'shred']);
const DISK_READONLY_ALLOWED = new Set(['fdisk', 'parted']);
const KERNEL_PRIV_TOOLS = new Set([
  'mount', 'umount', 'swapon', 'swapoff', 'chroot', 'pivot_root',
  'nsenter', 'unshare', 'modprobe', 'insmod', 'rmmod',
]);

const BLOCK_DEV_RE = /^\/dev\/(sd|hd|nvme|mmcblk|vd|xvd|disk|mapper|dm-|md|sr|loop|zram|ram)/;
const PHYSICAL_DEV_RE = /^\/dev\/(ttyUSB\d+|ttyACM\d+|ttyS\d+|bus\/usb\/|hidraw\d+|spidev|i2c-)/;

const PHYSICAL_FLASH_TOOLS = new Set([
  'esptool', 'esptool.py', 'openocd', 'avrdude', 'st-flash', 'st-info',
  'dfu-util', 'picotool', 'bossac', 'nrfjprog', 'probe-rs', 'pyocd',
  'minicom', 'picocom', 'tio', 'usbip', 'usbipd',
]);

const CWD_CHANGING_CMDS = new Set(['cd', 'chdir', 'popd', 'pushd', 'push-location', 'set-location']);

const PATH_ARITY: Readonly<Record<string, number>> = {
  cd: 1, chmod: 1, chown: 1, cp: 1, mkdir: 1, mv: 1, rm: 1, rmdir: 1, touch: 1,
  cdk: 2, mvn: 2, terraform: 2,
};

const SENSITIVE_GIT_CONFIG_KEYS = new Set([
  'core.fsmonitor',
  'core.sshcommand',
  'core.hookspath',
  'core.pager',
  'core.editor',
  'credential.helper',
  'diff.external',
]);

const SYSTEM_PROTECTED_PREFIXES = ['/etc/wsl.conf', '/etc/fstab', '/mnt/wslg/distro', '/mnt/wsl', '/run/WSL'];
const WIN_DRIVE_MNT_RE = /^\/mnt\/[a-zA-Z](?:\/|$)/;
const WSL_INTEROP_BINARIES = new Set([
  'wsl.exe', 'cmd.exe', 'powershell.exe', 'pwsh.exe', 'explorer.exe', 'bash.exe', 'wslpath.exe',
]);
const DOWNLOAD_CRADLE_TOOLS = new Set(['curl', 'wget', 'fetch']);

function basenameCmd(token: string): string {
  const idx = token.lastIndexOf('/');
  return idx >= 0 ? token.slice(idx + 1) : token;
}

export function isBannedPrefix(prefix: readonly string[]): boolean {
  if (prefix.length === 0) return true;
  const lowered = prefix.map((t) => t.toLowerCase());
  const firstBase = basenameCmd(lowered[0]!);
  for (const banned of BANNED_PREFIX_SUGGESTIONS) {
    if (banned.length === lowered.length && banned.every((b, i) => b.toLowerCase() === lowered[i])) {
      return true;
    }
    if (banned.length === 1 && banned[0]!.toLowerCase() === firstBase && lowered.length === 1) {
      return true;
    }
    if (
      banned.length === 2 &&
      lowered.length >= 2 &&
      banned[0]!.toLowerCase() === firstBase &&
      banned[1]!.toLowerCase() === lowered[1]
    ) {
      return true;
    }
  }
  return false;
}

interface ParsedSegment {
  readonly tokens: string[];
  readonly redirections: Array<{ op: string; target: string }>;
  readonly pipedToNext: boolean;
}

function normalizeIfs(script: string): string {
  return script.replace(/\$\{IFS\}|\$IFS\b/g, ' ');
}

function extractSubstitutions(script: string): string[] {
  const nested: string[] = [];
  let inSingle = false;
  let inDouble = false;

  for (let i = 0; i < script.length; i++) {
    const ch = script[i]!;
    if (ch === '\\' && !inSingle) {
      i++;
      continue;
    }
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      continue;
    }
    if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      continue;
    }
    if (inSingle) continue;

    // $( ... ) or <( ... ) or >( ... )
    if ((ch === '$' || ch === '<' || ch === '>') && script[i + 1] === '(') {
      let depth = 1;
      let j = i + 2;
      let s = false;
      let d = false;
      while (j < script.length && depth > 0) {
        const c = script[j]!;
        if (c === '\\' && !s) {
          j += 2;
          continue;
        }
        if (c === "'" && !d) s = !s;
        else if (c === '"' && !s) d = !d;
        else if (!s && !d) {
          if (c === '(') depth++;
          else if (c === ')') depth--;
        }
        j++;
      }
      if (depth === 0) {
        const inner = script.slice(i + 2, j - 1).trim();
        if (inner) nested.push(inner);
      }
      i = j - 1;
      continue;
    }

    // Backtick substitution `...`
    if (ch === '`') {
      let j = i + 1;
      while (j < script.length) {
        if (script[j] === '\\') {
          j += 2;
          continue;
        }
        if (script[j] === '`') break;
        j++;
      }
      if (j < script.length) {
        const inner = script.slice(i + 1, j).trim();
        if (inner) nested.push(inner);
        i = j;
      }
    }
  }
  return nested;
}

function tokenizeBashSegments(script: string): ParsedSegment[] {
  const segments: ParsedSegment[] = [];
  let tokens: string[] = [];
  let redirections: Array<{ op: string; target: string }> = [];
  let cur = '';
  let inSingle = false;
  let inDouble = false;
  let pendingRedir: string | null = null;

  const flushToken = (): void => {
    if (cur.length === 0) return;
    if (pendingRedir !== null) {
      redirections.push({ op: pendingRedir, target: cur });
      pendingRedir = null;
    } else {
      tokens.push(cur);
    }
    cur = '';
  };

  const flushSegment = (piped: boolean): void => {
    flushToken();
    if (tokens.length > 0 || redirections.length > 0) {
      segments.push({ tokens, redirections, pipedToNext: piped });
      tokens = [];
      redirections = [];
    }
  };

  for (let i = 0; i < script.length; i++) {
    const ch = script[i]!;
    const next = script[i + 1] ?? '';

    if (inSingle) {
      if (ch === "'") inSingle = false;
      else cur += ch;
      continue;
    }

    if (inDouble) {
      if (ch === '\\' && (next === '"' || next === '\\' || next === '$' || next === '`')) {
        cur += next;
        i++;
      } else if (ch === '"') {
        inDouble = false;
      } else {
        cur += ch;
      }
      continue;
    }

    // Comments outside quotes
    if (ch === '#' && cur.length === 0) {
      while (i < script.length && script[i] !== '\n') i++;
      flushSegment(false);
      continue;
    }

    if (ch === '\\') {
      if (i + 1 < script.length) {
        cur += script[i + 1];
        i++;
      }
      continue;
    }

    if (ch === "'") {
      inSingle = true;
      continue;
    }
    if (ch === '"') {
      inDouble = true;
      continue;
    }

    if (ch === ' ' || ch === '\t' || ch === '\r') {
      flushToken();
      continue;
    }

    if (ch === '\n' || ch === ';') {
      flushSegment(false);
      continue;
    }

    if (ch === '&' && next === '&') {
      flushSegment(false);
      i++;
      continue;
    }
    if (ch === '|' && next === '|') {
      flushSegment(false);
      i++;
      continue;
    }
    if (ch === '|') {
      flushSegment(true);
      continue;
    }
    if (ch === '&') {
      // Check for &> or >&
      if (next === '>') {
        flushToken();
        pendingRedir = '&>';
        i++;
        continue;
      }
      flushSegment(false);
      continue;
    }

    // Redirections (>, >>, >|, <, <<)
    if (ch === '>' || ch === '<') {
      // Allow fd prefix like 2> or 1>>
      if (/^\d+$/.test(cur)) {
        cur = '';
      } else {
        flushToken();
      }
      if (ch === '>' && (next === '>' || next === '|' || next === '&')) {
        pendingRedir = ch + next;
        i++;
      } else if (ch === '<' && (next === '<' || next === '&')) {
        pendingRedir = ch + next;
        i++;
      } else {
        pendingRedir = ch;
      }
      continue;
    }

    // Subshell parens
    if (ch === '(' || ch === ')') {
      flushSegment(false);
      continue;
    }

    cur += ch;
  }

  flushSegment(false);
  return segments;
}

function isForkBomb(script: string): boolean {
  if (/:\s*\(\s*\)\s*\{[^}]*:\s*\|\s*:\s*&[^}]*\}/.test(script)) return true;
  // Generic named recursive background pipe bomb: foo(){ foo|foo& }; foo
  const m = script.match(/\b([A-Za-z_]\w*)\s*\(\s*\)\s*\{([^}]*)\}/);
  if (m && m[1] && m[2]) {
    const fn = m[1];
    const body = m[2];
    const escaped = fn.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    if (new RegExp(`\\b${escaped}\\b.*\\|.*\\b${escaped}\\b.*&`).test(body)) {
      return true;
    }
  }
  return false;
}

export interface BashGuardContext {
  readonly workspaceRoot: string;
  readonly cwd?: string;
  readonly activeDeviceNodes?: readonly string[];
  readonly authorizedDevices?: readonly { readonly path: string }[];
  readonly authorizedShares?: readonly { readonly alias: string }[];
}

export function evaluateBashCommand(command: string, ctx: BashGuardContext): GuardEvaluation {
  const reasons: string[] = [];
  const unwrappedCommands: string[][] = [];
  const externalPaths = new Set<string>();
  let decision: 'allow' | 'ask' | 'deny' = 'allow';
  let riskLevel: 'safe' | 'elevated' | 'high' | 'critical' = 'safe';
  let touchesPhysicalDevice =
    (ctx.activeDeviceNodes?.length ?? 0) > 0 || (ctx.authorizedDevices?.length ?? 0) > 0;
  let trackedCwd = ctx.cwd ?? ctx.workspaceRoot;

  const escalate = (
    nextDecision: 'ask' | 'deny',
    nextRisk: 'elevated' | 'high' | 'critical',
    reason: string,
  ): void => {
    reasons.push(reason);
    if (nextDecision === 'deny') {
      decision = 'deny';
      riskLevel = 'critical';
    } else if (decision !== 'deny') {
      decision = 'ask';
      const order = { safe: 0, elevated: 1, high: 2, critical: 3 };
      if (order[nextRisk] > order[riskLevel]) riskLevel = nextRisk;
    }
  };

  if (typeof command !== 'string' || command.trim().length === 0) {
    return {
      decision: 'deny',
      riskLevel: 'critical',
      code: 'POLICY_BLOCK',
      reasons: ['Empty command'],
      unwrappedCommands: [],
      touchesPhysicalDevice: false,
      requiresSessionRuleBlocked: true,
      externalPaths: [],
    };
  }

  if (command.length > MAX_GUARD_CHARS) {
    return {
      decision: 'deny',
      riskLevel: 'critical',
      code: 'POLICY_BLOCK',
      reasons: [`Command exceeds MAX_GUARD_CHARS (${MAX_GUARD_CHARS})`],
      unwrappedCommands: [],
      touchesPhysicalDevice: false,
      requiresSessionRuleBlocked: true,
      externalPaths: [],
    };
  }

  if (isForkBomb(command)) {
    return {
      decision: 'deny',
      riskLevel: 'critical',
      code: 'POLICY_BLOCK',
      reasons: ['Fork bomb pattern detected'],
      unwrappedCommands: [],
      touchesPhysicalDevice: false,
      requiresSessionRuleBlocked: true,
      externalPaths: [],
    };
  }

  if (/gha-creds-.*\.json/i.test(command)) {
    escalate('deny', 'critical', 'Access to GitHub Actions credential file (gha-creds-*.json) is forbidden');
  }

  const checkPath = (rawPath: string): void => {
    if (!rawPath || rawPath.startsWith('-')) return;
    if (PHYSICAL_DEV_RE.test(rawPath)) {
      touchesPhysicalDevice = true;
      escalate('ask', 'high', `Physical hardware device access detected (${rawPath}); requires manual single-shot approval`);
    }
    if (BLOCK_DEV_RE.test(rawPath)) {
      escalate('deny', 'critical', `Raw block device target is forbidden: ${rawPath}`);
    }
    const resolved = rawPath.startsWith('/')
      ? posix.normalize(rawPath)
      : posix.normalize(posix.join(trackedCwd, rawPath));
    if (WIN_DRIVE_MNT_RE.test(resolved) || resolved === '/mnt') {
      escalate('deny', 'critical', `Direct Windows drive (/mnt) access from WSL sandbox is forbidden: ${resolved}`);
    }
    for (const sysPrefix of SYSTEM_PROTECTED_PREFIXES) {
      if (resolved === sysPrefix || resolved.startsWith(sysPrefix + '/')) {
        escalate('deny', 'critical', `Protected WSL/system path access is forbidden: ${resolved}`);
      }
    }
    if (
      !resolved.startsWith('/tmp/') &&
      resolved !== '/tmp' &&
      resolved !== '/dev/null' &&
      !resolved.startsWith('/shares/') &&
      !isPathInside(ctx.workspaceRoot, resolved)
    ) {
      externalPaths.add(resolved);
    }
  };

  const inspectArgv = (rawTokens: readonly string[], depth: number): void => {
    if (depth > MAX_WRAPPER_DEPTH) {
      escalate('ask', 'high', `Wrapper nesting exceeded MAX_WRAPPER_DEPTH (${MAX_WRAPPER_DEPTH})`);
      return;
    }

    // Strip leading VAR=VALUE assignments
    let idx = 0;
    while (idx < rawTokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(rawTokens[idx]!)) {
      idx++;
    }
    const tokens = rawTokens.slice(idx);
    if (tokens.length === 0) return;

    const head = tokens[0]!;
    const cmd = basenameCmd(head);
    const args = tokens.slice(1);

    // Recursive wrapper peeling: env
    if (cmd === 'env') {
      let i = 0;
      while (i < args.length) {
        const a = args[i]!;
        if (a === '--') {
          i++;
          break;
        }
        if (a === '-i' || a === '--ignore-environment' || a === '-0' || a === '-v') {
          i++;
          continue;
        }
        if (a === '-u' || a === '-C' || a === '-S') {
          i += 2;
          continue;
        }
        if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(a)) {
          i++;
          continue;
        }
        break;
      }
      if (i < args.length) {
        inspectArgv(args.slice(i), depth + 1);
      }
      return;
    }

    // Recursive wrapper peeling: timeout
    if (cmd === 'timeout') {
      let i = 0;
      const valFlags = WRAPPER_VALUE_FLAGS.timeout!;
      while (i < args.length && args[i]!.startsWith('-')) {
        const f = args[i]!;
        if (f === '--') {
          i++;
          break;
        }
        i += valFlags.has(f) ? 2 : 1;
      }
      // Skip duration positional argument
      if (i < args.length) i++;
      if (i < args.length) {
        inspectArgv(args.slice(i), depth + 1);
      }
      return;
    }

    // Recursive wrapper peeling: trap
    if (cmd === 'trap') {
      let i = 0;
      if (args[i] === '--') i++;
      if (i < args.length && !args[i]!.startsWith('-')) {
        inspectScript(args[i]!, depth + 1);
      }
      return;
    }

    // Recursive wrapper peeling: eval
    if (cmd === 'eval') {
      if (args.length > 0) {
        inspectScript(args.join(' '), depth + 1);
      }
      return;
    }

    // Recursive wrapper peeling: nested shells (`bash -c "..."`, `sh -lc "..."`)
    if (SHELL_BINARIES.has(cmd)) {
      for (let i = 0; i < args.length; i++) {
        const a = args[i]!;
        if (/^-[a-zA-Z]*c[a-zA-Z]*$/.test(a) && i + 1 < args.length) {
          inspectScript(args[i + 1]!, depth + 1);
          return;
        }
      }
    }

    // Recursive wrapper peeling: sudo, doas, command, exec, nohup, nice, ionice, time, stdbuf, setsid, runuser, xargs
    if (SIMPLE_WRAPPERS.has(cmd)) {
      if (cmd === 'sudo' || cmd === 'doas' || cmd === 'runuser') {
        escalate('deny', 'critical', `Privilege escalation wrapper is forbidden in sandbox: ${cmd}`);
      }
      let i = 0;
      const valFlags = WRAPPER_VALUE_FLAGS[cmd];
      while (i < args.length && args[i]!.startsWith('-')) {
        const f = args[i]!;
        if (f === '--') {
          i++;
          break;
        }
        i += valFlags?.has(f) ? 2 : 1;
      }
      if (i < args.length) {
        inspectArgv(args.slice(i), depth + 1);
      }
      return;
    }

    // Reached unwrapped command
    unwrappedCommands.push([...tokens]);

    // L0: Block invoking Windows host interop binaries from inside WSL sandbox (Single-Shell Purity)
    if (WSL_INTEROP_BINARIES.has(cmd.toLowerCase())) {
      escalate('deny', 'critical', `Single-shell purity violation: invoking Windows host executable (${cmd}) inside wsl_bash is forbidden`);
    }

    // L0: Pre-Execution POSIX Bash Dialect Alignment — block accidentally pasted PowerShell cmdlets or CMD syntax inside wsl_bash
    if (/^(?:get-childitem|move-item|remove-item|new-item|copy-item|set-content|get-content|invoke-webrequest|invoke-restmethod|invoke-expression|start-process)$/i.test(cmd)) {
      escalate(
        'deny',
        'critical',
        `Shell dialect mismatch inside wsl_bash: PowerShell cmdlet '${cmd}' cannot run in POSIX Bash. Rewrite using native Bash commands (ls, mv, rm, mkdir, cp, curl).`,
      );
    }
    if (
      (cmd === 'rd' || cmd === 'rmdir' || cmd === 'del' || cmd === 'erase') &&
      args.some((a) => /^\/[sqf]$/i.test(a))
    ) {
      escalate(
        'deny',
        'critical',
        `Shell dialect mismatch inside wsl_bash: Windows CMD slash-flags (${cmd} ${args.join(' ')}) detected in POSIX Bash. Use 'rm -rf <target>'.`,
      );
    }
    if (args.some((a) => /^\$env:[A-Za-z_]/i.test(a) || /^%[A-Za-z_][A-Za-z0-9_]*%$/.test(a))) {
      escalate(
        'deny',
        'critical',
        `Shell dialect mismatch inside wsl_bash: Windows '$env:VAR' / '%VAR%' syntax detected in POSIX Bash. Use '$VAR'.`,
      );
    }

    // L0: Scan ALL command arguments for protected WSL escape paths (/mnt/*, /run/WSL, /etc/wsl.conf, /etc/fstab)
    for (const a of args) {
      if (a.startsWith('/')) {
        const norm = posix.normalize(a);
        if (WIN_DRIVE_MNT_RE.test(norm) || norm === '/mnt') {
          escalate('deny', 'critical', `Direct Windows drive (/mnt) access from WSL sandbox is forbidden: ${norm}`);
        }
        for (const sysPrefix of SYSTEM_PROTECTED_PREFIXES) {
          if (norm === sysPrefix || norm.startsWith(sysPrefix + '/')) {
            escalate('deny', 'critical', `Protected WSL/system path access is forbidden: ${norm}`);
          }
        }
      }
    }

    // Check physical hardware tools (Q13 auto-downgrade)
    if (PHYSICAL_FLASH_TOOLS.has(cmd)) {
      touchesPhysicalDevice = true;
      escalate('ask', 'high', `Physical hardware tool detected (${cmd}); requires manual single-shot approval`);
    }
    if (cmd === 'idf.py' && args.some((a) => /^(flash|monitor|erase-flash|efuse|app-flash)$/i.test(a))) {
      touchesPhysicalDevice = true;
      escalate('ask', 'high', `ESP-IDF physical device operation (${cmd} ${args.join(' ')}) requires manual single-shot approval`);
    }
    if ((cmd === 'pio' || cmd === 'platformio') && args.some((a) => a === '--target' || a === 'upload' || a === 'monitor')) {
      touchesPhysicalDevice = true;
      escalate('ask', 'high', `PlatformIO physical device operation requires manual single-shot approval`);
    }
    for (const a of args) {
      if (PHYSICAL_DEV_RE.test(a)) {
        touchesPhysicalDevice = true;
        escalate('ask', 'high', `Physical device path referenced (${a}); requires manual single-shot approval`);
      }
    }

    // L0: Power & kernel mount/privilege tools
    if (POWER_TOOLS.has(cmd)) {
      escalate('deny', 'critical', `System power command is forbidden: ${cmd}`);
    }
    if (cmd === 'systemctl' && args.some((a) => SYSTEMCTL_POWER_VERBS.has(a))) {
      escalate('deny', 'critical', `Dangerous systemctl power action is forbidden`);
    }
    if (KERNEL_PRIV_TOOLS.has(cmd)) {
      escalate('deny', 'critical', `Kernel/mount privilege command is forbidden: ${cmd}`);
    }
    if (cmd === 'sysctl' && args.some((a) => a === '-w' || a === '--write')) {
      escalate('deny', 'critical', 'Kernel parameter write (sysctl -w) is forbidden');
    }

    // L0: Disk formatting & block erasure
    if (DISK_WIPE_ALWAYS_DENY.has(cmd) || /^mkfs(\.\w+)?$/.test(cmd) || /^mke2fs(\.\w+)?$/.test(cmd)) {
      const onlyHelp = args.length > 0 && args.every((a) => a === '-h' || a === '--help' || a === '-V' || a === '--version');
      if (!onlyHelp) {
        escalate('deny', 'critical', `Disk formatting/wiping command is forbidden: ${cmd}`);
      }
    }
    if (DISK_READONLY_ALLOWED.has(cmd)) {
      const readOnly = args.length > 0 && args.every((a) => a === '-l' || a === '--list' || a === '-h' || a === '--help' || a === '-V' || a === '--version');
      if (!readOnly) {
        escalate('deny', 'critical', `Mutating partition tool invocation is forbidden: ${cmd}`);
      }
    }

    // L0: dd / tee / cp / mv / install / truncate targeting raw block devices
    if (cmd === 'dd') {
      for (const a of args) {
        if (a.startsWith('of=')) {
          const target = a.slice(3);
          if (BLOCK_DEV_RE.test(target)) {
            escalate('deny', 'critical', `dd writing to raw block device is forbidden: ${target}`);
          }
          checkPath(target);
        }
      }
    }
    if (cmd === 'tee' || cmd === 'cp' || cmd === 'mv' || cmd === 'install' || cmd === 'truncate') {
      for (const a of args) {
        if (!a.startsWith('-') && BLOCK_DEV_RE.test(a)) {
          escalate('deny', 'critical', `${cmd} targeting raw block device is forbidden: ${a}`);
        }
      }
    }

    // L0 / L3: rm analysis (Codex ForcedRm + dsh-wsl recursive rm + root wipe L0)
    if (cmd === 'rm') {
      let forceOrRecursive = false;
      let afterDoubleDash = false;
      const targets: string[] = [];
      for (const a of args) {
        if (!afterDoubleDash && a === '--') {
          afterDoubleDash = true;
          continue;
        }
        if (!afterDoubleDash && a.startsWith('-')) {
          if (a === '--force' || a === '--recursive') forceOrRecursive = true;
          else if (!a.startsWith('--') && /[frR]/.test(a.slice(1))) forceOrRecursive = true;
        } else {
          targets.push(a);
        }
      }
      for (const t of targets) {
        const resolved = t.startsWith('/') ? posix.normalize(t) : posix.normalize(posix.join(trackedCwd, t));
        if (
          resolved === '/' ||
          resolved === '/mnt' ||
          resolved === '/etc' ||
          resolved === '/usr' ||
          resolved === '/var' ||
          resolved === '/home' ||
          /^\/home\/[^/]+$/.test(resolved)
        ) {
          escalate('deny', 'critical', `Destructive rm targeting root/system/home directory is forbidden: ${resolved}`);
        }
        checkPath(t);
      }
      if (forceOrRecursive) {
        escalate('ask', 'high', `Destructive force/recursive rm requires approval: rm ${args.join(' ')}`);
      }
    }

    // L3: find -delete / -exec rm
    if (cmd === 'find') {
      if (args.includes('-delete')) {
        escalate('ask', 'high', 'find -delete performs destructive deletion and requires approval');
      }
      for (let i = 0; i < args.length; i++) {
        if (args[i] === '-exec' || args[i] === '-execdir') {
          const execTarget = args[i + 1] ? basenameCmd(args[i + 1]!) : '';
          if (execTarget === 'rm' || execTarget === 'sh' || execTarget === 'bash') {
            escalate('ask', 'high', `find ${args[i]} ${execTarget} requires approval`);
          }
        }
      }
    }

    // L3: git dangerous flags & parameters (Gemini CLI + Codex)
    if (cmd === 'git') {
      let subIdx = 0;
      while (subIdx < args.length) {
        const a = args[subIdx]!;
        if (a === '-C' && subIdx + 1 < args.length) {
          const dirArg = args[subIdx + 1]!;
          const resolved = dirArg.startsWith('/') ? posix.normalize(dirArg) : posix.normalize(posix.join(trackedCwd, dirArg));
          if (!isPathInside(ctx.workspaceRoot, resolved)) {
            externalPaths.add(resolved);
            escalate('ask', 'high', `git -C targets directory outside workspace: ${resolved}`);
          }
          subIdx += 2;
          continue;
        }
        if (a.startsWith('--work-tree=') || a.startsWith('--git-dir=')) {
          const dirArg = a.slice(a.indexOf('=') + 1);
          const resolved = dirArg.startsWith('/') ? posix.normalize(dirArg) : posix.normalize(posix.join(trackedCwd, dirArg));
          if (!isPathInside(ctx.workspaceRoot, resolved)) {
            externalPaths.add(resolved);
            escalate('ask', 'high', `git ${a} targets external directory: ${resolved}`);
          }
          subIdx++;
          continue;
        }
        if (a === '--work-tree' || a === '--git-dir' || a === '-c') {
          if (a === '-c' && subIdx + 1 < args.length) {
            const key = args[subIdx + 1]!.split('=')[0]?.toLowerCase() ?? '';
            if (SENSITIVE_GIT_CONFIG_KEYS.has(key)) {
              escalate('ask', 'high', `git -c overriding sensitive config key (${key}) requires approval`);
            }
          }
          subIdx += 2;
          continue;
        }
        if (a.startsWith('-')) {
          subIdx++;
          continue;
        }
        break;
      }

      const sub = args[subIdx];
      const subArgs = args.slice(subIdx + 1);
      if (sub === 'clean') {
        const dryRun = subArgs.some((a) => a === '-n' || a === '--dry-run');
        const destructive = subArgs.some((a) => a === '--force' || (/^-[^-]*[fdDxX]/.test(a)));
        if (destructive && !dryRun) {
          escalate('ask', 'high', 'git clean with force/delete flags requires approval');
        }
      } else if (sub === 'reset' && subArgs.includes('--hard')) {
        escalate('ask', 'high', 'git reset --hard discards uncommitted work and requires approval');
      } else if (sub === 'checkout' && subArgs.includes('--') && subArgs.includes('.')) {
        escalate('ask', 'high', 'git checkout -- . discards working tree changes and requires approval');
      } else if (sub === 'push' && subArgs.some((a) => a === '-f' || a === '--force' || a.startsWith('--force-with-lease'))) {
        escalate('ask', 'high', 'git push --force requires approval');
      } else if (sub === 'config') {
        const lowerArgs = subArgs.map((a) => a.toLowerCase());
        const touchesSensitive = lowerArgs.some((a) => SENSITIVE_GIT_CONFIG_KEYS.has(a));
        const isGlobal = lowerArgs.includes('--global') || lowerArgs.includes('--system');
        if (touchesSensitive || isGlobal) {
          escalate('ask', 'high', 'Modifying sensitive or global git config requires approval');
        }
      }
    }

    // Track CWD changes and extract path arguments (OpenCode arity rules)
    if (CWD_CHANGING_CMDS.has(cmd)) {
      const target = args.find((a) => !a.startsWith('-'));
      if (target) {
        const nextCwd = target.startsWith('/') ? posix.normalize(target) : posix.normalize(posix.join(trackedCwd, target));
        checkPath(nextCwd);
        trackedCwd = nextCwd;
      }
    } else if (PATH_ARITY[cmd] !== undefined) {
      const arity = PATH_ARITY[cmd]!;
      const positionals = args.filter((a) => !a.startsWith('-'));
      for (const p of positionals.slice(arity - 1)) {
        checkPath(p);
      }
    }
  };

  const inspectScript = (rawScript: string, depth: number): void => {
    if (depth > MAX_WRAPPER_DEPTH) {
      escalate('ask', 'high', `Script substitution nesting exceeded MAX_WRAPPER_DEPTH (${MAX_WRAPPER_DEPTH})`);
      return;
    }
    const normalized = normalizeIfs(rawScript);

    // Inspect command/process substitutions recursively
    for (const nested of extractSubstitutions(normalized)) {
      inspectScript(nested, depth + 1);
    }

    const segments = tokenizeBashSegments(normalized);
    for (let i = 0; i < segments.length; i++) {
      const seg = segments[i]!;
      // Check redirection targets
      for (const redir of seg.redirections) {
        if (redir.op.startsWith('>')) {
          checkPath(redir.target);
        }
      }
      // Detect dangerous `curl/wget ... | sh/bash` pipe-to-shell patterns
      if (seg.pipedToNext && i + 1 < segments.length) {
        const curHead = seg.tokens[0];
        const curCmd = curHead ? basenameCmd(curHead) : '';
        const nextHead = segments[i + 1]!.tokens[0];
        const nextCmd = nextHead ? basenameCmd(nextHead) : '';
        if (SHELL_BINARIES.has(nextCmd)) {
          if (DOWNLOAD_CRADLE_TOOLS.has(curCmd)) {
            escalate('deny', 'critical', `Remote download piped directly into shell (${curCmd} | ${nextCmd}) is forbidden`);
          } else {
            escalate('ask', 'high', `Piping stream directly into shell (${nextCmd}) requires approval`);
          }
        }
      }
      inspectArgv(seg.tokens, depth);
    }
  };

  inspectScript(command, 0);

  if (externalPaths.size > 0 && decision === 'allow') {
    escalate('ask', 'elevated', `Command references path(s) outside workspaceRoot: ${Array.from(externalPaths).join(', ')}`);
  }

  const firstUnwrapped = unwrappedCommands[0];
  let suggestedPrefix: string[] | undefined;
  let requiresSessionRuleBlocked = touchesPhysicalDevice || decision === 'deny';

  if (firstUnwrapped && firstUnwrapped.length > 0 && !requiresSessionRuleBlocked) {
    const candidate = firstUnwrapped.slice(0, Math.min(2, firstUnwrapped.length));
    if (isBannedPrefix(candidate) || isBannedPrefix([firstUnwrapped[0]!])) {
      requiresSessionRuleBlocked = true;
    } else {
      suggestedPrefix = candidate;
    }
  }

  return {
    decision,
    riskLevel,
    code: decision === 'deny' ? 'POLICY_BLOCK' : undefined,
    reasons,
    unwrappedCommands,
    touchesPhysicalDevice,
    requiresSessionRuleBlocked,
    suggestedPrefix,
    externalPaths: Array.from(externalPaths),
  };
}
