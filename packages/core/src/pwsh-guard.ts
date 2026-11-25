import { type GuardEvaluation, isBannedPrefix, MAX_GUARD_CHARS, MAX_WRAPPER_DEPTH } from './bash-ast-guard.ts';

/**
 * Complete Zero-Token Windows PowerShell Guard with:
 *  1. Single-Shell Purity Enforcement (forbids nested `cmd`/`cmd.exe`/`%COMSPEC%` inside PowerShell
 *     and forbids mixing `pwsh.exe` <-> `powershell.exe` or multi-statement subshell nesting).
 *  2. Pre-Execution Shell Dialect Alignment (catches CMD slash-flags like `rmdir /s /q` / `del /f /q`
 *     that PowerShell misinterprets as `C:\s` & `C:\q`, blocks `2>nul` DOS reserved-file creation,
 *     blocks `%VAR%` unexpanded CMD env vars, blocks WinPS 5.1 `&&` syntax errors, and blocks
 *     interactive hang traps like `cmd /k`, `-NoExit`, `-Command -`, `Read-Host`, `pause`).
 *  3. Reverse UNC WSL Sandbox Escape Prevention (`\\wsl$\` / `\\wsl.localhost\` -> L0 POLICY_BLOCK).
 *  4. Physical Hardware Mandatory Single-Shot Downgrade (`usbipd` / `esptool` -> manual `allow-once`).
 */

const PWSH_ENCODED_FLAG_RE = /(?:^|\s)-(?:e|ec|enc|encoded|encodedcommand)\s+(['"]?)([A-Za-z0-9+/=]{8,})\1/gi;

/** Reverse UNC share into WSL rootfs from Windows host — bypasses bwrap read-only mounts if allowed! */
const WSL_UNC_PATH_RE = /(?:\\\\|\/\/)wsl(?:\$|\.localhost)(?:\\|\/)/i;

/** Matches cmd / cmd.exe / %COMSPEC% / $env:ComSpec / System32\cmd.exe */
const CMD_BINARY_RE =
  /(?:^|[\s;|&('"\\])(?:cmd(?:\.exe)?|%comspec%|\$env:comspec)(?=$|[\s;|&)'"\/])/i;

const L0_SINGLE_SHELL_AND_DIALECT_RULES: ReadonlyArray<{ re: RegExp; reason: string }> = [
  // 1. Single-Shell Purity: NEVER allow PowerShell to spawn or pipe into CMD
  {
    re: CMD_BINARY_RE,
    reason:
      'Single-shell purity violation: invoking nested cmd/cmd.exe/%COMSPEC% inside PowerShell is forbidden (causes quote/encoding corruption and hangs). Use wsl_bash inside WSL 2 for file/build tasks, or write pure single-shell PowerShell.',
  },
  // 2. Single-Shell Purity: NEVER allow `--%` stop-parsing smuggling
  {
    re: /(?:^|\s)--%(?:\s|$)/,
    reason:
      'Single-shell purity violation: PowerShell stop-parsing token (--%) is forbidden. Use pure PowerShell syntax or wsl_bash.',
  },
  // 3. Single-Shell Purity: NEVER mix pwsh.exe (PS 7) and powershell.exe (WinPS 5.1) in one command
  {
    re: /\bpwsh(?:\.exe)?\b[\s\S]*\bpowershell(?:\.exe)?\b|\bpowershell(?:\.exe)?\b[\s\S]*\bpwsh(?:\.exe)?\b/i,
    reason:
      'Single-shell purity violation: mixing pwsh.exe (PowerShell 7) and powershell.exe (Windows PowerShell 5.1) causes quote-escaping deadlocks (>>) and UTF-8/GBK mojibake.',
  },
  // 4. Hang Prevention: interactive keep-open / stdin traps (`-NoExit`, `-Command -`, `-File -`, `pause`, `Read-Host`, `choice`)
  {
    re: /(?:^|\s)-(?:noexit|noe)\b|(?:^|\s)-(?:c|command|f|file)\s+-(?:\s|$)|(?:^|[\s;|(])(?:read-host|pause|choice(?:\.exe)?)(?=$|[\s;|)])/i,
    reason:
      'Interactive shell hang prevented: -NoExit, -Command -, Read-Host, pause, and choice block headless tool execution indefinitely.',
  },
  // 5. Dialect Alignment: WinPS 5.1 (`powershell.exe`) invoked with PS 7 `&&` or `||` operators
  {
    re: /\bpowershell(?:\.exe)?\b[^\n]*-(?:c|command)\b[^\n]*(?:&&|\|\|)/i,
    reason:
      'Shell dialect mismatch: Windows PowerShell 5.1 (powershell.exe) does not support && or || chain operators.',
  },
  // 6. Dialect Alignment: CMD slash-flags passed to PowerShell aliases (`rmdir /s /q`, `del /f /q`, `move /y`, `copy /y`, `dir /b`)
  {
    re: /(?:^|[\s;|&(])(?:rmdir|rd|del|erase|rm|ri|move|mv|copy|cp|dir|ls)\s+(?:[^\n;|&]*\s)?\/(?:s|q|f|y|a|b|o)\b/i,
    reason:
      'Shell dialect mismatch: CMD slash-flags (/s, /q, /f, /y, /b) used on PowerShell aliases are parsed by PowerShell as root drive paths (C:\\s, C:\\q) or trigger interactive confirmation hangs. Use wsl_bash (rm -rf / mv) or native PowerShell parameters (-Recurse -Force).',
  },
  // 7. Dialect Alignment: CMD `>nul` / `2>nul` / `1>nul` redirection in PowerShell creates undeletable reserved `nul` file!
  {
    re: /(?:[12&]?>+\s*nul)(?=$|[\s;|&)])/i,
    reason:
      'Shell dialect mismatch: redirecting to "nul" (e.g. 2>nul) in PowerShell creates a literal DOS-reserved "nul" file that breaks Git and Windows Explorer. Use "$null" in PowerShell or "/dev/null" in wsl_bash.',
  },
  // 8. Dialect Alignment: Unexpanded CMD `%VAR%` syntax inside PowerShell
  {
    re: /%(?:USERPROFILE|TEMP|TMP|APPDATA|LOCALAPPDATA|PROGRAMFILES|PROGRAMDATA|SYSTEMROOT|WINDIR|HOMEDRIVE|HOMEPATH|CD|PATH)%/i,
    reason:
      'Shell dialect mismatch: CMD "%VAR%" environment variable syntax is not expanded by PowerShell. Use "$env:VAR" in PowerShell or "$VAR" in wsl_bash.',
  },
];

const L0_DESTRUCTIVE_PATTERNS: ReadonlyArray<{ re: RegExp; reason: string }> = [
  { re: WSL_UNC_PATH_RE, reason: 'Accessing WSL filesystem via Windows UNC share (\\\\wsl$\\ or \\\\wsl.localhost\\) bypasses bwrap read-only locks and is forbidden' },
  { re: /\b(?:format-volume|clear-disk|initialize-disk|remove-partition|set-disk)\b/i, reason: 'Disk/partition destruction cmdlet is forbidden' },
  { re: /\b(?:diskpart|format\.com|bcdedit(?:\.exe)?)\b/i, reason: 'Low-level disk/boot manipulation tool is forbidden' },
  { re: /\bcipher(?:\.exe)?\b[^\n;|&]*\/w(?::|\b)/i, reason: 'cipher /w free-space wipe is forbidden' },
  { re: /\b(?:stop-computer|restart-computer)\b/i, reason: 'Host power control cmdlet is forbidden' },
  { re: /\bshutdown(?:\.exe)?\b[^\n;|&]*(?:\/[srph]\b|-[srph]\b)/i, reason: 'Host shutdown/reboot command is forbidden' },
  { re: /\b(?:set-mppreference|add-mppreference)\b[^\n;|&]*(?:-disablerealtimemonitoring|-exclusionpath|-exclusionprocess)/i, reason: 'Disabling Windows Defender or adding exclusions is forbidden' },
  { re: /\bvssadmin(?:\.exe)?\b[^\n;|&]*\bdelete\s+shadows\b/i, reason: 'Deleting Volume Shadow Copies is forbidden' },
  { re: /\bwevtutil(?:\.exe)?\b[^\n;|&]*\b(?:cl|clear-log)\b/i, reason: 'Clearing Windows Event Logs is forbidden' },
  { re: /\breg(?:\.exe)?\b[^\n;|&]*\bsave\b[^\n;|&]*\bhklm\\(?:sam|system|security)\b/i, reason: 'Dumping Windows SAM/SYSTEM/SECURITY registry hives is forbidden' },
  { re: /\b(?:mimikatz|procdump.*lsass|comsvcs\.dll.*minidump)\b/i, reason: 'LSASS credential dumping is forbidden' },
  // Hard boundary against bypassing WSL sandbox via system config or root WSL management
  { re: /(?:\.wslconfig|\\etc\\wsl\.conf|\\etc\\fstab|\/etc\/wsl\.conf|\/etc\/fstab)/i, reason: 'Modifying WSL system configuration (.wslconfig / wsl.conf / fstab) from model tools is forbidden' },
  { re: /\bwsl(?:\.exe)?\b[^\n;|&]*(?:--import\b|--unregister\b|--shutdown\b|--set-default\b|--terminate\b|--mount\b)/i, reason: 'Managing/destroying WSL distributions from model tools is forbidden' },
  { re: /\bwsl(?:\.exe)?\b[^\n;|&]*(?:-u\s+root\b|--user\s+root\b|--user=root\b)/i, reason: 'Spawning root shell in WSL via wsl.exe is forbidden' },
];

const L3_APPROVAL_PATTERNS: ReadonlyArray<{ re: RegExp; reason: string; physical?: boolean; blockSessionPrefix?: boolean }> = [
  // Sandbox bypass attempt: calling wsl.exe / bash.exe from host pwsh instead of wsl_bash
  { re: /\b(?:wsl|wsl\.exe|bash\.exe)\b/i, reason: 'Invoking wsl.exe/bash.exe from Windows host bypasses the WSL sandbox; use wsl_bash or approve explicitly', blockSessionPrefix: true },
  // Host Windows directory creation, file moving, renaming, bulk copying, or NTFS junction/symlink creation
  {
    re: /(?:^|[\s;|&(])(?:mkdir|md|new-item|ni)\b/i,
    reason: 'Creating directories/items on the Windows host via pwsh requires approval (prefer wsl_bash / wsl_write inside WSL workspace)',
    blockSessionPrefix: true,
  },
  {
    re: /(?:^|[\s;|&(])(?:move|move-item|mv|mi|ren|rename|rename-item|rni|xcopy(?:\.exe)?|robocopy(?:\.exe)?)\b/i,
    reason: 'Moving, renaming, or bulk-copying files on the Windows host via pwsh requires approval (prefer wsl_bash inside WSL workspace)',
    blockSessionPrefix: true,
  },
  {
    re: /(?:^|[\s;|&(])mklink\b|\bnew-item\b[^\n;|&]*-itemtype\s+(?:symboliclink|junction|hardlink)\b/i,
    reason: 'Creating Windows NTFS junctions, symlinks, or hardlinks (mklink / New-Item) requires approval',
    blockSessionPrefix: true,
  },
  // Destructive file removal
  { re: /\b(?:remove-item|rm|ri|del|erase|rd|rmdir)\b[^\n;|&]*-(?:recurse|r|force|fo)\b/i, reason: 'Recursive/forced Windows file deletion requires approval', blockSessionPrefix: true },
  // Registry mutation or execution policy weakening
  { re: /\b(?:reg(?:\.exe)?\s+(?:add|delete|import)|remove-itemproperty|set-itemproperty\s+hklm:)\b/i, reason: 'Mutating Windows registry keys/values requires approval' },
  { re: /\bset-executionpolicy\b[^\n;|&]*\b(?:bypass|unrestricted)\b/i, reason: 'Weakening PowerShell ExecutionPolicy requires approval' },
  // Privilege elevation & persistence
  { re: /\b(?:start-process|saps|start)\b[^\n;|&]*-verb\s+runas\b/i, reason: 'UAC privilege elevation (-Verb RunAs) requires approval', blockSessionPrefix: true },
  { re: /\b(?:schtasks(?:\.exe)?\b[^\n;|&]*\/create\b|register-scheduledtask\b)/i, reason: 'Creating a Windows Scheduled Task requires approval' },
  { re: /\b(?:new-service\b|sc(?:\.exe)?\s+(?:create|delete|config)\b)/i, reason: 'Modifying Windows services requires approval' },
  { re: /\b(?:icacls(?:\.exe)?|takeown(?:\.exe)?|set-acl)\b/i, reason: 'Modifying NTFS ACLs/ownership requires approval' },
  // Download-and-execute cradle patterns
  { re: /\b(?:invoke-webrequest|iwr|invoke-restmethod|irm|curl|wget)\b[^\n;]*\|\s*(?:iex|invoke-expression|powershell|pwsh|cmd(?:\.exe)?)\b/i, reason: 'Piping remote download directly into shell/Invoke-Expression requires approval', blockSessionPrefix: true },
  { re: /\bcertutil(?:\.exe)?\b[^\n;|&]*-urlcache\b/i, reason: 'certutil -urlcache download requires approval' },
  { re: /\bbitsadmin(?:\.exe)?\b[^\n;|&]*\/transfer\b/i, reason: 'bitsadmin /transfer download requires approval' },
  // Physical hardware / USBIP mutating operations (Q13 auto-downgrade to manual allow-once!)
  { re: /\busbipd(?:\.exe)?\b[^\n;|&]*\b(?:bind|unbind|attach|detach)\b/i, reason: 'Physical USBIP device bind/attach/detach requires manual single-shot approval', physical: true },
  { re: /\b(?:esptool(?:\.exe|\.py)?|openocd(?:\.exe)?|avrdude(?:\.exe)?|dfu-util(?:\.exe)?)\b/i, reason: 'Host physical hardware flashing tool requires manual single-shot approval', physical: true },
];

/**
 * Strip PowerShell backtick escape obfuscation outside single quotes (`i`ex` -> `iex`)
 * AND CMD caret escape obfuscation outside quotes (`c^m^d /c m^o^v^e` -> `cmd /c move`),
 * while preserving `\\wsl$\` UNC paths cleanly.
 */
export function deobfuscatePowerShell(script: string): string {
  let out = '';
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < script.length; i++) {
    const ch = script[i]!;
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      out += ch;
      continue;
    }
    if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      out += ch;
      continue;
    }
    if (!inSingle && ch === '`' && i + 1 < script.length) {
      const next = script[i + 1]!;
      if (inDouble && (next === 'n' || next === 'r' || next === 't')) {
        out += ' ';
      } else {
        out += next;
      }
      i++;
      continue;
    }
    if (!inSingle && !inDouble && ch === '^' && i + 1 < script.length) {
      const next = script[i + 1]!;
      if (/[A-Za-z0-9_.\-\/\\&|<>()]/.test(next)) {
        out += next;
        i++;
        continue;
      }
    }
    out += ch;
  }
  return out;
}

export function decodePowerShellEncodedCommands(script: string): string[] {
  const decoded: string[] = [];
  PWSH_ENCODED_FLAG_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = PWSH_ENCODED_FLAG_RE.exec(script)) !== null) {
    const b64 = match[2];
    if (!b64) continue;
    try {
      const raw = Buffer.from(b64, 'base64');
      const text = raw.toString('utf16le').replace(/\0/g, '').trim();
      if (text.length > 0) {
        decoded.push(text);
      }
    } catch {
      // Malformed base64 handled below
    }
  }
  return decoded;
}

function stripOuterQuotes(s: string): string {
  const trimmed = s.trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    const inner = trimmed.slice(1, -1);
    const quoteChar = trimmed[0]!;
    if (!inner.includes(quoteChar)) {
      return inner;
    }
  }
  return trimmed;
}

export function splitCompoundWindowsCommands(script: string): string[] {
  const parts: string[] = [];
  let cur = '';
  let inSingle = false;
  let inDouble = false;

  for (let i = 0; i < script.length; i++) {
    const ch = script[i]!;
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      cur += ch;
      continue;
    }
    if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      cur += ch;
      continue;
    }
    if (!inSingle && !inDouble) {
      if (ch === '\n' || ch === '\r' || ch === ';') {
        if (cur.trim()) parts.push(cur.trim());
        cur = '';
        continue;
      }
      if ((ch === '&' && script[i + 1] === '&') || (ch === '|' && script[i + 1] === '|')) {
        if (cur.trim()) parts.push(cur.trim());
        cur = '';
        i++;
        continue;
      }
      if (ch === '&' && cur.trim().length > 0) {
        parts.push(cur.trim());
        cur = '';
        continue;
      }
      if (ch === '|') {
        if (cur.trim()) parts.push(cur.trim());
        cur = '';
        continue;
      }
    }
    cur += ch;
  }
  if (cur.trim()) parts.push(cur.trim());
  return parts;
}

function splitFirstTokens(script: string): string[] {
  const stripped = script.trim().replace(/^[&.]\s*/, '');
  const parts = stripped.match(/(?:"[^"]*"|'[^']*'|\S+)/g) ?? [];
  return parts.map((p) => p.replace(/^['"]|['"]$/g, ''));
}

export function evaluatePwshCommand(command: string): GuardEvaluation {
  const reasons: string[] = [];
  const unwrappedCommands: string[][] = [];
  let decision: 'allow' | 'ask' | 'deny' = 'allow';
  let riskLevel: 'safe' | 'elevated' | 'high' | 'critical' = 'safe';
  let touchesPhysicalDevice = false;
  let forceBlockSessionRule = false;

  const escalate = (
    nextDecision: 'ask' | 'deny',
    nextRisk: 'elevated' | 'high' | 'critical',
    reason: string,
    blockPrefix = false,
  ): void => {
    if (!reasons.includes(reason)) {
      reasons.push(reason);
    }
    if (blockPrefix) {
      forceBlockSessionRule = true;
    }
    if (nextDecision === 'deny') {
      decision = 'deny';
      riskLevel = 'critical';
      forceBlockSessionRule = true;
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
      reasons: ['Empty PowerShell command'],
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
      reasons: [`PowerShell command exceeds MAX_GUARD_CHARS (${MAX_GUARD_CHARS})`],
      unwrappedCommands: [],
      touchesPhysicalDevice: false,
      requiresSessionRuleBlocked: true,
      externalPaths: [],
    };
  }

  const visited = new Set<string>();

  const inspect = (raw: string, depth: number, segmentIndex: number): void => {
    if (depth > MAX_WRAPPER_DEPTH) {
      escalate('deny', 'critical', `PowerShell subshell nesting exceeded MAX_WRAPPER_DEPTH (${MAX_WRAPPER_DEPTH})`, true);
      return;
    }

    const clean = deobfuscatePowerShell(raw).trim();
    if (!clean) return;

    const visitKey = `${depth}:${clean}`;
    if (visited.has(visitKey)) return;
    visited.add(visitKey);

    const tokens = splitFirstTokens(clean);
    if (tokens.length > 0) {
      unwrappedCommands.push(tokens);
    }

    // Single-Shell Purity: block spawning a second PowerShell child after an outer statement
    // e.g. `Move-Item a b; powershell.exe -Command "..."` or `depth > 0` nested pwsh->pwsh
    if ((depth > 0 || segmentIndex > 0) && tokens.length > 0) {
      const bin0 = tokens[0]!.replace(/^.*\\/, '').toLowerCase();
      if (bin0 === 'pwsh' || bin0 === 'pwsh.exe' || bin0 === 'powershell' || bin0 === 'powershell.exe') {
        escalate(
          'deny',
          'critical',
          `Single-shell purity violation: spawning nested ${bin0} subshell inside an existing PowerShell call is forbidden (causes quote-escaping hangs and encoding mismatches).`,
          true,
        );
      }
    }

    // 1. Pre-execution Single-Shell Purity & Dialect Alignment (L0 POLICY_BLOCK)
    for (const rule of L0_SINGLE_SHELL_AND_DIALECT_RULES) {
      if (rule.re.test(clean)) {
        escalate('deny', 'critical', rule.reason, true);
      }
    }

    // 2. Decode -EncodedCommand payloads and inspect recursively
    const encodedPayloads = decodePowerShellEncodedCommands(clean);
    if (encodedPayloads.length > 0) {
      escalate('ask', 'high', 'Encoded PowerShell command (-EncodedCommand) decoded and requires inspection', true);
      for (const payload of encodedPayloads) {
        inspect(payload, depth + 1, 0);
      }
    } else if (/(?:^|\s)-(?:e|ec|enc|encoded|encodedcommand)\b/i.test(clean)) {
      escalate('deny', 'critical', 'Malformed/obfuscated PowerShell -EncodedCommand flag is forbidden', true);
    }

    // 3. Unwrap top-level `pwsh -Command "..."` if model wrapped its single command in `pwsh -c`
    if (depth === 0 && segmentIndex === 0 && tokens.length >= 3) {
      const bin0 = tokens[0]!.replace(/^.*\\/, '').toLowerCase();
      if (bin0 === 'pwsh' || bin0 === 'pwsh.exe' || bin0 === 'powershell' || bin0 === 'powershell.exe') {
        const cIdx = tokens.findIndex((t) => /^-(?:c|command)$/i.test(t));
        if (cIdx > 0 && cIdx + 1 < tokens.length) {
          const inner = stripOuterQuotes(tokens.slice(cIdx + 1).join(' '));
          if (inner && inner !== clean) {
            inspect(inner, depth + 1, 0);
          }
        }
      }
    }

    // 4. Split compound `;` / `&&` / `||` / `&` / `|` segments
    const segments = splitCompoundWindowsCommands(clean);
    if (segments.length > 1) {
      segments.forEach((seg, idx) => {
        if (seg !== clean) {
          inspect(seg, depth + 1, idx);
        }
      });
    }

    // 5. Invoke-Expression (`iex`) unwrapping
    const iexMatch = clean.match(/\b(?:iex|invoke-expression)\b\s+(?:"([^"]+)"|'([^']+)')/i);
    if (iexMatch) {
      const inner = iexMatch[1] ?? iexMatch[2];
      if (inner) {
        escalate('ask', 'high', 'Dynamic Invoke-Expression (iex) requires approval', true);
        inspect(inner, depth + 1, 0);
      }
    } else if (/\b(?:iex|invoke-expression)\b/i.test(clean)) {
      escalate('ask', 'high', 'Dynamic Invoke-Expression (iex) requires approval', true);
    }

    // 6. Check L0 Hard Deny rules
    for (const rule of L0_DESTRUCTIVE_PATTERNS) {
      if (rule.re.test(clean)) {
        escalate('deny', 'critical', rule.reason, true);
      }
    }

    // 7. Check L3 Approval rules (and physical device auto-downgrade)
    for (const rule of L3_APPROVAL_PATTERNS) {
      if (rule.re.test(clean)) {
        if (rule.physical) touchesPhysicalDevice = true;
        escalate('ask', 'high', rule.reason, Boolean(rule.blockSessionPrefix));
      }
    }
  };

  inspect(command, 0, 0);

  const first = unwrappedCommands[0];
  let suggestedPrefix: string[] | undefined;
  let requiresSessionRuleBlocked = touchesPhysicalDevice || decision === 'deny' || forceBlockSessionRule;

  if (first && first.length > 0 && !requiresSessionRuleBlocked) {
    const candidate = first.slice(0, Math.min(2, first.length));
    if (isBannedPrefix(candidate) || isBannedPrefix([first[0]!])) {
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
    externalPaths: [],
  };
}
