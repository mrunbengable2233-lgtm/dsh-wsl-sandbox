import { type GuardEvaluation, isBannedPrefix, MAX_GUARD_CHARS, MAX_WRAPPER_DEPTH } from './bash-ast-guard.ts';

/**
 * Complete Zero-Token Windows PowerShell / CMD High-Risk Command Guard (Q15=A + Q13=A).
 * Protects the Windows host tool surface when Windows native tools remain active alongside
 * `wsl_*` tools (USBIP / ESP32 / Kali hybrid workflows), without breaking host plugins like dsh-purge.
 */

const PWSH_ENCODED_FLAG_RE = /(?:^|\s)-(?:e|ec|enc|encoded|encodedcommand)\s+(['"]?)([A-Za-z0-9+/=]{8,})\1/gi;

const L0_DESTRUCTIVE_PATTERNS: ReadonlyArray<{ re: RegExp; reason: string }> = [
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

const L3_APPROVAL_PATTERNS: ReadonlyArray<{ re: RegExp; reason: string; physical?: boolean }> = [
  // Sandbox bypass attempt: calling wsl.exe / bash.exe from host pwsh instead of wsl_bash
  { re: /\b(?:wsl|wsl\.exe|bash\.exe)\b/i, reason: 'Invoking wsl.exe/bash.exe from Windows host bypasses the WSL sandbox; use wsl_bash or approve explicitly' },
  // Destructive file removal
  { re: /\b(?:remove-item|rm|ri|del|erase|rd|rmdir)\b[^\n;|&]*(?:-(?:recurse|r|force|fo)\b|\/[sq]\b)/i, reason: 'Recursive/forced Windows file deletion requires approval' },
  // Registry deletion or execution policy weakening
  { re: /\b(?:reg(?:\.exe)?\s+delete|remove-itemproperty)\b/i, reason: 'Deleting Windows registry keys/values requires approval' },
  { re: /\bset-executionpolicy\b[^\n;|&]*\b(?:bypass|unrestricted)\b/i, reason: 'Weakening PowerShell ExecutionPolicy requires approval' },
  // Privilege elevation & persistence
  { re: /\b(?:start-process|saps|start)\b[^\n;|&]*-verb\s+runas\b/i, reason: 'UAC privilege elevation (-Verb RunAs) requires approval' },
  { re: /\b(?:schtasks(?:\.exe)?\b[^\n;|&]*\/create\b|register-scheduledtask\b)/i, reason: 'Creating a Windows Scheduled Task requires approval' },
  { re: /\b(?:new-service\b|sc(?:\.exe)?\s+(?:create|delete|config)\b)/i, reason: 'Modifying Windows services requires approval' },
  { re: /\b(?:icacls(?:\.exe)?|takeown(?:\.exe)?|set-acl)\b/i, reason: 'Modifying NTFS ACLs/ownership requires approval' },
  // Download-and-execute cradle patterns
  { re: /\b(?:invoke-webrequest|iwr|invoke-restmethod|irm|curl|wget)\b[^\n;]*\|\s*(?:iex|invoke-expression|powershell|pwsh)\b/i, reason: 'Piping remote download directly into Invoke-Expression requires approval' },
  { re: /\bcertutil(?:\.exe)?\b[^\n;|&]*-urlcache\b/i, reason: 'certutil -urlcache download requires approval' },
  { re: /\bbitsadmin(?:\.exe)?\b[^\n;|&]*\/transfer\b/i, reason: 'bitsadmin /transfer download requires approval' },
  // Physical hardware / USBIP mutating operations (Q13 auto-downgrade to manual allow-once!)
  { re: /\busbipd(?:\.exe)?\b[^\n;|&]*\b(?:bind|unbind|attach|detach)\b/i, reason: 'Physical USBIP device bind/attach/detach requires manual single-shot approval', physical: true },
  { re: /\b(?:esptool(?:\.exe|\.py)?|openocd(?:\.exe)?|avrdude(?:\.exe)?|dfu-util(?:\.exe)?)\b/i, reason: 'Host physical hardware flashing tool requires manual single-shot approval', physical: true },
];

/**
 * Strip PowerShell backtick escape obfuscation outside single quotes (e.g. `i`ex` -> `iex`).
 * Preserves standard escape sequences like `n, `r, `t, `0 only as spaces/delimiters.
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
      // PowerShell -EncodedCommand uses UTF-16LE
      const text = raw.toString('utf16le').replace(/\0/g, '').trim();
      if (text.length > 0) {
        decoded.push(text);
      }
    } catch {
      // Malformed base64 will still be flagged below
    }
  }
  return decoded;
}

function splitFirstTokens(script: string): string[] {
  const stripped = script.trim().replace(/^[&.]\s+/, '');
  const parts = stripped.match(/(?:"[^"]*"|'[^']*'|\S+)/g) ?? [];
  return parts.map((p) => p.replace(/^['"]|['"]$/g, ''));
}

export function evaluatePwshCommand(command: string): GuardEvaluation {
  const reasons: string[] = [];
  const unwrappedCommands: string[][] = [];
  let decision: 'allow' | 'ask' | 'deny' = 'allow';
  let riskLevel: 'safe' | 'elevated' | 'high' | 'critical' = 'safe';
  let touchesPhysicalDevice = false;

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

  const inspect = (raw: string, depth: number): void => {
    if (depth > MAX_WRAPPER_DEPTH) {
      escalate('ask', 'high', `PowerShell wrapper nesting exceeded MAX_WRAPPER_DEPTH (${MAX_WRAPPER_DEPTH})`);
      return;
    }

    const clean = deobfuscatePowerShell(raw);
    const tokens = splitFirstTokens(clean);
    if (tokens.length > 0) {
      unwrappedCommands.push(tokens);
    }

    // 1. Decode -EncodedCommand payloads and inspect recursively
    const encodedPayloads = decodePowerShellEncodedCommands(clean);
    if (encodedPayloads.length > 0) {
      escalate('ask', 'high', 'Encoded PowerShell command (-EncodedCommand) decoded and requires inspection');
      for (const payload of encodedPayloads) {
        inspect(payload, depth + 1);
      }
    } else if (/(?:^|\s)-(?:e|ec|enc|encoded|encodedcommand)\b/i.test(clean)) {
      escalate('ask', 'high', 'Obfuscated/unparseable PowerShell -EncodedCommand flag requires approval');
    }

    // 2. Unwrap nested pwsh/powershell -Command or cmd /c or iex "..."
    const nestedShellMatch = clean.match(
      /\b(?:pwsh|powershell)(?:\.exe)?\b[^\n;|&]*\s-(?:c|command)\s+(?:"([^"]+)"|'([^']+)'|(.+))$/i,
    );
    if (nestedShellMatch) {
      const inner = nestedShellMatch[1] ?? nestedShellMatch[2] ?? nestedShellMatch[3];
      if (inner && inner.trim() !== clean.trim()) {
        inspect(inner, depth + 1);
      }
    }

    const cmdMatch = clean.match(/\bcmd(?:\.exe)?\b[^\n;|&]*\s\/[ck]\s+(?:"([^"]+)"|'([^']+)'|(.+))$/i);
    if (cmdMatch) {
      const inner = cmdMatch[1] ?? cmdMatch[2] ?? cmdMatch[3];
      if (inner && inner.trim() !== clean.trim()) {
        inspect(inner, depth + 1);
      }
    }

    const iexMatch = clean.match(/\b(?:iex|invoke-expression)\b\s+(?:"([^"]+)"|'([^']+)')/i);
    if (iexMatch) {
      const inner = iexMatch[1] ?? iexMatch[2];
      if (inner) {
        escalate('ask', 'high', 'Dynamic Invoke-Expression (iex) requires approval');
        inspect(inner, depth + 1);
      }
    } else if (/\b(?:iex|invoke-expression)\b/i.test(clean)) {
      escalate('ask', 'high', 'Dynamic Invoke-Expression (iex) requires approval');
    }

    // 3. Check L0 Hard Deny rules
    for (const rule of L0_DESTRUCTIVE_PATTERNS) {
      if (rule.re.test(clean)) {
        escalate('deny', 'critical', rule.reason);
      }
    }

    // 4. Check L3 Approval rules (and physical device auto-downgrade)
    for (const rule of L3_APPROVAL_PATTERNS) {
      if (rule.re.test(clean)) {
        if (rule.physical) touchesPhysicalDevice = true;
        escalate('ask', 'high', rule.reason);
      }
    }
  };

  inspect(command, 0);

  const first = unwrappedCommands[0];
  let suggestedPrefix: string[] | undefined;
  let requiresSessionRuleBlocked = touchesPhysicalDevice || decision === 'deny';

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
