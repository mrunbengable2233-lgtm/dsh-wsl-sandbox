import { type GuardEvaluation, isBannedPrefix, MAX_GUARD_CHARS, MAX_WRAPPER_DEPTH } from './bash-ast-guard.ts';
import { parsePwshWithSystemParser, type SystemPwshCommandElement, type SystemPwshCommandInfo } from './pwsh-system-parser.ts';

/**
 * Complete Zero-Token Windows PowerShell Guard with:
 *  1. Single-Shell Purity Enforcement (forbids nested `cmd`/`cmd.exe`/`%COMSPEC%` inside PowerShell
 *     and forbids mixing `pwsh.exe` <-> `powershell.exe` or multi-statement subshell nesting).
 *  2. Pre-Execution Shell Dialect Alignment (catches CMD slash-flags like `rmdir /s /q` / `del /f /q`
 *     that PowerShell misinterprets as `C:\s` & `C:\q`, blocks `2>nul` DOS reserved-file creation,
 *     blocks `%VAR%` unexpanded CMD env vars, blocks WinPS 5.1 `&&` syntax errors, and blocks
 *     interactive hang traps like `cmd /k`, `-NoExit`, `-Command -`, `Read-Host`, `pause`).
 *  3. Reverse UNC WSL Sandbox Escape Prevention (`\\wsl$\` / `\\wsl.localhost\` / `\\?\UNC\wsl.localhost\` -> L0 POLICY_BLOCK).
 *  4. Physical Hardware Mandatory Single-Shot Downgrade (`usbipd` / `esptool` -> manual `allow-once`).
 *  5. Optional Zero-Execution Official Windows Compiler AST verification via `evaluatePwshCommandWithSystemAst`.
 */

const PWSH_ENCODED_FLAG_PATTERN =
  '(?:e|ec|enc(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)';

const PWSH_ENCODED_FLAG_VALUE_RE = new RegExp(
  `(?:^|\\s)[/-]${PWSH_ENCODED_FLAG_PATTERN}(?:\\s+|:)(['"]?)([A-Za-z0-9+/=]{8,})\\1`,
  'gi',
);

const PWSH_ENCODED_TOKEN_RE = new RegExp(
  `^[/-]${PWSH_ENCODED_FLAG_PATTERN}(?:$|:([\\s\\S]*))`,
  'i',
);

const PWSH_COMMAND_FLAG_RE =
  /^[/-](?:c(?:om(?:m(?:a(?:n(?:d(?:w(?:i(?:t(?:h(?:a(?:r(?:g(?:s)?)?)?)?)?)?)?)?)?)?)?)?)?|cwa)(?:$|:([\s\S]*))/i;

const PWSH_VALUE_FLAG_RE =
  /^[/-](?:executionpolicy|ep|ex|windowstyle|w|inputformat|if|outputformat|of|configurationname|config|settingsfile|workingdirectory|wd|custompipename|file|f)(?:$|:([\s\S]*))/i;

const PWSH_FILE_FLAG_RE = /^[/-](?:f|fi|fil|file)(?:$|:([\s\S]*))/i;

const PWSH_BINARIES = new Set(['pwsh', 'pwsh.exe', 'powershell', 'powershell.exe']);
const WINPS_51_BINARIES = new Set(['powershell', 'powershell.exe']);
const CMD_ALIASED_CMDS = new Set(['rmdir', 'rd', 'del', 'erase', 'rm', 'ri', 'move', 'mv', 'copy', 'cp', 'dir', 'ls']);
const SEARCH_OR_TEXT_CMDS = new Set([
  'rg', 'grep', 'egrep', 'fgrep', 'ag', 'ack', 'fd', 'findstr', 'select-string', 'sls',
  'echo', 'write-output', 'write-host', 'write-verbose', 'write-debug',
]);
const FILE_CONFIG_CMDS = new Set([
  'set-content', 'sc', 'add-content', 'ac', 'out-file', 'copy-item', 'copy', 'cp', 'cpi',
  'move-item', 'move', 'mv', 'mi', 'remove-item', 'rm', 'ri', 'del', 'erase',
  'new-item', 'ni', 'rename-item', 'rni', 'ren', 'get-content', 'gc', 'cat', 'type',
  'tee-object', 'tee', 'clear-content', 'clc', 'notepad', 'notepad.exe', 'code', 'wsl', 'wsl.exe',
]);

/** Reverse UNC share into WSL rootfs from Windows host — bypasses bwrap read-only mounts if allowed! */
const WSL_UNC_PATH_RE = /(?:\\\\|\/\/)(?:[?.][\\/]unc[\\/])?wsl(?:\$|\.localhost)(?:[\\/]|$)/i;

/** Protected WSL system config targets */
const WSL_CONFIG_PATH_RE = /(?:^|[\\/\\s"'=])(?:\.wslconfig|etc[\\/]wsl\.conf|etc[\\/]fstab)(?:$|[\\/\\s"'])/i;

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
    re: /(?:^|\s)[/-](?:noexit|noe)(?=$|\s|:)|(?:^|\s)[/-](?:c|command|f|file)\s+-(?:\s|$)|(?:^|[\s;|(])(?:read-host|pause|choice(?:\.exe)?)(?=$|[\s;|)])/i,
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
    re: /(?:^|[\s;|&(])(?:rmdir|rd|del|erase|rm|ri|move|mv|copy|cp|dir|ls)\s+(?:[^\n;|&]*\s)?\/(?:s|q|f|y|a|b|o)(?=$|\s|[:;|&)])/i,
    reason:
      'Shell dialect mismatch: CMD slash-flags (/s, /q, /f, /y, /b) used on PowerShell aliases are parsed by PowerShell as root drive paths (C:\\s, C:\\q) or trigger interactive confirmation hangs. Use wsl_bash (rm -rf / mv) or native PowerShell parameters (-Recurse -Force).',
  },
  // 7. Dialect Alignment: CMD `>nul` / `2>nul` / `1>nul` redirection in PowerShell creates undeletable reserved `nul` file!
  {
    re: /(?:[12&*]?>>?\s*nul)(?=$|[\s;|&)])/i,
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
  { re: /\b(?:format-volume|clear-disk|initialize-disk|remove-partition|set-disk)\b/i, reason: 'Disk/partition destruction cmdlet is forbidden' },
  { re: /\b(?:diskpart|format\.com|bcdedit(?:\.exe)?)\b/i, reason: 'Low-level disk/boot manipulation tool is forbidden' },
  { re: /\bcipher(?:\.exe)?\b[^\n;|&]*\/w(?::|\s|$)/i, reason: 'cipher /w free-space wipe is forbidden' },
  { re: /\b(?:stop-computer|restart-computer)\b/i, reason: 'Host power control cmdlet is forbidden' },
  { re: /\bshutdown(?:\.exe)?\b[^\n;|&]*(?:\/[srph](?:$|\s)|-[srph](?:$|\s))/i, reason: 'Host shutdown/reboot command is forbidden' },
  { re: /\b(?:set-mppreference|add-mppreference)\b[^\n;|&]*(?:-disablerealtimemonitoring|-exclusionpath|-exclusionprocess)/i, reason: 'Disabling Windows Defender or adding exclusions is forbidden' },
  { re: /\bvssadmin(?:\.exe)?\b[^\n;|&]*\bdelete\s+shadows\b/i, reason: 'Deleting Volume Shadow Copies is forbidden' },
  { re: /\bwevtutil(?:\.exe)?\b[^\n;|&]*\b(?:cl|clear-log)\b/i, reason: 'Clearing Windows Event Logs is forbidden' },
  { re: /\breg(?:\.exe)?\b[^\n;|&]*\bsave\b[^\n;|&]*\bhklm\\(?:sam|system|security)\b/i, reason: 'Dumping Windows SAM/SYSTEM/SECURITY registry hives is forbidden' },
  { re: /\b(?:mimikatz|procdump.*lsass|comsvcs\.dll.*minidump)\b/i, reason: 'LSASS credential dumping is forbidden' },
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
  {
    re: /\b(?:reg(?:\.exe)?\s+(?:add|delete|import)|(?:remove|set|new)-itemproperty\b[^\n;|&]*(?:\b(?:hklm|hkcu|hkcr|hku|hkcc):|registry::|\\lxss\b)|set-item\b[^\n;|&]*(?:\b(?:hklm|hkcu|hkcr|hku|hkcc):|registry::|\\lxss\b))/i,
    reason: 'Mutating Windows registry keys/values (HKLM/HKCU/Lxss) requires approval',
    blockSessionPrefix: true,
  },
  { re: /\bset-executionpolicy\b[^\n;|&]*\b(?:bypass|unrestricted)\b/i, reason: 'Weakening PowerShell ExecutionPolicy requires approval', blockSessionPrefix: true },
  // Privilege elevation & persistence
  { re: /\b(?:start-process|saps|start)\b[^\n;|&]*-verb\s+runas\b/i, reason: 'UAC privilege elevation (-Verb RunAs) requires approval', blockSessionPrefix: true },
  { re: /\b(?:schtasks(?:\.exe)?\b[^\n;|&]*\/create\b|register-scheduledtask\b)/i, reason: 'Creating a Windows Scheduled Task requires approval', blockSessionPrefix: true },
  { re: /\b(?:new-service\b|sc(?:\.exe)?\s+(?:create|delete|config)\b)/i, reason: 'Modifying Windows services requires approval', blockSessionPrefix: true },
  { re: /\b(?:icacls(?:\.exe)?|takeown(?:\.exe)?|set-acl)\b/i, reason: 'Modifying NTFS ACLs/ownership requires approval', blockSessionPrefix: true },
  // Download-and-execute cradle patterns
  { re: /\b(?:invoke-webrequest|iwr|invoke-restmethod|irm|curl|wget)\b[^\n;]*\|\s*(?:iex|invoke-expression|powershell|pwsh|cmd(?:\.exe)?)\b/i, reason: 'Piping remote download directly into shell/Invoke-Expression requires approval', blockSessionPrefix: true },
  { re: /\bcertutil(?:\.exe)?\b[^\n;|&]*-urlcache\b/i, reason: 'certutil -urlcache download requires approval', blockSessionPrefix: true },
  { re: /\bbitsadmin(?:\.exe)?\b[^\n;|&]*\/transfer\b/i, reason: 'bitsadmin /transfer download requires approval', blockSessionPrefix: true },
  // Physical hardware, USBIP, phone Bootloader/ADB/Fastboot/EDL & Windows driver/NIC mutating operations (mandatory manual allow-once!)
  { re: /\busbipd(?:\.exe)?\b[^\n;|&]*\b(?:bind|unbind|attach|detach)\b/i, reason: 'Physical USBIP device bind/attach/detach requires manual single-shot approval', physical: true },
  { re: /\bfastboot(?:\.exe)?\b(?![^\n;|&]*\b(?:devices|--version|-V|--help|help)\b)/i, reason: 'Phone Bootloader / fastboot device operation requires manual single-shot approval', physical: true },
  { re: /\badb(?:\.exe)?\b[^\n;|&]*\b(?:reboot|sideload|install|uninstall|push|root|unroot|remount|disable-verity|enable-verity|shell|backup|restore)\b/i, reason: 'Phone ADB mutating/reboot/flashing operation requires manual single-shot approval', physical: true },
  { re: /\b(?:esptool(?:\.exe|\.py)?|openocd(?:\.exe)?|avrdude(?:\.exe)?|dfu-util(?:\.exe)?|st-flash(?:\.exe)?|odin\d*(?:\.exe)?|heimdall(?:\.exe)?|qdl(?:\.exe)?|edl(?:\.exe|\.py)?|mtk(?:\.exe|\.py)?|spflashtool(?:\.exe)?|miflash(?:\.exe)?)\b/i, reason: 'Host physical hardware / firmware / Bootloader flashing tool requires manual single-shot approval', physical: true },
  { re: /\bpnputil(?:\.exe)?\b[^\n;|&]*(?:\/(?:add-driver|delete-driver|install|enable-device|disable-device|restart-device|remove-device|scan-devices)\b|\s-[adi]\b)/i, reason: 'Windows PnP driver installation or device state mutation (pnputil) requires manual single-shot approval', physical: true },
  { re: /\b(?:devcon(?:\.exe)?\b[^\n;|&]*\b(?:install|update|updateni|remove|enable|disable|restart|dp_add|dp_delete)\b|zadig(?:\.exe)?\b|wdi-simple(?:\.exe)?\b|infdefaultinstall(?:\.exe)?\b)/i, reason: 'Windows USB/WinUSB/device driver mutation tool requires manual single-shot approval', physical: true },
  { re: /\b(?:enable-pnpdevice|disable-pnpdevice|remove-pnpdevice|enable-netadapter|disable-netadapter|restart-netadapter|set-netadapter[a-z]*|new-netipaddress|set-netipinterface)\b|\bnetsh(?:\.exe)?\b[^\n;|&]*\binterface\s+set\s+interface\b/i, reason: 'Windows PnP device or network adapter (USB NIC) driver/state mutation requires manual single-shot approval', physical: true },
];

function isSingleQuoteChar(ch: string): boolean {
  return ch === "'" || ch === '\u2018' || ch === '\u2019';
}

function isDoubleQuoteChar(ch: string): boolean {
  return ch === '"' || ch === '\u201c' || ch === '\u201d';
}

function basenameWin(token: string): string {
  return token.replace(/^.*[/\\]/, '');
}

/**
 * Strip PowerShell backtick escape obfuscation outside single quotes (`i`ex` -> `iex`)
 * AND CMD caret escape obfuscation outside quotes (`c^m^d /c m^o^v^e` -> `cmd /c move`),
 * while preserving `\\wsl$\` UNC paths and escaped double-quote delimiters cleanly.
 */
export function deobfuscatePowerShell(script: string): string {
  let out = '';
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < script.length; i++) {
    const ch = script[i]!;
    if (isSingleQuoteChar(ch) && !inDouble) {
      if (inSingle && isSingleQuoteChar(script[i + 1] ?? '')) {
        out += ch + script[i + 1]!;
        i++;
        continue;
      }
      inSingle = !inSingle;
      out += ch;
      continue;
    }
    if (isDoubleQuoteChar(ch) && !inSingle) {
      if (inDouble && isDoubleQuoteChar(script[i + 1] ?? '')) {
        out += ch + script[i + 1]!;
        i++;
        continue;
      }
      inDouble = !inDouble;
      out += ch;
      continue;
    }
    if (!inSingle && ch === '`' && i + 1 < script.length) {
      const next = script[i + 1]!;
      if (inDouble) {
        if (next === 'n' || next === 'r' || next === 't') {
          out += ' ';
        } else if (isDoubleQuoteChar(next) || next === '`' || next === '$') {
          out += '`' + next;
        } else {
          out += next;
        }
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

function decodeBase64Utf16Le(b64: string): string | null {
  const cleaned = b64.trim();
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(cleaned) || cleaned.length % 4 !== 0) {
    return null;
  }
  try {
    const raw = Buffer.from(cleaned, 'base64');
    if (raw.length < 2) return null;
    const text = raw.toString('utf16le').replace(/\0/g, '').trim();
    return text.length > 0 ? text : null;
  } catch {
    return null;
  }
}

export function decodePowerShellEncodedCommands(script: string): string[] {
  const decoded: string[] = [];
  PWSH_ENCODED_FLAG_VALUE_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = PWSH_ENCODED_FLAG_VALUE_RE.exec(script)) !== null) {
    const b64 = match[2];
    if (!b64) continue;
    const text = decodeBase64Utf16Le(b64);
    if (text) {
      decoded.push(text);
    }
  }
  return decoded;
}

interface HereStringSpan {
  readonly isSingle: boolean;
  readonly bodyStart: number;
  readonly bodyEnd: number;
  readonly endIdx: number;
}

function matchHereString(psCode: string, startIdx: number): HereStringSpan | null {
  if (psCode[startIdx] !== '@') return null;
  const q = psCode[startIdx + 1] ?? '';
  const isSingle = isSingleQuoteChar(q);
  const isDouble = isDoubleQuoteChar(q);
  if (!isSingle && !isDouble) return null;

  const afterQuote = startIdx + 2;
  const nlMatch = psCode.slice(afterQuote).match(/^[ \t]*\r?\n/);
  if (!nlMatch) return null;

  const bodyStart = afterQuote + nlMatch[0].length;
  let j = bodyStart;
  while (j < psCode.length) {
    if (j === bodyStart || psCode[j - 1] === '\n') {
      const c0 = psCode[j] ?? '';
      const c1 = psCode[j + 1] ?? '';
      if (((isSingle && isSingleQuoteChar(c0)) || (isDouble && isDoubleQuoteChar(c0))) && c1 === '@') {
        const bodyEnd =
          j > bodyStart && psCode[j - 1] === '\n'
            ? psCode[j - 2] === '\r'
              ? j - 2
              : j - 1
            : j;
        return { isSingle, bodyStart, bodyEnd, endIdx: j + 2 };
      }
    }
    j++;
  }
  return { isSingle, bodyStart, bodyEnd: psCode.length, endIdx: psCode.length };
}

function extractSubexpressionsFromRegion(region: string, subs: string[]): void {
  for (let i = 0; i < region.length; i++) {
    const ch = region[i]!;
    if (ch === '`' && i + 1 < region.length) {
      i++;
      continue;
    }
    if (ch === '$' && region[i + 1] === '(') {
      let depth = 1;
      let j = i + 2;
      let s = false;
      let d = false;
      while (j < region.length && depth > 0) {
        const c = region[j]!;
        if (!s && c === '`' && j + 1 < region.length) {
          j += 2;
          continue;
        }
        if (!d && isSingleQuoteChar(c)) s = !s;
        else if (!s && isDoubleQuoteChar(c)) d = !d;
        else if (!s && !d) {
          if (c === '(') depth++;
          else if (c === ')') depth--;
        }
        j++;
      }
      if (depth === 0) {
        const inner = region.slice(i + 2, j - 1).trim();
        if (inner) subs.push(inner);
        i = j - 1;
      }
    }
  }
}

/**
 * Masks single-quoted (`'...'`), double-quoted (`"..."`), here-string (`@'...'@` / `@"..."@`),
 * smart-quoted, and PowerShell comment (`# ...` / `<#...#>`) bodies with spaces while preserving
 * quote placeholders (`""` / `''`) and newlines so unquoted dialect/hang/binary regexes never
 * false-positive on commit messages, grep patterns, or literal strings.
 */
function maskQuotedLiterals(psCode: string): string {
  let out = '';
  let i = 0;
  while (i < psCode.length) {
    const ch = psCode[i]!;
    const next = psCode[i + 1] ?? '';

    // Stop-parsing token `--%` runs until next newline or `|`
    if (
      ch === '-' &&
      next === '-' &&
      psCode[i + 2] === '%' &&
      (i === 0 || /[\s;|&(]/.test(psCode[i - 1]!)) &&
      (i + 3 >= psCode.length || /[\s|;\r\n]/.test(psCode[i + 3]!))
    ) {
      out += '--%';
      i += 3;
      while (i < psCode.length && psCode[i] !== '\n' && psCode[i] !== '|') {
        out += psCode[i];
        i++;
      }
      continue;
    }

    // Block comment <# ... #>
    if (ch === '<' && next === '#') {
      const end = psCode.indexOf('#>', i + 2);
      if (end === -1) {
        out += ' '.repeat(psCode.length - i);
        break;
      }
      out += ' ';
      i = end + 2;
      continue;
    }

    // Line comment # ...
    if (ch === '#' && (i === 0 || /[\s;|&({]/.test(psCode[i - 1]!))) {
      while (i < psCode.length && psCode[i] !== '\n') i++;
      out += ' ';
      continue;
    }

    // Here-strings: @'...\n'@ or @"...\n"@
    const hs = matchHereString(psCode, i);
    if (hs) {
      out += hs.isSingle ? "''" : '""';
      i = hs.endIdx;
      continue;
    }

    // Single-quoted literal '...' (including smart single quotes)
    if (isSingleQuoteChar(ch)) {
      i++;
      while (i < psCode.length) {
        if (isSingleQuoteChar(psCode[i]!)) {
          if (isSingleQuoteChar(psCode[i + 1] ?? '')) {
            i += 2;
            continue;
          }
          i++;
          break;
        }
        i++;
      }
      out += "''";
      continue;
    }

    // Double-quoted literal "..." (including smart double quotes)
    if (isDoubleQuoteChar(ch)) {
      i++;
      while (i < psCode.length) {
        const c = psCode[i]!;
        if (c === '`' && i + 1 < psCode.length) {
          i += 2;
          continue;
        }
        if (isDoubleQuoteChar(c)) {
          if (isDoubleQuoteChar(psCode[i + 1] ?? '')) {
            i += 2;
            continue;
          }
          i++;
          break;
        }
        i++;
      }
      out += '""';
      continue;
    }

    out += ch;
    i++;
  }
  return out;
}

/**
 * Extracts `$(...)` subexpressions nested inside PowerShell double-quoted strings and
 * expandable here-strings `@"..."@` while strictly skipping `@'...'@` verbatim here-strings
 * and `#` / `<#...#>` comments.
 */
function extractDoubleQuotedSubexpressions(psCode: string): string[] {
  const subs: string[] = [];
  let inSingle = false;
  let inDouble = false;

  for (let i = 0; i < psCode.length; i++) {
    const ch = psCode[i]!;
    const next = psCode[i + 1] ?? '';

    if (!inSingle && !inDouble) {
      if (ch === '<' && next === '#') {
        const end = psCode.indexOf('#>', i + 2);
        if (end === -1) break;
        i = end + 1;
        continue;
      }
      if (ch === '#' && (i === 0 || /[\s;|&({]/.test(psCode[i - 1]!))) {
        while (i < psCode.length && psCode[i] !== '\n') i++;
        continue;
      }
      const hs = matchHereString(psCode, i);
      if (hs) {
        if (!hs.isSingle) {
          extractSubexpressionsFromRegion(psCode.slice(hs.bodyStart, hs.bodyEnd), subs);
        }
        i = hs.endIdx - 1;
        continue;
      }
    }

    if (!inDouble && isSingleQuoteChar(ch)) {
      if (inSingle && isSingleQuoteChar(next)) {
        i++;
        continue;
      }
      inSingle = !inSingle;
      continue;
    }
    if (inSingle) continue;

    if (inDouble && ch === '`' && i + 1 < psCode.length) {
      i++;
      continue;
    }
    if (isDoubleQuoteChar(ch)) {
      if (inDouble && isDoubleQuoteChar(next)) {
        i++;
        continue;
      }
      inDouble = !inDouble;
      continue;
    }

    if (inDouble && ch === '$' && next === '(') {
      let depth = 1;
      let j = i + 2;
      let s = false;
      let d = false;
      while (j < psCode.length && depth > 0) {
        const c = psCode[j]!;
        if (!s && c === '`' && j + 1 < psCode.length) {
          j += 2;
          continue;
        }
        if (!d && isSingleQuoteChar(c)) s = !s;
        else if (!s && isDoubleQuoteChar(c)) d = !d;
        else if (!s && !d) {
          if (c === '(') depth++;
          else if (c === ')') depth--;
        }
        j++;
      }
      if (depth === 0) {
        const inner = psCode.slice(i + 2, j - 1).trim();
        if (inner) subs.push(inner);
        i = j - 1;
      }
    }
  }
  return subs;
}

export function splitCompoundWindowsCommands(script: string): string[] {
  const parts: string[] = [];
  let cur = '';
  let inSingle = false;
  let inDouble = false;

  for (let i = 0; i < script.length; i++) {
    const ch = script[i]!;
    const next = script[i + 1] ?? '';

    if (!inSingle && !inDouble) {
      if (ch === '<' && next === '#') {
        const end = script.indexOf('#>', i + 2);
        if (end === -1) break;
        i = end + 1;
        continue;
      }
      if (ch === '#' && (i === 0 || /[\s;|&({]/.test(script[i - 1]!))) {
        while (i + 1 < script.length && script[i + 1] !== '\n') i++;
        continue;
      }
      const hs = matchHereString(script, i);
      if (hs) {
        cur += script.slice(i, hs.endIdx);
        i = hs.endIdx - 1;
        continue;
      }
    }

    if (!inDouble && isSingleQuoteChar(ch)) {
      if (inSingle && isSingleQuoteChar(next)) {
        cur += ch + next;
        i++;
        continue;
      }
      inSingle = !inSingle;
      cur += ch;
      continue;
    }
    if (!inSingle && isDoubleQuoteChar(ch)) {
      if (inDouble && isDoubleQuoteChar(next)) {
        cur += ch + next;
        i++;
        continue;
      }
      inDouble = !inDouble;
      cur += ch;
      continue;
    }
    if (inDouble && ch === '`' && i + 1 < script.length) {
      cur += ch + next;
      i++;
      continue;
    }
    if (!inSingle && !inDouble) {
      if (ch === '\n' || ch === '\r' || ch === ';') {
        if (cur.trim()) parts.push(cur.trim());
        cur = '';
        continue;
      }
      if ((ch === '&' && next === '&') || (ch === '|' && next === '|')) {
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

interface PwshToken {
  readonly text: string;
  readonly raw: string;
  readonly quoted: boolean;
}

function tokenizePwshLine(script: string): {
  invocationOp?: '&' | '.';
  tokens: PwshToken[];
  redirectionTargets: string[];
} {
  let s = script.trim();
  let invocationOp: '&' | '.' | undefined;
  if (s.startsWith('&')) {
    invocationOp = '&';
    s = s.slice(1).trimStart();
  } else if (/^\.(?:\s+|(?=['"\u2018\u2019\u201c\u201d$(]))/.test(s)) {
    invocationOp = '.';
    s = s.slice(1).trimStart();
  }

  const tokens: PwshToken[] = [];
  const redirectionTargets: string[] = [];
  let curText = '';
  let curRaw = '';
  let hadQuote = false;
  let inSingle = false;
  let inDouble = false;
  let pendingRedir = false;

  const flush = (): void => {
    if (curRaw.length === 0) return;
    if (pendingRedir) {
      redirectionTargets.push(curText);
      pendingRedir = false;
    } else {
      tokens.push({ text: curText, raw: curRaw, quoted: hadQuote });
    }
    curText = '';
    curRaw = '';
    hadQuote = false;
  };

  for (let i = 0; i < s.length; i++) {
    const ch = s[i]!;
    const next = s[i + 1] ?? '';

    if (inSingle) {
      curRaw += ch;
      if (isSingleQuoteChar(ch)) {
        if (isSingleQuoteChar(next)) {
          curText += "'";
          curRaw += next;
          i++;
        } else {
          inSingle = false;
        }
      } else {
        curText += ch;
      }
      continue;
    }
    if (inDouble) {
      curRaw += ch;
      if (ch === '`' && i + 1 < s.length) {
        curRaw += next;
        curText += next;
        i++;
      } else if (isDoubleQuoteChar(ch)) {
        if (isDoubleQuoteChar(next)) {
          curText += '"';
          curRaw += next;
          i++;
        } else {
          inDouble = false;
        }
      } else {
        curText += ch;
      }
      continue;
    }

    if (ch === '<' && next === '#') {
      const end = s.indexOf('#>', i + 2);
      flush();
      if (end === -1) break;
      i = end + 1;
      continue;
    }
    if (ch === '#' && (i === 0 || /[\s;|&({]/.test(s[i - 1]!))) {
      flush();
      while (i + 1 < s.length && s[i + 1] !== '\n') i++;
      continue;
    }

    const hs = matchHereString(s, i);
    if (hs) {
      flush();
      tokens.push({
        text: s.slice(hs.bodyStart, hs.bodyEnd),
        raw: s.slice(i, hs.endIdx),
        quoted: true,
      });
      i = hs.endIdx - 1;
      continue;
    }

    if (/\s/.test(ch)) {
      flush();
      continue;
    }
    if (isSingleQuoteChar(ch)) {
      inSingle = true;
      hadQuote = true;
      curRaw += ch;
      continue;
    }
    if (isDoubleQuoteChar(ch)) {
      inDouble = true;
      hadQuote = true;
      curRaw += ch;
      continue;
    }
    if (ch === '>' && (curRaw === '' || /^[12&*]$/.test(curRaw))) {
      curText = '';
      curRaw = '';
      hadQuote = false;
      if (next === '&') {
        // Stream merge like `2>&1`, not a file redirection
        if (s[i + 2] && /[0-9]/.test(s[i + 2]!)) {
          i += 2;
          continue;
        }
      }
      pendingRedir = true;
      if (next === '>') i++;
      continue;
    }
    curText += ch;
    curRaw += ch;
  }
  flush();

  return { invocationOp, tokens, redirectionTargets };
}

function isPwshTextOrSearchArg(bin0: string, tokens: readonly PwshToken[], idx: number): boolean {
  if (idx === 0) return false;
  if (SEARCH_OR_TEXT_CMDS.has(bin0)) {
    // For rg/grep/Select-String, the first non-flag positional or `-e`/`-Pattern` arg is the regex pattern
    const prev = tokens[idx - 1]?.text.toLowerCase() ?? '';
    if (prev === '-e' || prev === '--regexp' || prev === '-pattern' || prev === '--pattern') {
      return true;
    }
    if (bin0 === 'echo' || bin0 === 'write-output' || bin0 === 'write-host' || bin0 === 'write-verbose' || bin0 === 'write-debug') {
      return true;
    }
    let posCount = 0;
    for (let j = 1; j <= idx; j++) {
      const tj = tokens[j]!;
      if (tj.text.startsWith('-')) continue;
      const p = tokens[j - 1]?.text.toLowerCase() ?? '';
      if (p === '-e' || p === '-f' || p === '-path' || p === '-pattern' || p === '-g' || p === '--glob') continue;
      posCount++;
    }
    return posCount === 1;
  }
  if (bin0 === 'git' || bin0 === 'git.exe') {
    const sub = tokens[1]?.text.toLowerCase() ?? '';
    if (sub === 'commit' || sub === 'tag' || sub === 'notes' || sub === 'merge' || sub === 'revert') {
      const prev = tokens[idx - 1]?.text.toLowerCase() ?? '';
      if (prev === '-m' || prev === '--message' || prev === '-am') return true;
      if (tokens[idx]!.text.startsWith('--message=')) return true;
    }
    if (sub === 'grep') {
      const prev = tokens[idx - 1]?.text.toLowerCase() ?? '';
      if (prev === '-e') return true;
      let posCount = 0;
      for (let j = 2; j <= idx; j++) {
        if (!tokens[j]!.text.startsWith('-')) posCount++;
      }
      return posCount === 1;
    }
  }
  return false;
}

function stripOuterPwshQuotes(s: string): string {
  const trimmed = s.trim();
  if (trimmed.length >= 2) {
    const first = trimmed[0]!;
    const last = trimmed[trimmed.length - 1]!;
    if ((isSingleQuoteChar(first) && isSingleQuoteChar(last)) || (isDoubleQuoteChar(first) && isDoubleQuoteChar(last))) {
      return trimmed.slice(1, -1);
    }
  }
  return trimmed;
}

function cleanPwshArgFragment(s: string): string {
  return stripOuterPwshQuotes(s.trim().replace(/^[(),]+|[(),;]+$/g, ''))
    .replace(/[.,;)]+$/, '')
    .trim();
}

function isRegistryMutatingCmd(bin0: string): boolean {
  return (
    bin0 === 'set-itemproperty' ||
    bin0 === 'sp' ||
    bin0 === 'new-itemproperty' ||
    bin0 === 'remove-itemproperty' ||
    bin0 === 'rp' ||
    bin0 === 'set-item' ||
    bin0 === 'si'
  );
}

function isProtectedRegistryTarget(val: string): boolean {
  return /^(?:hklm|hkcu|hkcr|hku|hkcc):|^registry::|\\lxss(?:\\|$)/i.test(val);
}

function extractPwshCliInnerPayload(tokens: readonly PwshToken[]): {
  kind: 'encoded' | 'command' | 'file-stdin' | 'none';
  payload?: string;
} {
  for (let i = 1; i < tokens.length; i++) {
    const t = tokens[i]!.text;
    const encMatch = t.match(PWSH_ENCODED_TOKEN_RE);
    if (encMatch) {
      const val = encMatch[1] !== undefined && encMatch[1].length > 0 ? encMatch[1] : tokens[i + 1]?.text;
      return { kind: 'encoded', payload: val };
    }
    const cmdMatch = t.match(PWSH_COMMAND_FLAG_RE);
    if (cmdMatch) {
      const inline = cmdMatch[1] ? stripOuterPwshQuotes(cmdMatch[1]) : '';
      const rest = tokens.slice(i + 1).map((x) => x.text).join(' ').trim();
      const joined = [inline, rest].filter(Boolean).join(' ').trim();
      return { kind: 'command', payload: joined };
    }
    const fileMatch = t.match(PWSH_FILE_FLAG_RE);
    if (fileMatch) {
      const val = fileMatch[1] ? fileMatch[1] : tokens[i + 1]?.text;
      if (val === '-') return { kind: 'file-stdin' };
      if (!fileMatch[1]) i++;
      continue;
    }
    const valFlagMatch = t.match(PWSH_VALUE_FLAG_RE);
    if (valFlagMatch) {
      if (valFlagMatch[1] === undefined) i++;
      continue;
    }
    if (t.startsWith('-') || t.startsWith('/')) {
      continue;
    }
    // Positional script argument (e.g. `powershell.exe -NoProfile "Format-Volume -DriveLetter C"`)
    return {
      kind: 'command',
      payload: tokens.slice(i).map((x) => x.text).join(' ').trim(),
    };
  }
  return { kind: 'none' };
}

function extractAstPwshCliInnerPayload(elements: readonly SystemPwshCommandElement[]): {
  kind: 'encoded' | 'command' | 'file-stdin' | 'none';
  payload?: string;
} {
  for (let i = 1; i < elements.length; i++) {
    const el = elements[i]!;
    if (el.kind === 'CommandParameterAst' && el.parameterName) {
      const pFlag = `-${el.parameterName}`;
      if (PWSH_ENCODED_TOKEN_RE.test(pFlag)) {
        const val = el.argumentValue ?? el.argumentText ?? elements[i + 1]?.value ?? elements[i + 1]?.text;
        return { kind: 'encoded', payload: val ?? undefined };
      }
      if (PWSH_COMMAND_FLAG_RE.test(pFlag)) {
        const inline = el.argumentValue ?? (el.argumentText ? stripOuterPwshQuotes(el.argumentText) : '');
        const rest = elements
          .slice(i + 1)
          .map((x) => x.value ?? stripOuterPwshQuotes(x.text))
          .join(' ')
          .trim();
        return { kind: 'command', payload: [inline, rest].filter(Boolean).join(' ').trim() };
      }
      if (PWSH_FILE_FLAG_RE.test(pFlag)) {
        const val = el.argumentValue ?? el.argumentText ?? elements[i + 1]?.value ?? elements[i + 1]?.text;
        if (val?.trim() === '-') return { kind: 'file-stdin' };
        if (!el.argumentValue && !el.argumentText) i++;
        continue;
      }
      if (PWSH_VALUE_FLAG_RE.test(pFlag)) {
        if (!el.argumentValue && !el.argumentText) i++;
        continue;
      }
      continue;
    }

    const txt = el.value ?? stripOuterPwshQuotes(el.text);
    const encMatch = txt.match(PWSH_ENCODED_TOKEN_RE);
    if (encMatch) {
      const val = encMatch[1] !== undefined && encMatch[1].length > 0 ? encMatch[1] : elements[i + 1]?.value ?? elements[i + 1]?.text;
      return { kind: 'encoded', payload: val ?? undefined };
    }
    const cmdMatch = txt.match(PWSH_COMMAND_FLAG_RE);
    if (cmdMatch) {
      const inline = cmdMatch[1] ? stripOuterPwshQuotes(cmdMatch[1]) : '';
      const rest = elements
        .slice(i + 1)
        .map((x) => x.value ?? stripOuterPwshQuotes(x.text))
        .join(' ')
        .trim();
      return { kind: 'command', payload: [inline, rest].filter(Boolean).join(' ').trim() };
    }
    const fileMatch = txt.match(PWSH_FILE_FLAG_RE);
    if (fileMatch) {
      const val = fileMatch[1] ? fileMatch[1] : elements[i + 1]?.value ?? elements[i + 1]?.text;
      if (val?.trim() === '-') return { kind: 'file-stdin' };
      if (!fileMatch[1]) i++;
      continue;
    }
    const valMatch = txt.match(PWSH_VALUE_FLAG_RE);
    if (valMatch) {
      if (valMatch[1] === undefined) i++;
      continue;
    }
    if (txt.startsWith('-') || txt.startsWith('/')) {
      continue;
    }
    return {
      kind: 'command',
      payload: elements
        .slice(i)
        .map((x) => x.value ?? stripOuterPwshQuotes(x.text))
        .join(' ')
        .trim(),
    };
  }
  return { kind: 'none' };
}
function hasUnquotedChainOps(script: string): boolean {
  const masked = maskQuotedLiterals(script);
  return /(?:&&|\|\|)/.test(masked);
}

function evaluateStringAgainstRules(
  text: string,
  rules: ReadonlyArray<{ re: RegExp; reason: string; physical?: boolean; blockSessionPrefix?: boolean }>,
  onMatch: (rule: { re: RegExp; reason: string; physical?: boolean; blockSessionPrefix?: boolean }) => void,
): void {
  for (const rule of rules) {
    if (rule.re.test(text)) {
      onMatch(rule);
    }
  }
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

    const masked = maskQuotedLiterals(clean);
    const parsed = tokenizePwshLine(clean);
    const tokens = parsed.tokens;
    const tokenTexts = tokens.map((t) => t.text);
    if (tokenTexts.length > 0) {
      unwrappedCommands.push(tokenTexts);
    }

    const headText = tokens[0]?.text ?? '';
    const bin0 = basenameWin(headText).toLowerCase();

    // Detect dynamic invocation (`& $var`, `& (...)`, `. $var`, `& { ... }`)
    if (parsed.invocationOp && tokens[0] && !tokens[0].quoted && /^[$({]/.test(tokens[0].raw)) {
      escalate(
        'ask',
        'high',
        'Dynamic PowerShell command invocation (& $var / & (...)) requires single-shot approval',
        true,
      );
    }

    // Single-Shell Purity: block spawning a second PowerShell child after an outer statement
    if ((depth > 0 || segmentIndex > 0) && PWSH_BINARIES.has(bin0)) {
      escalate(
        'deny',
        'critical',
        `Single-shell purity violation: spawning nested ${bin0} subshell inside an existing PowerShell call is forbidden (causes quote-escaping hangs and encoding mismatches).`,
        true,
      );
    }

    // Catch quoted cmd.exe / pause / read-host / choice invoked as command head (`& "cmd.exe"`)
    if (bin0 === 'cmd' || bin0 === 'cmd.exe' || bin0 === '%comspec%' || bin0 === '$env:comspec') {
      escalate('deny', 'critical', L0_SINGLE_SHELL_AND_DIALECT_RULES[0]!.reason, true);
    }
    if (bin0 === 'read-host' || bin0 === 'pause' || bin0 === 'choice' || bin0 === 'choice.exe') {
      escalate('deny', 'critical', L0_SINGLE_SHELL_AND_DIALECT_RULES[3]!.reason, true);
    }

    // 1. Pre-execution Single-Shell Purity & Dialect Alignment on quote-masked script (L0 POLICY_BLOCK)
    evaluateStringAgainstRules(masked, L0_SINGLE_SHELL_AND_DIALECT_RULES, (rule) => {
      escalate('deny', 'critical', rule.reason, true);
    });

    // Check unquoted CMD slash-flags directly on aliased command heads
    if (CMD_ALIASED_CMDS.has(bin0)) {
      for (let i = 1; i < tokens.length; i++) {
        const tok = tokens[i]!;
        if (!tok.quoted && /^\/(?:s|q|f|y|a|b|o)(?:$|:)/i.test(tok.text)) {
          escalate('deny', 'critical', L0_SINGLE_SHELL_AND_DIALECT_RULES[5]!.reason, true);
        }
      }
    }

    // 2 & 3. Scope `-EncodedCommand` & unwrap ALL PowerShell CLI command modes (`-Command`, `-cwa`, `-comm`, positional)
    if (PWSH_BINARIES.has(bin0)) {
      const cli = extractPwshCliInnerPayload(tokens);
      if (cli.kind === 'encoded') {
        const decoded = cli.payload ? decodeBase64Utf16Le(cli.payload) : null;
        if (decoded) {
          escalate('ask', 'high', 'Encoded PowerShell command (-EncodedCommand) decoded and requires inspection', true);
          if (WINPS_51_BINARIES.has(bin0) && hasUnquotedChainOps(decoded)) {
            escalate(
              'deny',
              'critical',
              'Shell dialect mismatch: Windows PowerShell 5.1 (powershell.exe) does not support && or || chain operators.',
              true,
            );
          }
          inspect(decoded, depth + 1, 0);
        } else {
          escalate('deny', 'critical', 'Malformed/obfuscated PowerShell -EncodedCommand flag is forbidden', true);
        }
      } else if (cli.kind === 'file-stdin') {
        escalate('deny', 'critical', L0_SINGLE_SHELL_AND_DIALECT_RULES[3]!.reason, true);
      } else if (cli.kind === 'command' && cli.payload) {
        if (cli.payload === '-') {
          escalate('deny', 'critical', L0_SINGLE_SHELL_AND_DIALECT_RULES[3]!.reason, true);
        } else if (cli.payload !== clean) {
          if (WINPS_51_BINARIES.has(bin0) && hasUnquotedChainOps(cli.payload)) {
            escalate(
              'deny',
              'critical',
              'Shell dialect mismatch: Windows PowerShell 5.1 (powershell.exe) does not support && or || chain operators.',
              true,
            );
          }
          inspect(cli.payload, depth + 1, 0);
        }
      }
    }

    // 4. Inspect `$(...)` nested inside double-quoted strings / expandable here-strings
    for (const sub of extractDoubleQuotedSubexpressions(clean)) {
      inspect(sub, depth + 1, 0);
    }

    // 5. Split compound `;` / `&&` / `||` / `&` / `|` segments
    const segments = splitCompoundWindowsCommands(clean);
    if (segments.length > 1) {
      segments.forEach((seg, idx) => {
        if (seg !== clean) {
          inspect(seg, depth + 1, idx);
        }
      });
    }

    // 6. Invoke-Expression (`iex`) unwrapping
    if (bin0 === 'iex' || bin0 === 'invoke-expression') {
      escalate('ask', 'high', 'Dynamic Invoke-Expression (iex) requires approval', true);
      const argTok = tokens[1]?.text.toLowerCase() === '-command' ? tokens[2] : tokens[1];
      if (argTok && argTok.text && argTok.text !== clean) {
        inspect(argTok.text, depth + 1, 0);
      }
    } else if (/\b(?:iex|invoke-expression)\b/i.test(masked)) {
      escalate('ask', 'high', 'Dynamic Invoke-Expression (iex) requires approval', true);
    }

    // 7. Reverse WSL UNC paths, `nul` redirections & protected `.wslconfig` / `wsl.conf` / `fstab` config targets
    for (const redir of parsed.redirectionTargets) {
      const cleanedRedir = cleanPwshArgFragment(redir);
      if (/^nul$/i.test(cleanedRedir)) {
        escalate('deny', 'critical', L0_SINGLE_SHELL_AND_DIALECT_RULES[6]!.reason, true);
      }
      if (WSL_UNC_PATH_RE.test(cleanedRedir)) {
        escalate(
          'deny',
          'critical',
          'Accessing WSL filesystem via Windows UNC share (\\\\wsl$\\ or \\\\wsl.localhost\\) bypasses bwrap read-only locks and is forbidden',
          true,
        );
      }
      if (WSL_CONFIG_PATH_RE.test(cleanedRedir)) {
        escalate(
          'deny',
          'critical',
          'Modifying WSL system configuration (.wslconfig / wsl.conf / fstab) from model tools is forbidden',
          true,
        );
      }
    }

    const isFileOrConfigOp =
      FILE_CONFIG_CMDS.has(bin0) ||
      parsed.redirectionTargets.length > 0 ||
      /\[(?:system\.)?(?:io\.file|io\.directory|io\.fileinfo|io\.streamwriter|io\.path)\]::/i.test(masked);

    for (let i = 0; i < tokens.length; i++) {
      const tok = tokens[i]!;
      const isTextArg = isPwshTextOrSearchArg(bin0, tokens, i);
      const candidates = tok.text.includes('::') || tok.text.includes('(') ? tok.text.split(/[(),]+/) : [tok.text];
      for (const cand of candidates) {
        const cleanedCand = cleanPwshArgFragment(cand);
        if (!cleanedCand) continue;
        if (!isTextArg && WSL_UNC_PATH_RE.test(cleanedCand)) {
          escalate(
            'deny',
            'critical',
            'Accessing WSL filesystem via Windows UNC share (\\\\wsl$\\ or \\\\wsl.localhost\\) bypasses bwrap read-only locks and is forbidden',
            true,
          );
        }
        if (
          !isTextArg &&
          !SEARCH_OR_TEXT_CMDS.has(bin0) &&
          isFileOrConfigOp &&
          /(?:^|[\\/])(?:\.wslconfig|etc[\\/]wsl\.conf|etc[\\/]fstab)$/i.test(cleanedCand)
        ) {
          escalate(
            'deny',
            'critical',
            'Modifying WSL system configuration (.wslconfig / wsl.conf / fstab) from model tools is forbidden',
            true,
          );
        }
        if (!isTextArg && isRegistryMutatingCmd(bin0) && isProtectedRegistryTarget(cleanedCand)) {
          escalate('ask', 'high', 'Mutating Windows registry keys/values (HKLM/HKCU/Lxss) requires approval', true);
        }
      }
    }

    // Reconstruct unmasked head + unquoted args so `& "Format-Volume" -DriveLetter C` is still evaluated
    const headPlusUnquoted =
      tokens.length > 0
        ? [tokens[0]!.text, ...tokens.slice(1).map((t) => (t.quoted ? '""' : t.text))].join(' ')
        : '';

    // 8. Check L0 Hard Deny rules on masked script and head+unquoted invocation
    evaluateStringAgainstRules(masked, L0_DESTRUCTIVE_PATTERNS, (rule) => {
      escalate('deny', 'critical', rule.reason, true);
    });
    if (headPlusUnquoted && headPlusUnquoted !== masked) {
      evaluateStringAgainstRules(headPlusUnquoted, L0_DESTRUCTIVE_PATTERNS, (rule) => {
        escalate('deny', 'critical', rule.reason, true);
      });
    }

    // 9. Check L3 Approval rules (and physical device auto-downgrade)
    const onL3Match = (rule: { re: RegExp; reason: string; physical?: boolean; blockSessionPrefix?: boolean }): void => {
      if (rule.physical) touchesPhysicalDevice = true;
      escalate('ask', 'high', rule.reason, Boolean(rule.blockSessionPrefix));
    };
    evaluateStringAgainstRules(masked, L3_APPROVAL_PATTERNS, onL3Match);
    if (headPlusUnquoted && headPlusUnquoted !== masked) {
      evaluateStringAgainstRules(headPlusUnquoted, L3_APPROVAL_PATTERNS, onL3Match);
    }
  };

  inspect(command, 0, 0);

  const first = unwrappedCommands[0];
  let suggestedPrefix: string[] | undefined;
  let requiresSessionRuleBlocked =
    touchesPhysicalDevice ||
    decision === 'deny' ||
    forceBlockSessionRule ||
    unwrappedCommands.length !== 1;

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

function reconstructAstCommandStrings(cmd: SystemPwshCommandInfo): {
  unquotedText: string;
  argv: string[];
  argValues: Array<{ text: string; quoted: boolean }>;
} {
  const unquotedParts: string[] = [];
  const argv: string[] = [];
  const argValues: Array<{ text: string; quoted: boolean }> = [];

  for (let i = 0; i < cmd.elements.length; i++) {
    const el = cmd.elements[i]!;
    if (el.kind === 'CommandParameterAst' && el.parameterName) {
      const flag = `-${el.parameterName}`;
      unquotedParts.push(flag);
      argv.push(flag);
      argValues.push({ text: flag, quoted: false });
      if (el.argumentValue !== null && el.argumentValue !== undefined) {
        const argQuoted = /^['"\u2018\u2019\u201c\u201d]/.test(el.argumentText ?? '');
        unquotedParts.push(argQuoted ? '""' : el.argumentValue);
        argv.push(el.argumentValue);
        argValues.push({ text: el.argumentValue, quoted: argQuoted });
      } else if (el.argumentText) {
        unquotedParts.push(el.argumentText);
        argv.push(el.argumentText);
        argValues.push({ text: el.argumentText, quoted: false });
      }
      continue;
    }

    if (el.value !== null && el.value !== undefined) {
      const isQuoted = /^['"\u2018\u2019\u201c\u201d@]/u.test(el.text);
      unquotedParts.push(i === 0 ? el.value : isQuoted ? '""' : el.value);
      argv.push(el.value);
      argValues.push({ text: el.value, quoted: isQuoted });
    } else if (el.kind === 'ExpandableStringExpressionAst') {
      unquotedParts.push(i === 0 ? el.text : '""');
      argv.push(el.text);
      argValues.push({ text: el.text, quoted: true });
    } else {
      unquotedParts.push(el.text);
      argv.push(el.text);
      argValues.push({ text: el.text, quoted: /^['"\u2018\u2019\u201c\u201d@]/u.test(el.text) });
    }
  }

  return { unquotedText: unquotedParts.join(' '), argv, argValues };
}

/**
 * Authoritative Windows PowerShell guard combining deterministic lexical inspection with
 * official zero-execution `[System.Management.Automation.Language.Parser]::ParseInput` AST analysis.
 * Gracefully falls back to `evaluatePwshCommand` on non-Windows hosts or when PowerShell is unavailable.
 */
export async function evaluatePwshCommandWithSystemAst(
  command: string,
  depth = 0,
): Promise<GuardEvaluation> {
  const baseline = evaluatePwshCommand(command);
  if (typeof command !== 'string' || command.trim().length === 0 || command.length > MAX_GUARD_CHARS) {
    return baseline;
  }
  if (depth > MAX_WRAPPER_DEPTH) {
    return {
      ...baseline,
      decision: 'deny',
      riskLevel: 'critical',
      code: 'POLICY_BLOCK',
      reasons: [...baseline.reasons, `PowerShell AST inspection exceeded MAX_WRAPPER_DEPTH (${MAX_WRAPPER_DEPTH})`],
      requiresSessionRuleBlocked: true,
      suggestedPrefix: undefined,
    };
  }

  const ast = await parsePwshWithSystemParser(command);
  if (!ast) {
    return baseline;
  }

  const reasons = [...baseline.reasons];
  const unwrappedCommands = baseline.unwrappedCommands.map((c) => [...c]);
  let decision: 'allow' | 'ask' | 'deny' = baseline.decision;
  let riskLevel: 'safe' | 'elevated' | 'high' | 'critical' = baseline.riskLevel;
  let touchesPhysicalDevice = baseline.touchesPhysicalDevice;
  let forceBlockSessionRule = baseline.requiresSessionRuleBlocked;

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

  const mergeChildVerdict = (child: GuardEvaluation): void => {
    for (const r of child.reasons) {
      if (!reasons.includes(r)) reasons.push(r);
    }
    if (child.touchesPhysicalDevice) touchesPhysicalDevice = true;
    if (child.requiresSessionRuleBlocked) forceBlockSessionRule = true;
    if (child.decision === 'deny') {
      decision = 'deny';
      riskLevel = 'critical';
      forceBlockSessionRule = true;
    } else if (child.decision === 'ask' && decision !== 'deny') {
      decision = 'ask';
      const order = { safe: 0, elevated: 1, high: 2, critical: 3 };
      if (order[child.riskLevel] > order[riskLevel]) riskLevel = child.riskLevel;
    }
  };

  if (ast.hasStopParsing) {
    escalate(
      'deny',
      'critical',
      'Single-shell purity violation: PowerShell stop-parsing token (--%) is forbidden. Use pure PowerShell syntax or wsl_bash.',
      true,
    );
  }

  if (ast.hasDynamicInvocation || ast.commands.some((c) => c.dynamicInvocation)) {
    escalate(
      'ask',
      'high',
      'Dynamic PowerShell command invocation (& $var / & (...)) detected by System AST; requires single-shot approval',
      true,
    );
  }

  if (ast.errors.length > 0) {
    const firstErr = ast.errors[0]!;
    escalate(
      'ask',
      'high',
      `PowerShell syntax parse error (${ast.shell}: ${firstErr.errorId || 'ParseError'}): ${firstErr.message}`,
      true,
    );
  }

  // Inspect all AST FileRedirectionAst nodes
  for (const r of ast.redirections) {
    const target = (r.targetValue ?? r.targetText ?? '').trim();
    if (/^nul$/i.test(target)) {
      escalate(
        'deny',
        'critical',
        'Shell dialect mismatch: redirecting to "nul" (e.g. 2>nul) in PowerShell creates a literal DOS-reserved "nul" file that breaks Git and Windows Explorer. Use "$null" in PowerShell or "/dev/null" in wsl_bash.',
        true,
      );
    }
    if (WSL_UNC_PATH_RE.test(target)) {
      escalate(
        'deny',
        'critical',
        'Accessing WSL filesystem via Windows UNC share (\\\\wsl$\\ or \\\\wsl.localhost\\) bypasses bwrap read-only locks and is forbidden',
        true,
      );
    }
    if (WSL_CONFIG_PATH_RE.test(target)) {
      escalate(
        'deny',
        'critical',
        'Modifying WSL system configuration (.wslconfig / wsl.conf / fstab) from model tools is forbidden',
        true,
      );
    }
  }

  // Inspect every CommandAst (including nested $(...), "...", @"..."@, {...})
  let sawPwshCmdletCount = 0;
  for (let cmdIdx = 0; cmdIdx < ast.commands.length; cmdIdx++) {
    const cmd = ast.commands[cmdIdx]!;
    const { unquotedText, argv, argValues } = reconstructAstCommandStrings(cmd);
    const headRaw = argv[0] ?? '';
    const bin0 = basenameWin(headRaw).toLowerCase();

    if (PWSH_BINARIES.has(bin0)) {
      sawPwshCmdletCount++;
      if (cmdIdx > 0 || sawPwshCmdletCount > 1) {
        escalate(
          'deny',
          'critical',
          `Single-shell purity violation: spawning nested ${bin0} subshell inside an existing PowerShell call is forbidden (causes quote-escaping hangs and encoding mismatches).`,
          true,
        );
      }

      const cli = extractAstPwshCliInnerPayload(cmd.elements);
      if (cli.kind === 'encoded') {
        const decoded = cli.payload ? decodeBase64Utf16Le(cli.payload) : null;
        if (decoded) {
          escalate('ask', 'high', 'Encoded PowerShell command (-EncodedCommand) decoded and requires inspection', true);
          if (WINPS_51_BINARIES.has(bin0)) {
            const innerAst = await parsePwshWithSystemParser(decoded);
            if ((innerAst && innerAst.chainOperators.length > 0) || hasUnquotedChainOps(decoded)) {
              escalate(
                'deny',
                'critical',
                'Shell dialect mismatch: Windows PowerShell 5.1 (powershell.exe) does not support && or || chain operators.',
                true,
              );
            }
          }
          mergeChildVerdict(await evaluatePwshCommandWithSystemAst(decoded, depth + 1));
        } else {
          escalate('deny', 'critical', 'Malformed/obfuscated PowerShell -EncodedCommand flag is forbidden', true);
        }
      } else if (cli.kind === 'file-stdin') {
        escalate('deny', 'critical', L0_SINGLE_SHELL_AND_DIALECT_RULES[3]!.reason, true);
      } else if (cli.kind === 'command' && cli.payload) {
        if (cli.payload === '-') {
          escalate('deny', 'critical', L0_SINGLE_SHELL_AND_DIALECT_RULES[3]!.reason, true);
        } else {
          if (WINPS_51_BINARIES.has(bin0)) {
            const innerAst = await parsePwshWithSystemParser(cli.payload);
            if ((innerAst && innerAst.chainOperators.length > 0) || hasUnquotedChainOps(cli.payload)) {
              escalate(
                'deny',
                'critical',
                'Shell dialect mismatch: Windows PowerShell 5.1 (powershell.exe) does not support && or || chain operators.',
                true,
              );
            }
          }
          mergeChildVerdict(await evaluatePwshCommandWithSystemAst(cli.payload, depth + 1));
        }
      }
    }

    // Invoke-Expression (`iex`) static and expandable-string payload inspection
    if (bin0 === 'iex' || bin0 === 'invoke-expression') {
      escalate('ask', 'high', 'Dynamic Invoke-Expression (iex) requires approval', true);
      let payload: string | null | undefined;
      let targetEl: SystemPwshCommandElement | undefined;
      const el1 = cmd.elements[1];
      if (el1?.kind === 'CommandParameterAst' && el1.parameterName && /^c/i.test(el1.parameterName)) {
        targetEl = cmd.elements[2];
        payload = el1.argumentValue ?? targetEl?.value;
      } else {
        targetEl = el1;
        payload = el1?.value;
      }
      if (!payload && targetEl?.kind === 'ExpandableStringExpressionAst') {
        const hs = matchHereString(targetEl.text, 0);
        payload = hs ? targetEl.text.slice(hs.bodyStart, hs.bodyEnd) : stripOuterPwshQuotes(targetEl.text);
      }
      if (payload) {
        mergeChildVerdict(await evaluatePwshCommandWithSystemAst(payload, depth + 1));
      }
    }

    // Nested cmd / interactive hang head
    if (bin0 === 'cmd' || bin0 === 'cmd.exe' || bin0 === '%comspec%' || bin0 === '$env:comspec') {
      escalate('deny', 'critical', L0_SINGLE_SHELL_AND_DIALECT_RULES[0]!.reason, true);
    }
    if (bin0 === 'read-host' || bin0 === 'pause' || bin0 === 'choice' || bin0 === 'choice.exe') {
      escalate('deny', 'critical', L0_SINGLE_SHELL_AND_DIALECT_RULES[3]!.reason, true);
    }

    // CMD slash-flags on aliased commands (unquoted args only)
    if (CMD_ALIASED_CMDS.has(bin0)) {
      for (let i = 1; i < argValues.length; i++) {
        const av = argValues[i]!;
        if (!av.quoted && /^\/(?:s|q|f|y|a|b|o)(?:$|:)/i.test(av.text)) {
          escalate('deny', 'critical', L0_SINGLE_SHELL_AND_DIALECT_RULES[5]!.reason, true);
        }
      }
    }

    // Check UNC paths & protected `.wslconfig` / `wsl.conf` / `fstab` on AST arguments
    const pseudoTokens: PwshToken[] = argValues.map((av) => ({
      text: av.text,
      raw: av.text,
      quoted: av.quoted,
    }));
    const hasRedirs = (cmd.redirections?.length ?? 0) > 0 || ast.redirections.length > 0;
    const isFileOp =
      FILE_CONFIG_CMDS.has(bin0) ||
      hasRedirs ||
      /\[(?:system\.)?(?:io\.file|io\.directory|io\.fileinfo|io\.streamwriter|io\.path)\]::/i.test(cmd.text);

    for (let i = 0; i < pseudoTokens.length; i++) {
      const tok = pseudoTokens[i]!;
      const strippedTok = cleanPwshArgFragment(tok.text);
      const isTextArg = isPwshTextOrSearchArg(bin0, pseudoTokens, i);
      if (!isTextArg && WSL_UNC_PATH_RE.test(strippedTok)) {
        escalate(
          'deny',
          'critical',
          'Accessing WSL filesystem via Windows UNC share (\\\\wsl$\\ or \\\\wsl.localhost\\) bypasses bwrap read-only locks and is forbidden',
          true,
        );
      }
      if (
        !isTextArg &&
        !SEARCH_OR_TEXT_CMDS.has(bin0) &&
        isFileOp &&
        /(?:^|[\\/])(?:\.wslconfig|etc[\\/]wsl\.conf|etc[\\/]fstab)$/i.test(strippedTok)
      ) {
        escalate(
          'deny',
          'critical',
          'Modifying WSL system configuration (.wslconfig / wsl.conf / fstab) from model tools is forbidden',
          true,
        );
      }
      if (!isTextArg && isRegistryMutatingCmd(bin0) && isProtectedRegistryTarget(strippedTok)) {
        escalate('ask', 'high', 'Mutating Windows registry keys/values (HKLM/HKCU/Lxss) requires approval', true);
      }
    }

    // Evaluate L0 & L3 rules against AST-reconstructed unquoted command invocation
    evaluateStringAgainstRules(unquotedText, L0_SINGLE_SHELL_AND_DIALECT_RULES, (rule) => {
      escalate('deny', 'critical', rule.reason, true);
    });
    evaluateStringAgainstRules(unquotedText, L0_DESTRUCTIVE_PATTERNS, (rule) => {
      escalate('deny', 'critical', rule.reason, true);
    });
    evaluateStringAgainstRules(unquotedText, L3_APPROVAL_PATTERNS, (rule) => {
      if (rule.physical) touchesPhysicalDevice = true;
      escalate('ask', 'high', rule.reason, Boolean(rule.blockSessionPrefix));
    });
  }

  // Inspect static .NET member invocations (`[System.IO.File]::WriteAllText(...)`, `[Registry]::SetValue(...)`, etc.)
  for (const inv of ast.memberInvocations ?? []) {
    const isFileNetType = /\[(?:system\.)?(?:io\.file|io\.directory|io\.fileinfo|io\.streamwriter|io\.path)\]/i.test(inv.expression);
    const isRegNetType = /\[(?:microsoft\.win32\.)?registry\]/i.test(inv.expression);
    for (const arg of inv.arguments) {
      const cleanedArg = cleanPwshArgFragment(arg.value ?? arg.text);
      if (!cleanedArg) continue;
      if (WSL_UNC_PATH_RE.test(cleanedArg)) {
        escalate(
          'deny',
          'critical',
          'Accessing WSL filesystem via Windows UNC share (\\\\wsl$\\ or \\\\wsl.localhost\\) bypasses bwrap read-only locks and is forbidden',
          true,
        );
      }
      if (isFileNetType && /(?:^|[\\/])(?:\.wslconfig|etc[\\/]wsl\.conf|etc[\\/]fstab)$/i.test(cleanedArg)) {
        escalate(
          'deny',
          'critical',
          'Modifying WSL system configuration (.wslconfig / wsl.conf / fstab) from model tools is forbidden',
          true,
        );
      }
      if (isRegNetType && /(?:hklm|hkcu|hkey_local_machine|hkey_current_user|\\lxss\b)/i.test(cleanedArg)) {
        escalate('ask', 'high', 'Mutating Windows registry keys/values (HKLM/HKCU/Lxss) requires approval', true);
      }
    }
  }

  if (ast.commands.length > 1) {
    forceBlockSessionRule = true;
  }

  const first = unwrappedCommands[0];
  let suggestedPrefix: string[] | undefined;
  let requiresSessionRuleBlocked =
    touchesPhysicalDevice ||
    decision === 'deny' ||
    forceBlockSessionRule ||
    unwrappedCommands.length !== 1 ||
    ast.commands.length > 1;

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
