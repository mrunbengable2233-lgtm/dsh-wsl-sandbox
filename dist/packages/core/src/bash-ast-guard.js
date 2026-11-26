import { posix } from 'node:path';
import { isPathInside } from './binding.js';

/**
 * Checklist A: Zero-token deterministic Bash lexer/AST guard with 8-layer wrapper peeling,
 * heredoc/here-string/`$'...'`/line-continuation handling, dangerous command detection,
 * external path tracking, physical-device detection, and Codex BANNED_PREFIX_SUGGESTIONS enforcement.
 */

export const MAX_GUARD_CHARS = 64 * 1024;
export const MAX_WRAPPER_DEPTH = 8;

                                  
                                              
                                                                
                                 
                                      
                                                             
                                          
                                               
                                               
                                            
 

export const BANNED_PREFIX_SUGGESTIONS                                 = [
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
const INTERPRETER_BINARIES = new Set([
  'python', 'python2', 'python3', 'node', 'nodejs', 'perl', 'ruby', 'php', 'bun', 'deno', 'rscript', 'julia',
]);

const SIMPLE_WRAPPERS = new Set([
  'sudo', 'doas', 'command', 'exec', 'nohup', 'nice', 'ionice',
  'time', 'stdbuf', 'setsid', 'runuser', 'xargs',
]);

const WRAPPER_VALUE_FLAGS                                                = {
  sudo: new Set(['-u', '-g', '-C', '-D', '-h', '-p', '-r', '-t', '-U']),
  doas: new Set(['-u', '-C']),
  nice: new Set(['-n']),
  ionice: new Set(['-c', '-n', '-p']),
  stdbuf: new Set(['-i', '-o', '-e']),
  runuser: new Set(['-u', '-g', '-s', '-c']),
  timeout: new Set(['-k', '-s', '--kill-after', '--signal']),
  xargs: new Set(['-n', '-L', '-P', '-I', '-d', '-E', '-s', '-a', '--arg-file']),
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
const PHYSICAL_DEV_RE = /^\/dev\/(ttyUSB\d+|ttyACM\d+|ttyS\d+|bus\/usb\/|hidraw\d+|cdc-wdm\d+|video\d+|spidev|i2c-)/;

const PHYSICAL_FLASH_TOOLS = new Set([
  'esptool', 'esptool.py', 'openocd', 'avrdude', 'st-flash', 'st-info',
  'dfu-util', 'picotool', 'bossac', 'nrfjprog', 'probe-rs', 'pyocd',
  'minicom', 'picocom', 'tio', 'usbip', 'usbipd', 'usbreset',
  'heimdall', 'qdl', 'edl', 'mtk', 'rkdeveloptool', 'sunxi-fel',
]);

const ADB_READONLY_SUBCMDS = new Set(['devices', 'version', '--version', 'help', 'get-state', 'get-serialno', 'get-devpath']);
const FASTBOOT_READONLY_SUBCMDS = new Set(['devices', '--version', '-V', 'help', '--help', 'getvar']);

const CWD_CHANGING_CMDS = new Set(['cd', 'chdir', 'popd', 'pushd', 'push-location', 'set-location']);

const PATH_ARITY                                   = {
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
const GHA_CREDS_RE = /(?:^|\/)gha-creds-[^/]*\.json$/i;
const RAW_READ_TOOLS = new Set([
  'cat', 'head', 'tail', 'less', 'more', 'tac', 'nl', 'od', 'strings', 'xxd', 'hexdump',
  'base64', 'sha256sum', 'md5sum', 'stat', 'readlink', 'source', '.',
  'cp', 'mv', 'tee', 'install', 'truncate',
]);

function basenameCmd(token        )         {
  const idx = token.lastIndexOf('/');
  return idx >= 0 ? token.slice(idx + 1) : token;
}

export function isBannedPrefix(prefix                   )          {
  if (prefix.length === 0) return true;
  const lowered = prefix.map((t) => t.toLowerCase());
  const firstBase = basenameCmd(lowered[0] );
  for (const banned of BANNED_PREFIX_SUGGESTIONS) {
    if (banned.length === lowered.length && banned.every((b, i) => b.toLowerCase() === lowered[i])) {
      return true;
    }
    if (banned.length === 1 && banned[0] .toLowerCase() === firstBase && lowered.length >= 1) {
      return true;
    }
    if (
      banned.length === 2 &&
      lowered.length >= 2 &&
      banned[0] .toLowerCase() === firstBase &&
      banned[1] .toLowerCase() === lowered[1]
    ) {
      return true;
    }
  }
  return false;
}

                         
                            
                                   
                                                               
                                
 

                        
                                
                        
 

function normalizeIfs(script        )         {
  return script.replace(/\$\{IFS\}|\$IFS\b/g, ' ');
}

function decodeAnsiCEscape(content        )         {
  let out = '';
  for (let i = 0; i < content.length; i++) {
    const ch = content[i] ;
    if (ch !== '\\' || i + 1 >= content.length) {
      out += ch;
      continue;
    }
    const next = content[++i] ;
    if (next === 'n') out += '\n';
    else if (next === 'r') out += '\r';
    else if (next === 't') out += '\t';
    else if (next === 'v') out += '\v';
    else if (next === 'b') out += '\b';
    else if (next === 'f') out += '\f';
    else if (next === 'a') out += '\x07';
    else if (next === 'e' || next === 'E') out += '\x1b';
    else if (next === '\\' || next === "'" || next === '"' || next === '?') out += next;
    else if (next === 'x') {
      const m = content.slice(i + 1, i + 3).match(/^[0-9a-fA-F]{1,2}/);
      if (m) {
        out += String.fromCharCode(parseInt(m[0], 16));
        i += m[0].length;
      } else {
        out += '\\x';
      }
    } else if (next === 'u') {
      const m = content.slice(i + 1, i + 5).match(/^[0-9a-fA-F]{1,4}/);
      if (m) {
        out += String.fromCodePoint(parseInt(m[0], 16));
        i += m[0].length;
      } else {
        out += '\\u';
      }
    } else if (next === 'U') {
      const m = content.slice(i + 1, i + 9).match(/^[0-9a-fA-F]{1,8}/);
      if (m) {
        const cp = parseInt(m[0], 16);
        out += cp <= 0x10ffff ? String.fromCodePoint(cp) : '';
        i += m[0].length;
      } else {
        out += '\\U';
      }
    } else if (/^[0-7]$/.test(next)) {
      const m = content.slice(i, i + 3).match(/^[0-7]{1,3}/);
      if (m) {
        out += String.fromCharCode(parseInt(m[0], 8));
        i += m[0].length - 1;
      }
    } else {
      out += '\\' + next;
    }
  }
  return out;
}

/**
 * Strips Bash `\<LF>` / `\<CRLF>` line continuations outside `'...'` and `$'...'` on non-heredoc
 * command lines AND extracts `<<` / `<<-` heredoc bodies so literal prose inside `<<'EOF'` is never
 * misparsed as commands while unquoted `<<EOF` and shell-fed heredocs remain inspected.
 */
function stripContinuationsAndExtractHeredocs(rawScript        )   
                 
                                      
  {
  const lines = rawScript.split('\n');
  const outLines           = [];
  const heredocs = new Map                      ();
  const active         
                     
                      
                       
                         
                        
     = [];

  let hdSeq = 0;
  let inSingle = false;
  let inDouble = false;
  let inAnsiC = false;

  for (let li = 0; li < lines.length; li++) {
    let line = (lines[li] ?? '').replace(/\r$/, '');

    if (active.length > 0) {
      const curHd = active[0] ;
      const candidate = curHd.stripTabs ? line.replace(/^\t+/, '') : line;
      if (candidate === curHd.delimiter) {
        active.shift();
        heredocs.set(curHd.tokenKey, {
          quotedDelim: curHd.quotedDelim,
          body: curHd.bodyLines.join('\n'),
        });
        outLines.push('');
      } else {
        curHd.bodyLines.push(candidate);
        outLines.push('');
      }
      continue;
    }

    let outLine = '';
    for (let i = 0; i < line.length; i++) {
      const ch = line[i] ;
      const next = line[i + 1] ?? '';

      if (inSingle) {
        outLine += ch;
        if (ch === "'") inSingle = false;
        continue;
      }

      if (inAnsiC) {
        if (ch === '\\' && i + 1 < line.length) {
          outLine += ch + line[i + 1] ;
          i++;
          continue;
        }
        outLine += ch;
        if (ch === "'") inAnsiC = false;
        continue;
      }

      if (inDouble) {
        if (ch === '\\') {
          if (i === line.length - 1 && li + 1 < lines.length) {
            li++;
            line = line + (lines[li] ?? '').replace(/\r$/, '');
            continue;
          }
          if (i + 1 < line.length) {
            outLine += ch + line[i + 1] ;
            i++;
          }
          continue;
        }
        outLine += ch;
        if (ch === '"') inDouble = false;
        continue;
      }

      // Unquoted backslash: line continuation if at end of line
      if (ch === '\\') {
        if (i === line.length - 1 && li + 1 < lines.length) {
          li++;
          line = line + (lines[li] ?? '').replace(/\r$/, '');
          continue;
        }
        if (i + 1 < line.length) {
          outLine += ch + line[i + 1] ;
          i++;
        }
        continue;
      }

      // Comment outside quotes
      if (ch === '#' && (i === 0 || /[\s;|&({]/.test(line[i - 1] ))) {
        outLine += line.slice(i);
        break;
      }

      if (ch === '$' && next === "'") {
        inAnsiC = true;
        outLine += "$'";
        i++;
        continue;
      }
      if (ch === "'") {
        inSingle = true;
        outLine += ch;
        continue;
      }
      if (ch === '"') {
        inDouble = true;
        outLine += ch;
        continue;
      }

      // Here-string `<<<` (must skip all 3 chars so 2nd+3rd `<` aren't parsed as heredoc `<<`)
      if (ch === '<' && next === '<' && line[i + 2] === '<') {
        outLine += '<<<';
        i += 2;
        continue;
      }

      // Heredoc `<<` / `<<-`
      if (ch === '<' && next === '<') {
        let pos = i + 2;
        let stripTabs = false;
        if (line[pos] === '-') {
          stripTabs = true;
          pos++;
        }
        while (pos < line.length && (line[pos] === ' ' || line[pos] === '\t')) pos++;
        let delim = '';
        let quotedDelim = false;
        let dSingle = false;
        let dDouble = false;
        let p = pos;
        while (p < line.length) {
          const dc = line[p] ;
          if (dSingle) {
            if (dc === "'") dSingle = false;
            else delim += dc;
            p++;
            continue;
          }
          if (dDouble) {
            if (dc === '\\' && p + 1 < line.length) {
              delim += line[p + 1] ;
              p += 2;
              continue;
            }
            if (dc === '"') dDouble = false;
            else delim += dc;
            p++;
            continue;
          }
          if (dc === '\\' && p + 1 < line.length) {
            quotedDelim = true;
            delim += line[p + 1] ;
            p += 2;
            continue;
          }
          if (dc === "'") {
            quotedDelim = true;
            dSingle = true;
            p++;
            continue;
          }
          if (dc === '"') {
            quotedDelim = true;
            dDouble = true;
            p++;
            continue;
          }
          if (/[\s;|&<>()]/.test(dc)) break;
          delim += dc;
          p++;
        }

        if (delim.length > 0) {
          const tokenKey = `__DSH_HD_${hdSeq++}__`;
          active.push({ tokenKey, delimiter: delim, stripTabs, quotedDelim, bodyLines: [] });
          outLine += `<< ${tokenKey}`;
          i = p - 1;
          continue;
        }
      }

      outLine += ch;
    }

    outLines.push(outLine);
  }

  // Unclosed heredoc fallback: still capture whatever lines remained
  for (const rem of active) {
    heredocs.set(rem.tokenKey, {
      quotedDelim: rem.quotedDelim,
      body: rem.bodyLines.join('\n'),
    });
  }

  return { script: outLines.join('\n'), heredocs };
}

function maskQuotedBashLiterals(script        )         {
  let out = '';
  let inSingle = false;
  let inDouble = false;
  let inAnsiC = false;

  for (let i = 0; i < script.length; i++) {
    const ch = script[i] ;
    if (inSingle) {
      if (ch === "'") {
        inSingle = false;
        out += "'";
      } else {
        out += ' ';
      }
      continue;
    }
    if (inAnsiC) {
      if (ch === '\\' && i + 1 < script.length) {
        out += '  ';
        i++;
        continue;
      }
      if (ch === "'") {
        inAnsiC = false;
        out += "'";
      } else {
        out += ' ';
      }
      continue;
    }
    if (inDouble) {
      if (ch === '\\' && i + 1 < script.length) {
        out += '  ';
        i++;
        continue;
      }
      if (ch === '"') {
        inDouble = false;
        out += '"';
      } else {
        out += ' ';
      }
      continue;
    }
    if (ch === '\\' && i + 1 < script.length) {
      out += ch + script[i + 1] ;
      i++;
      continue;
    }
    if (ch === '$' && script[i + 1] === "'") {
      inAnsiC = true;
      out += "$'";
      i++;
      continue;
    }
    if (ch === "'") {
      inSingle = true;
      out += "'";
      continue;
    }
    if (ch === '"') {
      inDouble = true;
      out += '"';
      continue;
    }
    out += ch;
  }
  return out;
}

function extractSubstitutions(script        )           {
  const nested           = [];
  let inSingle = false;
  let inDouble = false;
  let inAnsiC = false;

  for (let i = 0; i < script.length; i++) {
    const ch = script[i] ;
    if (inAnsiC) {
      if (ch === '\\') i++;
      else if (ch === "'") inAnsiC = false;
      continue;
    }
    if (ch === '\\' && !inSingle) {
      i++;
      continue;
    }
    if (!inSingle && !inDouble && ch === '$' && script[i + 1] === "'") {
      inAnsiC = true;
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

    // $( ... ) always; <( ... ) and >( ... ) ONLY outside double quotes!
    if ((ch === '$' || (!inDouble && (ch === '<' || ch === '>'))) && script[i + 1] === '(') {
      let depth = 1;
      let j = i + 2;
      let s = false;
      let d = false;
      let a = false;
      while (j < script.length && depth > 0) {
        const c = script[j] ;
        if (a) {
          if (c === '\\') { j += 2; continue; }
          if (c === "'") a = false;
          j++;
          continue;
        }
        if (c === '\\' && !s) {
          j += 2;
          continue;
        }
        if (!s && !d && c === '$' && script[j + 1] === "'") {
          a = true;
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

function consumeBalancedBlock(script        , startOpenIdx        , openChar           , closeChar           )   
               
                 
  {
  let depth = 1;
  let j = startOpenIdx + 1;
  let s = false;
  let d = false;
  let a = false;
  while (j < script.length && depth > 0) {
    const c = script[j] ;
    if (a) {
      if (c === '\\' && j + 1 < script.length) {
        j += 2;
        continue;
      }
      if (c === "'") a = false;
      j++;
      continue;
    }
    if (c === '\\' && !s) {
      j += 2;
      continue;
    }
    if (!s && !d && c === '$' && script[j + 1] === "'") {
      a = true;
      j += 2;
      continue;
    }
    if (c === "'" && !d) s = !s;
    else if (c === '"' && !s) d = !d;
    else if (!s && !d) {
      if (c === openChar) depth++;
      else if (c === closeChar) depth--;
    }
    j++;
  }
  return { text: script.slice(startOpenIdx, j), endIdx: j - 1 };
}

function tokenizeBashSegments(script        )                  {
  const segments                  = [];
  let tokens           = [];
  let quotedTokens            = [];
  let redirections                                        = [];
  let cur = '';
  let curHadQuote = false;
  let inSingle = false;
  let inDouble = false;
  let inAnsiC = false;
  let ansiBuf = '';
  let pendingRedir                = null;

  const flushToken = ()       => {
    if (cur.length === 0 && !curHadQuote) return;
    if (pendingRedir !== null) {
      redirections.push({ op: pendingRedir, target: cur });
      pendingRedir = null;
    } else {
      tokens.push(cur);
      quotedTokens.push(curHadQuote);
    }
    cur = '';
    curHadQuote = false;
  };

  const flushSegment = (piped         )       => {
    flushToken();
    if (tokens.length > 0 || redirections.length > 0) {
      segments.push({ tokens, quotedTokens, redirections, pipedToNext: piped });
      tokens = [];
      quotedTokens = [];
      redirections = [];
    }
  };

  for (let i = 0; i < script.length; i++) {
    const ch = script[i] ;
    const next = script[i + 1] ?? '';

    if (inSingle) {
      if (ch === "'") inSingle = false;
      else cur += ch;
      continue;
    }

    if (inAnsiC) {
      if (ch === '\\' && i + 1 < script.length) {
        ansiBuf += ch + script[i + 1] ;
        i++;
      } else if (ch === "'") {
        inAnsiC = false;
        cur += decodeAnsiCEscape(ansiBuf);
        ansiBuf = '';
      } else {
        ansiBuf += ch;
      }
      continue;
    }

    if (inDouble) {
      if (ch === '\\' && (next === '"' || next === '\\' || next === '$' || next === '`')) {
        cur += next;
        i++;
      } else if (ch === '$' && next === '(') {
        const blk = consumeBalancedBlock(script, i + 1, '(', ')');
        cur += '$' + blk.text;
        i = blk.endIdx;
      } else if (ch === '"') {
        inDouble = false;
      } else {
        cur += ch;
      }
      continue;
    }

    // Comments outside quotes
    if (ch === '#' && cur.length === 0 && !curHadQuote) {
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

    if (ch === '$' && next === "'") {
      inAnsiC = true;
      curHadQuote = true;
      ansiBuf = '';
      i++;
      continue;
    }

    if (ch === "'") {
      inSingle = true;
      curHadQuote = true;
      continue;
    }
    if (ch === '"') {
      inDouble = true;
      curHadQuote = true;
      continue;
    }

    // Preserve $(...), <(...), >(...), ${...} inside current token rather than splitting segments on inner parens
    if ((ch === '$' || ch === '<' || ch === '>') && next === '(') {
      const blk = consumeBalancedBlock(script, i + 1, '(', ')');
      cur += ch + blk.text;
      i = blk.endIdx;
      continue;
    }
    if (ch === '$' && next === '{') {
      const blk = consumeBalancedBlock(script, i + 1, '{', '}');
      cur += '$' + blk.text;
      i = blk.endIdx;
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
      if (next === '>') {
        flushToken();
        if (script[i + 2] === '>') {
          pendingRedir = '&>>';
          i += 2;
        } else {
          pendingRedir = '&>';
          i++;
        }
        continue;
      }
      flushSegment(false);
      continue;
    }

    // Redirections (<<<, <<, <&, <, >>, >|, >&, >)
    if (ch === '>' || ch === '<') {
      if (/^\d+$/.test(cur)) {
        cur = '';
      } else {
        flushToken();
      }
      if (ch === '<' && next === '<' && script[i + 2] === '<') {
        pendingRedir = '<<<';
        i += 2;
      } else if (ch === '>' && (next === '>' || next === '|' || next === '&')) {
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

    // Standalone subshell parens (not $(, <(, >()
    if (ch === '(' || ch === ')') {
      flushSegment(false);
      continue;
    }

    cur += ch;
  }

  if (inAnsiC && ansiBuf.length > 0) {
    cur += decodeAnsiCEscape(ansiBuf);
  }
  flushSegment(false);
  return segments;
}

function isForkBomb(script        )          {
  const masked = maskQuotedBashLiterals(script);
  if (/:\s*\(\s*\)\s*\{[^}]*:\s*\|\s*:\s*&[^}]*\}/.test(masked)) return true;
  // Generic named recursive background pipe bomb: foo(){ foo|foo& }; foo
  const m = masked.match(/\b([A-Za-z_]\w*)\s*\(\s*\)\s*\{([^}]*)\}/);
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

                           
                             
                                 
                                         
 

function parseEnvArgs(
  args                   ,
  onChdir                        ,
)                  {
  let i = 0;
  while (i < args.length) {
    const a = args[i] ;
    if (a === '--') {
      i++;
      break;
    }
    if (a === '--ignore-environment') {
      i++;
      continue;
    }
    if (a === '--unset') {
      i += 2;
      continue;
    }
    if (a.startsWith('--unset=')) {
      i++;
      continue;
    }
    if (a === '--chdir') {
      if (args[i + 1]) onChdir?.(args[i + 1] );
      i += 2;
      continue;
    }
    if (a.startsWith('--chdir=')) {
      onChdir?.(a.slice('--chdir='.length));
      i++;
      continue;
    }
    if (a === '--split-string' || a.startsWith('--split-string=')) {
      const splitPayload = a === '--split-string' ? args[i + 1] ?? '' : a.slice('--split-string='.length);
      const consumed = a === '--split-string' ? 2 : 1;
      return { nextIndex: i + consumed, splitPayload, remaining: args.slice(i + consumed) };
    }
    if (a.startsWith('-') && a.length > 1 && !a.startsWith('--')) {
      let consumedNext = false;
      for (let k = 1; k < a.length; k++) {
        const flagCh = a[k] ;
        if (flagCh === 'i' || flagCh === '0' || flagCh === 'v') {
          continue;
        }
        if (flagCh === 'u') {
          if (k + 1 >= a.length) consumedNext = true;
          break;
        }
        if (flagCh === 'C') {
          const dir = k + 1 < a.length ? a.slice(k + 1) : args[i + 1];
          if (dir) onChdir?.(dir);
          if (k + 1 >= a.length) consumedNext = true;
          break;
        }
        if (flagCh === 'S') {
          const splitPayload = k + 1 < a.length ? a.slice(k + 1) : args[i + 1] ?? '';
          const consumed = k + 1 < a.length ? 1 : 2;
          return { nextIndex: i + consumed, splitPayload, remaining: args.slice(i + consumed) };
        }
      }
      i += consumedNext ? 2 : 1;
      continue;
    }
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(a)) {
      i++;
      continue;
    }
    break;
  }
  return { nextIndex: i };
}

function unwrapPipeTargetCmd(rawTokens                   , depth = 0)         {
  if (depth > MAX_WRAPPER_DEPTH || rawTokens.length === 0) return '';
  let idx = 0;
  while (idx < rawTokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(rawTokens[idx] )) {
    idx++;
  }
  const tokens = rawTokens.slice(idx);
  if (tokens.length === 0) return '';

  const cmd = basenameCmd(tokens[0] );
  const args = tokens.slice(1);

  if (cmd === 'env') {
    const parsedEnv = parseEnvArgs(args);
    if (parsedEnv.splitPayload !== undefined) {
      const splitSegs = tokenizeBashSegments(parsedEnv.splitPayload);
      if (splitSegs[0]?.tokens.length) {
        return unwrapPipeTargetCmd([...splitSegs[0].tokens, ...(parsedEnv.remaining ?? [])], depth + 1);
      }
      return unwrapPipeTargetCmd(parsedEnv.remaining ?? [], depth + 1);
    }
    return unwrapPipeTargetCmd(args.slice(parsedEnv.nextIndex), depth + 1);
  }

  if (cmd === 'timeout') {
    let i = 0;
    const valFlags = WRAPPER_VALUE_FLAGS.timeout ;
    while (i < args.length && args[i] .startsWith('-')) {
      const f = args[i] ;
      if (f === '--') {
        i++;
        break;
      }
      if (f.includes('=')) {
        i++;
        continue;
      }
      i += valFlags.has(f) ? 2 : 1;
    }
    if (i < args.length) i++;
    return unwrapPipeTargetCmd(args.slice(i), depth + 1);
  }

  if (cmd === 'busybox' && args[0] && !args[0].startsWith('-')) {
    return unwrapPipeTargetCmd(args, depth + 1);
  }

  if (SIMPLE_WRAPPERS.has(cmd)) {
    let i = 0;
    const valFlags = WRAPPER_VALUE_FLAGS[cmd];
    while (i < args.length && args[i] .startsWith('-')) {
      const f = args[i] ;
      if (f === '--') {
        i++;
        break;
      }
      if (f.includes('=')) {
        i++;
        continue;
      }
      if (cmd === 'xargs' && f.startsWith('-a') && f.length > 2) {
        i++;
        continue;
      }
      i += valFlags?.has(f) ? 2 : 1;
    }
    return unwrapPipeTargetCmd(args.slice(i), depth + 1);
  }

  return cmd;
}

const GIT_GLOBAL_VALUE_FLAGS = new Set([
  '-C', '-c', '--git-dir', '--work-tree', '--namespace', '--super-prefix', '--exec-path', '--config-env',
]);

function findGitSubcommandIndex(args                   )         {
  let i = 0;
  while (i < args.length) {
    const a = args[i] ;
    if (a === '--') {
      i++;
      break;
    }
    if (GIT_GLOBAL_VALUE_FLAGS.has(a)) {
      i += 2;
      continue;
    }
    if (a.startsWith('-')) {
      i++;
      continue;
    }
    break;
  }
  return i;
}

function isBashTextOrPatternArg(cmd        , args                   , argIdx        )          {
  if (cmd === 'echo' || cmd === 'printf') {
    return true;
  }
  if (cmd === 'git') {
    const subIdx = findGitSubcommandIndex(args);
    if (argIdx <= subIdx) return false;
    const sub = args[subIdx];
    if (sub === 'commit' || sub === 'tag' || sub === 'notes' || sub === 'merge' || sub === 'revert') {
      const cur = args[argIdx] ?? '';
      const prev = args[argIdx - 1] ?? '';
      if (prev === '-m' || prev === '--message' || prev === '-am' || cur.startsWith('--message=')) {
        return true;
      }
    }
    if (sub === 'grep') {
      const prev = args[argIdx - 1] ?? '';
      if (prev === '-e') return true;
      let posCount = 0;
      for (let j = subIdx + 1; j <= argIdx; j++) {
        const aj = args[j] ;
        if (aj.startsWith('-')) continue;
        const p = args[j - 1] ?? '';
        if (p === '-e' || p === '-f') continue;
        posCount++;
      }
      return posCount === 1;
    }
  }
  if (cmd === 'rg' || cmd === 'grep' || cmd === 'egrep' || cmd === 'fgrep' || cmd === 'ag') {
    const prev = args[argIdx - 1] ?? '';
    if (prev === '-e' || prev === '--regexp') return true;
    let posCount = 0;
    for (let j = 0; j <= argIdx; j++) {
      const aj = args[j] ;
      if (aj.startsWith('-')) continue;
      const p = args[j - 1] ?? '';
      if (p === '-e' || p === '--regexp' || p === '-f' || p === '--file' || p === '-g' || p === '--glob') continue;
      posCount++;
    }
    return posCount === 1;
  }
  return false;
}

function extractInlineInterpreterCode(cmd        , args                   )                {
  const lower = cmd.toLowerCase();
  if (lower === 'python' || lower === 'python2' || lower === 'python3') {
    for (let i = 0; i < args.length; i++) {
      const a = args[i] ;
      if (a === '-c' && i + 1 < args.length) return args[i + 1] ;
      if (a.startsWith('-c') && a.length > 2) return a.slice(2);
    }
  } else if (lower === 'node' || lower === 'nodejs' || lower === 'bun') {
    for (let i = 0; i < args.length; i++) {
      const a = args[i] ;
      if ((a === '-e' || a === '--eval' || a === '-p' || a === '--print') && i + 1 < args.length) {
        return args[i + 1] ;
      }
      if (a.startsWith('--eval=')) return a.slice('--eval='.length);
      if (a.startsWith('--print=')) return a.slice('--print='.length);
      if (/^-[a-zA-Z]*[ep][a-zA-Z]*$/.test(a) && i + 1 < args.length) {
        return args[i + 1] ;
      }
    }
  } else if (lower === 'perl' || lower === 'ruby') {
    for (let i = 0; i < args.length; i++) {
      const a = args[i] ;
      if ((a === '-e' || (lower === 'perl' && a === '-E')) && i + 1 < args.length) {
        return args[i + 1] ;
      }
    }
  } else if (lower === 'php') {
    for (let i = 0; i < args.length; i++) {
      if (args[i] === '-r' && i + 1 < args.length) return args[i + 1] ;
    }
  } else if (lower === 'deno') {
    if (args[0] === 'eval' && args.length >= 2) {
      return args.slice(1).join(' ');
    }
  } else if (lower === 'julia') {
    for (let i = 0; i < args.length; i++) {
      const a = args[i] ;
      if ((a === '-e' || a === '--eval') && i + 1 < args.length) return args[i + 1] ;
      if (a.startsWith('--eval=')) return a.slice('--eval='.length);
    }
  }
  return null;
}

                                   
                                 
                        
                                                 
                                                                    
                                                                    
 

export function evaluateBashCommand(command        , ctx                  )                  {
  const reasons           = [];
  const unwrappedCommands             = [];
  const externalPaths = new Set        ();
  let decision                           = 'allow';
  let riskLevel                                            = 'safe';
  let touchesPhysicalDevice =
    (ctx.activeDeviceNodes?.length ?? 0) > 0 || (ctx.authorizedDevices?.length ?? 0) > 0;
  let forceBlockSessionRule = false;
  let trackedCwd = ctx.cwd ?? ctx.workspaceRoot;

  const escalate = (
    nextDecision                ,
    nextRisk                                  ,
    reason        ,
    blockPrefix = false,
  )       => {
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

  const extractPathValue = (rawArg        )                => {
    if (!rawArg) return null;
    if (rawArg.startsWith('-')) {
      const eq = rawArg.indexOf('=');
      if (eq > 1) {
        return rawArg.slice(eq + 1);
      }
      return null;
    }
    const eq = rawArg.indexOf('=');
    if (eq > 0 && /^[A-Za-z_][A-Za-z0-9_]*=/.test(rawArg)) {
      return rawArg.slice(eq + 1);
    }
    return rawArg;
  };

  const checkPath = (rawPath        , trackExternal = true)       => {
    const extracted = extractPathValue(rawPath);
    if (!extracted) return;
    if (GHA_CREDS_RE.test(extracted) || /gha-creds-.*\.json/i.test(posix.basename(extracted))) {
      escalate('deny', 'critical', 'Access to GitHub Actions credential file (gha-creds-*.json) is forbidden', true);
    }
    const resolved = extracted.startsWith('/')
      ? posix.normalize(extracted)
      : posix.normalize(posix.join(trackedCwd, extracted));
    if (PHYSICAL_DEV_RE.test(resolved)) {
      touchesPhysicalDevice = true;
      escalate('ask', 'high', `Physical hardware device access detected (${resolved}); requires manual single-shot approval`, true);
    }
    if (BLOCK_DEV_RE.test(resolved)) {
      escalate('deny', 'critical', `Raw block device target is forbidden: ${resolved}`, true);
    }
    if (WIN_DRIVE_MNT_RE.test(resolved) || resolved === '/mnt') {
      escalate('deny', 'critical', `Direct Windows drive (/mnt) access from WSL sandbox is forbidden: ${resolved}`, true);
    }
    for (const sysPrefix of SYSTEM_PROTECTED_PREFIXES) {
      if (resolved === sysPrefix || resolved.startsWith(sysPrefix + '/')) {
        escalate('deny', 'critical', `Protected WSL/system path access is forbidden: ${resolved}`, true);
      }
    }
    if (
      trackExternal &&
      !resolved.startsWith('/tmp/') &&
      resolved !== '/tmp' &&
      resolved !== '/dev/null' &&
      !resolved.startsWith('/shares/') &&
      !isPathInside(ctx.workspaceRoot, resolved)
    ) {
      externalPaths.add(resolved);
    }
  };

  const scanCodeBodyForL0AndDevices = (codeBody        )       => {
    const winMntMatch = codeBody.match(/(?:^|[\s"'(=])(\/mnt\/[a-zA-Z](?:\/[^\s"')]*)?)/);
    if (winMntMatch?.[1]) {
      checkPath(winMntMatch[1], false);
    }
    const sysMatch = codeBody.match(/(?:^|[\s"'(=])(\/(?:etc\/wsl\.conf|etc\/fstab|run\/WSL|mnt\/wsl(?:g\/distro)?))/);
    if (sysMatch?.[1]) {
      checkPath(sysMatch[1], false);
    }
    const blkMatch = codeBody.match(/(?:^|[\s"'(=])(\/dev\/(?:sd|hd|nvme|mmcblk|vd|xvd|disk|mapper|dm-|md|sr|loop|zram|ram)[^\s"']*)/);
    if (blkMatch?.[1]) {
      checkPath(blkMatch[1], false);
    }
    const physMatch = codeBody.match(/(?:^|[\s"'(=])(\/dev\/(?:ttyUSB\d+|ttyACM\d+|ttyS\d+|bus\/usb\/[^\s"']*|hidraw\d+|cdc-wdm\d+|video\d+|spidev[^\s"']*|i2c-\d+))/);
    if (physMatch?.[1]) {
      checkPath(physMatch[1], false);
    }
  };

  const inspectArgv = (rawTokens                   , depth        )       => {
    if (depth > MAX_WRAPPER_DEPTH) {
      escalate('ask', 'high', `Wrapper nesting exceeded MAX_WRAPPER_DEPTH (${MAX_WRAPPER_DEPTH})`, true);
      return;
    }

    // Strip leading VAR=VALUE assignments
    let idx = 0;
    while (idx < rawTokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(rawTokens[idx] )) {
      idx++;
    }
    const tokens = rawTokens.slice(idx);
    if (tokens.length === 0) return;

    const head = tokens[0] ;
    const cmd = basenameCmd(head);
    const args = tokens.slice(1);

    // Recursive wrapper peeling: env (including `-S` / `--split-string`, bundled `-iS`, `-u`, `-C`, `--unset=`)
    if (cmd === 'env') {
      const parsedEnv = parseEnvArgs(args, (dir) => checkPath(dir));
      if (parsedEnv.splitPayload !== undefined) {
        const remaining = parsedEnv.remaining ?? [];
        const splitSegs = tokenizeBashSegments(parsedEnv.splitPayload);
        if (splitSegs.length === 1 && splitSegs[0] .redirections.length === 0) {
          inspectArgv([...splitSegs[0] .tokens, ...remaining], depth + 1);
        } else {
          inspectScript(parsedEnv.splitPayload, depth + 1);
          if (remaining.length > 0) {
            inspectArgv(remaining, depth + 1);
          }
        }
        return;
      }
      if (parsedEnv.nextIndex < args.length) {
        inspectArgv(args.slice(parsedEnv.nextIndex), depth + 1);
      }
      return;
    }

    // Recursive wrapper peeling: timeout
    if (cmd === 'timeout') {
      let i = 0;
      const valFlags = WRAPPER_VALUE_FLAGS.timeout ;
      while (i < args.length && args[i] .startsWith('-')) {
        const f = args[i] ;
        if (f === '--') {
          i++;
          break;
        }
        i += valFlags.has(f) ? 2 : 1;
      }
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
      if (i < args.length && !args[i] .startsWith('-')) {
        inspectScript(args[i] , depth + 1);
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

    // Recursive wrapper peeling: nested shells (`bash -c "..."`, `sh -lc "..."`, `busybox <applet> ...`)
    if (SHELL_BINARIES.has(cmd)) {
      for (let i = 0; i < args.length; i++) {
        const a = args[i] ;
        if (/^-[a-zA-Z]*c[a-zA-Z]*$/.test(a) && i + 1 < args.length) {
          inspectScript(args[i + 1] , depth + 1);
          return;
        }
      }
      if (cmd === 'busybox' && args[0] && !args[0].startsWith('-')) {
        inspectArgv(args, depth + 1);
        return;
      }
    }

    // Recursive wrapper peeling: sudo, doas, command, exec, nohup, nice, ionice, time, stdbuf, setsid, runuser, xargs
    if (SIMPLE_WRAPPERS.has(cmd)) {
      if (cmd === 'sudo' || cmd === 'doas' || cmd === 'runuser') {
        escalate('deny', 'critical', `Privilege escalation wrapper is forbidden in sandbox: ${cmd}`, true);
      }
      let i = 0;
      const valFlags = WRAPPER_VALUE_FLAGS[cmd];
      while (i < args.length && args[i] .startsWith('-')) {
        const f = args[i] ;
        if (f === '--') {
          i++;
          break;
        }
        if (f.includes('=')) {
          if (cmd === 'xargs' && f.startsWith('--arg-file=')) {
            checkPath(f.slice('--arg-file='.length), true);
          }
          i++;
          continue;
        }
        if (cmd === 'xargs' && f.startsWith('-a') && f.length > 2) {
          checkPath(f.slice(2), true);
          i++;
          continue;
        }
        if (cmd === 'xargs' && (f === '-a' || f === '--arg-file') && args[i + 1]) {
          checkPath(args[i + 1] , true);
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
      escalate('deny', 'critical', `Single-shell purity violation: invoking Windows host executable (${cmd}) inside wsl_bash is forbidden`, true);
    }

    // L0: Pre-Execution POSIX Bash Dialect Alignment — block accidentally pasted PowerShell cmdlets or CMD syntax inside wsl_bash
    if (/^(?:get-childitem|move-item|remove-item|new-item|copy-item|set-content|get-content|invoke-webrequest|invoke-restmethod|invoke-expression|start-process)$/i.test(cmd)) {
      escalate(
        'deny',
        'critical',
        `Shell dialect mismatch inside wsl_bash: PowerShell cmdlet '${cmd}' cannot run in POSIX Bash. Rewrite using native Bash commands (ls, mv, rm, mkdir, cp, curl).`,
        true,
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
        true,
      );
    }
    if (args.some((a) => /^\$env:[A-Za-z_]/i.test(a) || /^%[A-Za-z_][A-Za-z0-9_]*%$/.test(a))) {
      escalate(
        'deny',
        'critical',
        `Shell dialect mismatch inside wsl_bash: Windows '$env:VAR' / '%VAR%' syntax detected in POSIX Bash. Use '$VAR'.`,
        true,
      );
    }

    // L3 + L0 scan on inline script interpreter invocations (`python3 -c`, `node -e`, `perl -e`, etc.)
    if (INTERPRETER_BINARIES.has(cmd.toLowerCase())) {
      const inlineCode = extractInlineInterpreterCode(cmd, args);
      if (inlineCode !== null) {
        escalate(
          'ask',
          'high',
          `Inline script interpreter execution (${cmd}) requires manual single-shot approval`,
          true,
        );
        scanCodeBodyForL0AndDevices(inlineCode);
      }
    }

    // L0: Scan non-message command arguments for gha-creds, protected WSL escape paths, raw block devices & physical devices
    for (let i = 0; i < args.length; i++) {
      const rawArg = args[i] ;
      const isTextArg = isBashTextOrPatternArg(cmd, args, i);
      if (isTextArg) continue;

      if (GHA_CREDS_RE.test(rawArg) || /gha-creds-[^/]*\.json/i.test(posix.basename(rawArg))) {
        escalate('deny', 'critical', 'Access to GitHub Actions credential file (gha-creds-*.json) is forbidden', true);
      }

      const pathVal = extractPathValue(rawArg);
      if (pathVal) {
        const resolved = pathVal.startsWith('/')
          ? posix.normalize(pathVal)
          : posix.normalize(posix.join(trackedCwd, pathVal));
        if (WIN_DRIVE_MNT_RE.test(resolved) || resolved === '/mnt') {
          escalate('deny', 'critical', `Direct Windows drive (/mnt) access from WSL sandbox is forbidden: ${resolved}`, true);
        }
        for (const sysPrefix of SYSTEM_PROTECTED_PREFIXES) {
          if (resolved === sysPrefix || resolved.startsWith(sysPrefix + '/')) {
            escalate('deny', 'critical', `Protected WSL/system path access is forbidden: ${resolved}`, true);
          }
        }
        if (BLOCK_DEV_RE.test(resolved)) {
          escalate('deny', 'critical', `Raw block device access is forbidden: ${resolved}`, true);
        }
        if (PHYSICAL_DEV_RE.test(resolved)) {
          touchesPhysicalDevice = true;
          escalate('ask', 'high', `Physical device path referenced (${resolved}); requires manual single-shot approval`, true);
        }
      }
    }

    // Check physical hardware tools (mandatory manual single-shot approval)
    if (PHYSICAL_FLASH_TOOLS.has(cmd)) {
      touchesPhysicalDevice = true;
      escalate('ask', 'high', `Physical hardware tool detected (${cmd}); requires manual single-shot approval`, true);
    }
    if (cmd === 'fastboot') {
      const sub = args.find((a) => !a.startsWith('-'))?.toLowerCase() ?? '';
      if (!sub || !FASTBOOT_READONLY_SUBCMDS.has(sub)) {
        touchesPhysicalDevice = true;
        escalate('ask', 'high', `Phone Bootloader / fastboot operation (${cmd} ${args.join(' ')}) requires manual single-shot approval`, true);
      }
    }
    if (cmd === 'adb') {
      let aIdx = 0;
      while (aIdx < args.length) {
        const a = args[aIdx] ;
        if (a === '-s' || a === '-t' || a === '-H' || a === '-P' || a === '-L') {
          aIdx += 2;
        } else if (a.startsWith('-')) {
          aIdx += 1;
        } else {
          break;
        }
      }
      const sub = (args[aIdx] ?? '').toLowerCase();
      if (sub && !ADB_READONLY_SUBCMDS.has(sub)) {
        touchesPhysicalDevice = true;
        escalate('ask', 'high', `Phone ADB mutating/device operation (${cmd} ${sub}) requires manual single-shot approval`, true);
      }
    }
    if (cmd === 'idf.py' && args.some((a) => /^(flash|monitor|erase-flash|efuse|app-flash)$/i.test(a))) {
      touchesPhysicalDevice = true;
      escalate('ask', 'high', `MCU firmware flashing operation (${cmd} ${args.join(' ')}) requires manual single-shot approval`, true);
    }
    if ((cmd === 'pio' || cmd === 'platformio') && args.some((a) => a === '--target' || a === 'upload' || a === 'monitor')) {
      touchesPhysicalDevice = true;
      escalate('ask', 'high', `Hardware upload/monitor operation requires manual single-shot approval`, true);
    }

    // L0: Power & kernel mount/privilege tools
    if (POWER_TOOLS.has(cmd)) {
      escalate('deny', 'critical', `System power command is forbidden: ${cmd}`, true);
    }
    if (cmd === 'systemctl' && args.some((a) => SYSTEMCTL_POWER_VERBS.has(a))) {
      escalate('deny', 'critical', `Dangerous systemctl power action is forbidden`, true);
    }
    if (KERNEL_PRIV_TOOLS.has(cmd)) {
      escalate('deny', 'critical', `Kernel/mount privilege command is forbidden: ${cmd}`, true);
    }
    if (cmd === 'sysctl' && args.some((a) => a === '-w' || a === '--write')) {
      escalate('deny', 'critical', 'Kernel parameter write (sysctl -w) is forbidden', true);
    }

    // L0: Disk formatting & block erasure
    if (DISK_WIPE_ALWAYS_DENY.has(cmd) || /^mkfs(\.\w+)?$/.test(cmd) || /^mke2fs(\.\w+)?$/.test(cmd)) {
      const onlyHelp = args.length > 0 && args.every((a) => a === '-h' || a === '--help' || a === '-V' || a === '--version');
      if (!onlyHelp) {
        escalate('deny', 'critical', `Disk formatting/wiping command is forbidden: ${cmd}`, true);
      }
    }
    if (DISK_READONLY_ALLOWED.has(cmd)) {
      const readOnly = args.length > 0 && args.every((a) => a === '-l' || a === '--list' || a === '-h' || a === '--help' || a === '-V' || a === '--version');
      if (!readOnly) {
        escalate('deny', 'critical', `Mutating partition tool invocation is forbidden: ${cmd}`, true);
      }
    }

    // L0: dd (`if=` & `of=`) / raw file readers & writers targeting block devices
    if (cmd === 'dd') {
      for (const a of args) {
        if (a.startsWith('of=') || a.startsWith('if=')) {
          checkPath(a);
        }
      }
    }
    if (RAW_READ_TOOLS.has(cmd)) {
      for (const a of args) {
        if (!a.startsWith('-')) {
          checkPath(a, true);
        }
      }
    }

    // L0 / L3: rm analysis
    if (cmd === 'rm') {
      let forceOrRecursive = false;
      let afterDoubleDash = false;
      const targets           = [];
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
          escalate('deny', 'critical', `Destructive rm targeting root/system/home directory is forbidden: ${resolved}`, true);
        }
        checkPath(t);
      }
      if (forceOrRecursive) {
        escalate('ask', 'high', `Destructive force/recursive rm requires approval: rm ${args.join(' ')}`);
      }
    }

    // L3 + recursive inspection: find -delete / -exec / -execdir
    if (cmd === 'find') {
      if (args.includes('-delete')) {
        escalate('ask', 'high', 'find -delete performs destructive deletion and requires approval', true);
      }
      for (let i = 0; i < args.length; i++) {
        const flag = args[i] ;
        if (flag === '-exec' || flag === '-execdir' || flag === '-ok' || flag === '-okdir') {
          const execTokens           = [];
          let j = i + 1;
          while (j < args.length && args[j] !== ';' && args[j] !== '+') {
            execTokens.push(args[j] === '{}' ? './target' : args[j] );
            j++;
          }
          if (execTokens.length > 0) {
            inspectArgv(execTokens, depth + 1);
            const execTarget = basenameCmd(execTokens[0] );
            if (execTarget === 'rm' || execTarget === 'sh' || execTarget === 'bash' || execTarget === 'unlink') {
              escalate('ask', 'high', `find ${flag} ${execTarget} requires approval`, true);
            }
          }
          i = j;
        }
      }
    }

    // L3: git dangerous flags & parameters
    if (cmd === 'git') {
      let subIdx = 0;
      while (subIdx < args.length) {
        const a = args[subIdx] ;
        if (a === '-C' && subIdx + 1 < args.length) {
          const dirArg = args[subIdx + 1] ;
          const resolved = dirArg.startsWith('/') ? posix.normalize(dirArg) : posix.normalize(posix.join(trackedCwd, dirArg));
          if (!isPathInside(ctx.workspaceRoot, resolved)) {
            externalPaths.add(resolved);
            escalate('ask', 'high', `git -C targets directory outside workspace: ${resolved}`, true);
          }
          subIdx += 2;
          continue;
        }
        if (a.startsWith('--work-tree=') || a.startsWith('--git-dir=')) {
          const dirArg = a.slice(a.indexOf('=') + 1);
          const resolved = dirArg.startsWith('/') ? posix.normalize(dirArg) : posix.normalize(posix.join(trackedCwd, dirArg));
          if (!isPathInside(ctx.workspaceRoot, resolved)) {
            externalPaths.add(resolved);
            escalate('ask', 'high', `git ${a} targets external directory: ${resolved}`, true);
          }
          subIdx++;
          continue;
        }
        if (a === '--work-tree' || a === '--git-dir' || a === '-c') {
          if (a === '-c' && subIdx + 1 < args.length) {
            const key = args[subIdx + 1] .split('=')[0]?.toLowerCase() ?? '';
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
      const arity = PATH_ARITY[cmd] ;
      const positionals = args.filter((a) => !a.startsWith('-'));
      for (const p of positionals.slice(arity - 1)) {
        checkPath(p);
      }
    }
  };

  const inspectScript = (rawScript        , depth        )       => {
    if (depth > MAX_WRAPPER_DEPTH) {
      escalate('ask', 'high', `Script substitution nesting exceeded MAX_WRAPPER_DEPTH (${MAX_WRAPPER_DEPTH})`, true);
      return;
    }

    const { script: cleanedScript, heredocs } = stripContinuationsAndExtractHeredocs(rawScript);
    const normalized = normalizeIfs(cleanedScript);

    if (isForkBomb(normalized)) {
      escalate('deny', 'critical', 'Fork bomb pattern detected', true);
      return;
    }

    // Inspect command/process substitutions recursively outside quoted heredocs
    for (const nested of extractSubstitutions(normalized)) {
      inspectScript(nested, depth + 1);
    }

    const segments = tokenizeBashSegments(normalized);
    for (let i = 0; i < segments.length; i++) {
      const seg = segments[i] ;
      const targetCmd = unwrapPipeTargetCmd(seg.tokens);

      // Look ahead across connected pipeline segments to detect heredocs piped into shells/interpreters
      let pipelineFeedsShell = false;
      let pipelineFeedsInterp = false;
      for (let p = i; p + 1 < segments.length && segments[p] .pipedToNext; p++) {
        const downCmd = unwrapPipeTargetCmd(segments[p + 1] .tokens);
        if (SHELL_BINARIES.has(downCmd)) pipelineFeedsShell = true;
        if (INTERPRETER_BINARIES.has(downCmd.toLowerCase())) pipelineFeedsInterp = true;
      }

      // Check redirections (>, >>, >|, &>, &>>, <, <<, <<<)
      for (const redir of seg.redirections) {
        if (redir.op === '<<') {
          const hd = heredocs.get(redir.target);
          if (hd) {
            if (!hd.quotedDelim) {
              for (const nested of extractSubstitutions(hd.body)) {
                inspectScript(nested, depth + 1);
              }
            }
            if (SHELL_BINARIES.has(targetCmd) || pipelineFeedsShell) {
              inspectScript(hd.body, depth + 1);
            } else if (INTERPRETER_BINARIES.has(targetCmd.toLowerCase()) || pipelineFeedsInterp) {
              escalate('ask', 'high', `Heredoc execution via interpreter (${targetCmd}) requires single-shot approval`, true);
              scanCodeBodyForL0AndDevices(hd.body);
            }
          }
          continue;
        }
        if (redir.op === '<<<') {
          if (SHELL_BINARIES.has(targetCmd)) {
            inspectScript(redir.target, depth + 1);
          } else if (INTERPRETER_BINARIES.has(targetCmd.toLowerCase())) {
            escalate('ask', 'high', `Here-string execution via interpreter (${targetCmd}) requires single-shot approval`, true);
            scanCodeBodyForL0AndDevices(redir.target);
          }
          if (GHA_CREDS_RE.test(redir.target) || /gha-creds-[^/]*\.json/i.test(posix.basename(redir.target))) {
            escalate('deny', 'critical', 'Access to GitHub Actions credential file (gha-creds-*.json) is forbidden', true);
          }
          continue;
        }
        if (redir.op === '<') {
          checkPath(redir.target, true);
          if (SHELL_BINARIES.has(targetCmd)) {
            escalate('ask', 'high', `Redirecting script file into shell (${targetCmd} < ${redir.target}) requires single-shot approval`, true);
          }
          continue;
        }
        if (redir.op.startsWith('>') || redir.op === '&>' || redir.op === '&>>') {
          checkPath(redir.target, true);
        }
      }

      // Detect dangerous `curl/wget ... | sh/bash` and `curl/wget ... | python/node/perl/ruby/php` patterns (peeling wrappers on both sides!)
      if (seg.pipedToNext && i + 1 < segments.length) {
        const curCmd = targetCmd;
        const nextCmd = unwrapPipeTargetCmd(segments[i + 1] .tokens);
        const nextIsShell = SHELL_BINARIES.has(nextCmd);
        const nextIsInterp = INTERPRETER_BINARIES.has(nextCmd.toLowerCase());
        if (nextIsShell || (DOWNLOAD_CRADLE_TOOLS.has(curCmd) && nextIsInterp)) {
          if (DOWNLOAD_CRADLE_TOOLS.has(curCmd)) {
            escalate(
              'deny',
              'critical',
              `Remote download piped directly into shell/interpreter (${curCmd} | ${nextCmd}) is forbidden`,
              true,
            );
          } else if (nextIsShell) {
            escalate('ask', 'high', `Piping stream directly into shell (${nextCmd}) requires single-shot approval`, true);
          }
        }
      }

      inspectArgv(seg.tokens, depth);
    }
  };

  inspectScript(command, 0);

  if (externalPaths.size > 0 && decision === 'allow') {
    escalate('ask', 'elevated', `Command references path(s) outside workspaceRoot: ${Array.from(externalPaths).join(', ')}`, true);
  }

  const firstUnwrapped = unwrappedCommands[0];
  let suggestedPrefix                      ;
  let requiresSessionRuleBlocked =
    touchesPhysicalDevice ||
    decision === 'deny' ||
    forceBlockSessionRule ||
    unwrappedCommands.length !== 1 ||
    externalPaths.size > 0;

  if (firstUnwrapped && firstUnwrapped.length > 0 && !requiresSessionRuleBlocked) {
    const candidate = firstUnwrapped.slice(0, Math.min(2, firstUnwrapped.length));
    if (isBannedPrefix(candidate) || isBannedPrefix([firstUnwrapped[0] ])) {
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

                                            
                                           
                                                 
 

/**
 * Extracts normalized non-prose command arguments and redirection targets from a POSIX Bash
 * script (respecting heredocs, line continuations, `$'...'`, and `git`/`rg`/`echo` prose args)
 * so host-side guards reuse the exact Bash lexer without duplicating tokenization logic.
 */
export function extractBashNonProseTargets(command        )                            {
  const nonProseArgs           = [];
  const redirectionTargets           = [];
  if (typeof command !== 'string' || command.length === 0 || command.length > MAX_GUARD_CHARS) {
    return { nonProseArgs, redirectionTargets };
  }

  const walk = (rawScript        , depth        )       => {
    if (depth > MAX_WRAPPER_DEPTH) return;
    const { script: cleanedScript, heredocs } = stripContinuationsAndExtractHeredocs(rawScript);
    const normalized = normalizeIfs(cleanedScript);

    for (const nested of extractSubstitutions(normalized)) {
      walk(nested, depth + 1);
    }

    const segments = tokenizeBashSegments(normalized);
    for (let i = 0; i < segments.length; i++) {
      const seg = segments[i] ;
      const targetCmd = unwrapPipeTargetCmd(seg.tokens);
      let pipelineFeedsShell = false;
      for (let p = i; p + 1 < segments.length && segments[p] .pipedToNext; p++) {
        if (SHELL_BINARIES.has(unwrapPipeTargetCmd(segments[p + 1] .tokens))) {
          pipelineFeedsShell = true;
        }
      }
      for (const redir of seg.redirections) {
        if (redir.op === '<<') {
          const hd = heredocs.get(redir.target);
          if (hd) {
            if (!hd.quotedDelim) {
              for (const nested of extractSubstitutions(hd.body)) {
                walk(nested, depth + 1);
              }
            }
            if (SHELL_BINARIES.has(targetCmd) || pipelineFeedsShell) {
              walk(hd.body, depth + 1);
            }
          }
          continue;
        }
        if (redir.op === '<<<') {
          if (SHELL_BINARIES.has(targetCmd)) {
            walk(redir.target, depth + 1);
          } else {
            nonProseArgs.push(redir.target);
          }
          continue;
        }
        redirectionTargets.push(redir.target);
      }

      // Skip leading VAR=VALUE assignments to identify command head and args cleanly
      let idx = 0;
      while (idx < seg.tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(seg.tokens[idx] )) {
        idx++;
      }
      const tokens = seg.tokens.slice(idx);
      if (tokens.length === 0) continue;
      const cmd = basenameCmd(tokens[0] );
      const args = tokens.slice(1);
      if (cmd === 'env') {
        const parsedEnv = parseEnvArgs(args);
        if (parsedEnv.splitPayload !== undefined) {
          walk(parsedEnv.splitPayload, depth + 1);
        }
      } else if (SHELL_BINARIES.has(cmd)) {
        for (let aIdx = 0; aIdx < args.length; aIdx++) {
          if (/^-[a-zA-Z]*c[a-zA-Z]*$/.test(args[aIdx] ) && aIdx + 1 < args.length) {
            walk(args[aIdx + 1] , depth + 1);
            break;
          }
        }
      }
      for (let aIdx = 0; aIdx < args.length; aIdx++) {
        if (!isBashTextOrPatternArg(cmd, args, aIdx)) {
          nonProseArgs.push(args[aIdx] );
        }
      }
    }
  };

  walk(command, 0);
  return { nonProseArgs, redirectionTargets };
}
