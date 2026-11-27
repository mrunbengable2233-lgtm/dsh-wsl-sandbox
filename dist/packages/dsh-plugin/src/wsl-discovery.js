import { spawn, spawnSync } from 'node:child_process';
import {
  isInternalContainerDistro,
  isValidDistroName,
  isValidLinuxUsername,
} from '../../core/src/index.js';

                                      
                        
                         
                              
                              
                                        
                              
                                                                                                                               
                             
                                                                                                                          
                                          
                                                                                         
                                         
 

                                   
                          
                       
                            
                           
                         
                                 
 

                                     
                        
                               
                                  
                                                          
                                     
                              
                               
                                       
 

                                     
                            
                                                   
                                     
                                               
                                    
                                         
                                  
                                     
    
 

/**
 * Decodes Windows `wsl.exe` stdout which is frequently UTF-16LE (with or without BOM)
 * even when invoked from UTF-8 Node.js processes.
 */
export function decodeWslOutput(buf                 )         {
  if (typeof buf === 'string') {
    return buf.replace(/^\uFEFF/, '').replace(/\0/g, '');
  }
  if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) {
    return buf.subarray(2).toString('utf16le').replace(/\0/g, '');
  }
  let zeroCount = 0;
  const sampleLen = Math.min(buf.length, 256);
  for (let i = 1; i < sampleLen; i += 2) {
    if (buf[i] === 0) zeroCount++;
  }
  if (sampleLen >= 4 && zeroCount > sampleLen / 4) {
    return buf.toString('utf16le').replace(/^\uFEFF/, '').replace(/\0/g, '');
  }
  return buf.toString('utf8').replace(/^\uFEFF/, '').replace(/\0/g, '');
}

/**
 * Pure parser for `wsl.exe --list --verbose` output (English & localized headers).
 * Handles UTF-16LE buffers, `*` default marker, custom distro names created by
 * WSL Manager / `wsl --import`, and filters internal container distros accurately.
 */
export function parseWslListVerbose(raw                 )                        {
  const text = decodeWslOutput(raw);
  const lines = text
    .split(/\r?\n/)
    .map((l) => l.replace(/\r/g, '').trimEnd())
    .filter((l) => l.trim().length > 0);

  const results                        = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ;
    // Skip header line (e.g. "  NAME   STATE   VERSION" or localized equivalents without trailing digit)
    const m = line.match(/^\s*(\*)?\s*(.+?)\s{2,}(\S.*?)\s+(\d+)\s*$/);
    if (!m) continue;
    const isDefault = m[1] === '*';
    const name = m[2] .trim();
    const state = m[3] .trim();
    const wslVersion = Number(m[4]);
    if (!name || !Number.isInteger(wslVersion)) continue;
    const isInternal = isInternalContainerDistro(name);
    results.push({
      name,
      state,
      wslVersion,
      isDefault,
      isInternalContainer: isInternal,
      supported: wslVersion === 2 && !isInternal && isValidDistroName(name),
    });
  }
  return results;
}

                                    
                                     
                             
                            
                               
 

/**
 * Pure merge of `wsl.exe -l -v` parsed rows and read-only `HKCU\...\Lxss` registry entries.
 * Captures WSL Manager imported/moved distros even when omitted by Explorer or `wsl.exe -l -v`.
 */
export function mergeWslDistrosWithLxss(
  parsed                                ,
  lxss                                        ,
)                        {
  const merged                        = [];
  const seen = new Set        ();

  for (const d of parsed) {
    seen.add(d.name.toLowerCase());
    const reg = lxss.get(d.name.toLowerCase());
    const basePath = reg?.BasePath || undefined;
    const isCustomDiskLocation = Boolean(
      basePath && !/[\\/]appdata[\\/]local[\\/]packages[\\/]/i.test(basePath),
    );
    merged.push({
      ...d,
      basePath,
      isCustomDiskLocation,
      registeredDefaultUid: reg?.DefaultUid !== undefined && reg.DefaultUid >= 0 ? reg.DefaultUid : undefined,
    });
  }

  for (const [key, reg] of lxss) {
    if (seen.has(key) || !reg.DistributionName) continue;
    const name = reg.DistributionName;
    const isInternal = isInternalContainerDistro(name);
    const ver = reg.Version ?? 2;
    const basePath = reg.BasePath || undefined;
    merged.push({
      name,
      state: 'Registered',
      wslVersion: ver,
      isDefault: false,
      isInternalContainer: isInternal,
      supported: ver === 2 && !isInternal && isValidDistroName(name),
      basePath,
      isCustomDiskLocation: Boolean(
        basePath && !/[\\/]appdata[\\/]local[\\/]packages[\\/]/i.test(basePath),
      ),
      registeredDefaultUid: reg.DefaultUid !== undefined && reg.DefaultUid >= 0 ? reg.DefaultUid : undefined,
    });
  }

  return merged;
}

function parseRegDword(rawVal        )                     {
  const t = rawVal.trim();
  if (!t) return undefined;
  const n = /^0x/i.test(t) ? Number.parseInt(t, 16) : Number.parseInt(t, 10);
  return Number.isSafeInteger(n) ? n : undefined;
}

/**
 * Pure parser for `reg.exe query HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss /s` output.
 */
export function parseRegQueryLxssOutput(raw        )                                 {
  const map = new Map                           ();
  const lines = raw.replace(/^\uFEFF/, '').split(/\r?\n/);
  let current   
                              
                      
                     
                        
           = null;

  const flush = ()       => {
    if (current?.DistributionName) {
      map.set(current.DistributionName.toLowerCase(), {
        DistributionName: current.DistributionName,
        ...(current.BasePath !== undefined ? { BasePath: current.BasePath } : {}),
        ...(current.Version !== undefined ? { Version: current.Version } : {}),
        ...(current.DefaultUid !== undefined ? { DefaultUid: current.DefaultUid } : {}),
      });
    }
    current = null;
  };

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) {
      flush();
      continue;
    }
    if (/^HKEY_/i.test(trimmed)) {
      flush();
      current = {};
      continue;
    }
    if (!current) continue;
    const m = line.match(/^\s+(\S+)\s+(REG_[A-Z0-9_]+)(?:\s+(.*))?$/);
    if (!m) continue;
    const field = m[1] ;
    const value = (m[3] ?? '').trim();
    if (field === 'DistributionName' && value) {
      current.DistributionName = value;
    } else if (field === 'BasePath' && value) {
      current.BasePath = value.replace(/^\\\\\?\\/, '');
    } else if (field === 'Version') {
      const ver = parseRegDword(value);
      if (ver !== undefined) current.Version = ver;
    } else if (field === 'DefaultUid') {
      const uid = parseRegDword(value);
      if (uid !== undefined) current.DefaultUid = uid;
    }
  }
  flush();
  return map;
}

export function isHostSpawnDisabled()          {
  return process.env.DSH_WSL_NO_HOST_SPAWN === '1';
}

/**
 * 解析 `wsl.exe --version` 输出（兼容中/英双语以及旧版 Windows Inbox WSL `< 2.0` 返回非零退出码）。
 * 重点识别 WSL `< 2.4`（现代 `.wsl` 安装包 / `wsl --install --name` 需 `>= 2.4.4`，
 * 早期 `2.0–2.3` 的 `mirrored` 模式易出现环回/VPN 兼容问题，测试环境建议优先使用默认 `NAT` 模式）。
 */
export function parseWslVersionOutput(
  raw                 ,
  exitStatus                = 0,
)                     {
  const text = decodeWslOutput(raw).trim();
  const wslMatch = text.match(/^\s*WSL\s*(?:version|版本)\s*[:：]\s*(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?/im);
  const kernelMatch = text.match(/^\s*(?:Kernel\s*version|内核版本)\s*[:：]\s*([^\r\n]+)/im);
  const warnings           = [];

  if (!wslMatch) {
    const isLegacy = exitStatus !== 0 || text.length === 0 || /--version|help|用法/i.test(text);
    warnings.push(
      '未检测到新版 Microsoft Store / MSI WSL 版本信息（可能是旧版 Windows Inbox WSL < 2.0）：' +
      '不支持 .wsl 格式新发行版与 mirrored 网络模式，建议保持默认 NAT 网络模式或执行 wsl.exe --update 升级至 2.4+。',
    );
    return {
      raw: text || undefined,
      isLegacyInboxWsl: isLegacy,
      isBelow24: true,
      isBelow244: true,
      warnings,
    };
  }

  const major = Number(wslMatch[1]);
  const minor = Number(wslMatch[2]);
  const patch = Number(wslMatch[3]);
  const build = wslMatch[4];
  const versionStr = build ? `${major}.${minor}.${patch}.${build}` : `${major}.${minor}.${patch}`;
  const isBelow24 = major < 2 || (major === 2 && minor < 4);
  const isBelow244 = major < 2 || (major === 2 && (minor < 4 || (minor === 4 && patch < 4)));

  if (isBelow24) {
    warnings.push(
      `检测到宿主机 WSL 版本为 ${versionStr}（低于 2.4.0）：` +
      '2.4 以下版本的 mirrored 网络模式对环回端口/VPN 兼容性较差，测试环境强烈建议使用默认 NAT 网络模式；' +
      '且不支持新版 .wsl 单文件发行版，如需新版 Arch/Ubuntu 发行版建议执行 wsl.exe --update。',
    );
  } else if (isBelow244) {
    warnings.push(
      `检测到宿主机 WSL 版本为 ${versionStr}（低于 2.4.4）：现代 .wsl 格式发行版与 wsl --install --name 参数需 WSL >= 2.4.4。`,
    );
  }

  return {
    raw: text,
    wslVersion: versionStr,
    kernelVersion: kernelMatch?.[1]?.trim(),
    majorMinor: [major, minor, patch],
    isLegacyInboxWsl: false,
    isBelow24,
    isBelow244,
    warnings,
  };
}

export function probeHostWslVersion()                                 {
  if (process.platform !== 'win32' || isHostSpawnDisabled()) return undefined;
  const res = spawnSync('wsl.exe', ['--version'], {
    timeout: 4000,
    windowsHide: true,
  });
  return parseWslVersionOutput(res.stdout ?? Buffer.alloc(0), res.status);
}

export async function probeHostWslVersionAsync()                                          {
  if (process.platform !== 'win32' || isHostSpawnDisabled()) return undefined;
  const res = await spawnBufferAsync('wsl.exe', ['--version'], 4000);
  return parseWslVersionOutput(res.stdout, res.status);
}

function spawnBufferAsync(
  command        ,
  args                   ,
  timeoutMs        ,
)                                                     {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(command, [...args], {
        stdio: ['ignore', 'pipe', 'ignore'],
        shell: false,
        windowsHide: true,
      });
    } catch {
      resolve({ status: null, stdout: Buffer.alloc(0) });
      return;
    }
    const chunks           = [];
    let settled = false;
    const timer = setTimeout(() => {
      try {
        child.kill('SIGKILL');
      } catch {
        // ignore
      }
      if (!settled) {
        settled = true;
        resolve({ status: null, stdout: Buffer.concat(chunks) });
      }
    }, timeoutMs);
    timer.unref();

    child.stdout?.on('data', (chunk        ) => chunks.push(chunk));
    child.once('error', () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ status: null, stdout: Buffer.concat(chunks) });
    });
    child.once('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ status: code, stdout: Buffer.concat(chunks) });
    });
  });
}

/**
 * Read-only query of Windows `HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss\*`.
 * Captures imported/moved distros (e.g. moved to D:\WSL via WSL Manager or WSL Settings)
 * even when they vanish from Windows File Explorer's left "Linux" sidebar.
 */
export function queryWindowsLxssRegistry()                                 {
  const map = new Map                           ();
  if (process.platform !== 'win32' || isHostSpawnDisabled()) return map;

  const ps = [
    '$items = @();',
    '$root = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss";',
    'if (Test-Path $root) {',
    '  Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {',
    '    $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue;',
    '    if ($p -and $p.DistributionName) {',
    '      $bp = if ($p.BasePath) { [string]$p.BasePath -replace "^\\\\\\\\\\?\\\\", "" } else { "" };',
    '      $items += [PSCustomObject]@{ DistributionName = [string]$p.DistributionName; BasePath = $bp; Version = [int]($p.Version); DefaultUid = if ($null -ne $p.DefaultUid) { [int]$p.DefaultUid } else { -1 } };',
    '    }',
    '  }',
    '};',
    '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8;',
    'ConvertTo-Json -InputObject $items -Compress',
  ].join(' ');

  const res = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', ps], {
    encoding: 'utf8',
    timeout: 6000,
    windowsHide: true,
  });
  if (res.status !== 0 || !res.stdout) return map;
  try {
    const parsed = JSON.parse(res.stdout.trim())                                           ;
    const list = Array.isArray(parsed) ? parsed : parsed ? [parsed] : [];
    for (const item of list) {
      if (item.DistributionName) {
        map.set(item.DistributionName.toLowerCase(), item);
      }
    }
  } catch {
    // Ignore malformed output
  }
  return map;
}

export async function queryWindowsLxssRegistryAsync()                                          {
  if (process.platform !== 'win32' || isHostSpawnDisabled()) {
    return new Map                           ();
  }
  const res = await spawnBufferAsync(
    'reg.exe',
    ['query', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss', '/s'],
    6000,
  );
  if (res.status !== 0 || res.stdout.length === 0) {
    return new Map                           ();
  }
  return parseRegQueryLxssOutput(res.stdout.toString('utf8'));
}

const SHARED_WSL_PATHS = {
  windowsGlobalConfig: '%USERPROFILE%\\.wslconfig',
  distroConfig: '/etc/wsl.conf',
  lxssRegistryKey: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss',
}         ;

function buildDiscoveryReport(
  merged                       ,
  wslVersionInfo                     ,
)                     {
  if (process.platform !== 'win32' || isHostSpawnDisabled()) {
    if (merged.length === 0) {
      return {
        platform: process.platform,
        distros: [],
        recommendedDistro:
          process.platform !== 'win32'
            ? (process.env.WSL_DISTRO_NAME || 'local-linux')
            : 'Ubuntu-26.04',
        ...(wslVersionInfo ? { wslVersionInfo } : {}),
        wslSettingsSharedPaths: SHARED_WSL_PATHS,
      };
    }
  }
  const preferred =
    merged.find((d) => d.supported && d.isDefault) ??
    merged.find((d) => d.supported) ??
    undefined;

  return {
    platform: process.platform,
    distros: merged,
    recommendedDistro: preferred?.name ?? 'Ubuntu-26.04',
    ...(wslVersionInfo ? { wslVersionInfo } : {}),
    wslSettingsSharedPaths: SHARED_WSL_PATHS,
  };
}

/**
 * 探测 Windows 上所有已注册的 WSL 发行版（合并 `wsl.exe -l -v` 与只读 `Lxss` 注册表，
 * 并采集宿主机 `wsl.exe --version` 兼容性信息），兼容 Ubuntu/Debian/Fedora/Arch/NixOS 及 WSL Manager 迁移实例。
 */
export function discoverWslDistros()                     {
  if (process.platform !== 'win32' || isHostSpawnDisabled()) {
    return buildDiscoveryReport([]);
  }

  const lxss = queryWindowsLxssRegistry();
  const res = spawnSync('wsl.exe', ['--list', '--verbose'], {
    timeout: 6000,
    windowsHide: true,
  });

  const parsed = res.status === 0 && res.stdout ? parseWslListVerbose(res.stdout) : [];
  const merged = mergeWslDistrosWithLxss(parsed, lxss);
  return buildDiscoveryReport(merged);
}

export async function discoverWslDistrosAsync()                              {
  if (process.platform !== 'win32' || isHostSpawnDisabled()) {
    return buildDiscoveryReport([]);
  }
  const [lxss, res] = await Promise.all([
    queryWindowsLxssRegistryAsync(),
    spawnBufferAsync('wsl.exe', ['--list', '--verbose'], 6000),
  ]);
  const parsed = res.status === 0 && res.stdout.length > 0 ? parseWslListVerbose(res.stdout) : [];
  const merged = mergeWslDistrosWithLxss(parsed, lxss);
  return buildDiscoveryReport(merged);
}

function buildProbeUserArgs(distro        , username         )                  {
  if (!isValidDistroName(distro)) return null;
  const trimmedUser = username?.trim();
  if (trimmedUser && !isValidLinuxUsername(trimmedUser)) return null;

  const args = ['-d', distro, '--cd', '~'];
  if (trimmedUser) {
    args.push('-u', trimmedUser);
  }
  const probeSh = [
    'cd "$HOME" 2>/dev/null || true',
    'u_uid="$(id -u)"; u_name="$(id -un)"; u_home="$HOME"',
    'if [ -z "$1" ] && [ "$u_uid" = "0" ] && [ -r /etc/passwd ]; then',
    '  pw="$(awk -F: \'$3 >= 1000 && $3 < 65534 && $1 != "nobody" && $6 ~ /^\\// { print $3 "\\n" $1 "\\n" $6; exit }\' /etc/passwd 2>/dev/null || true)"',
    '  if [ -n "$pw" ]; then',
    '    u_uid="$(printf "%s\\n" "$pw" | sed -n "1p")"',
    '    u_name="$(printf "%s\\n" "$pw" | sed -n "2p")"',
    '    u_home="$(printf "%s\\n" "$pw" | sed -n "3p")"',
    '  fi',
    'fi',
    'os_id=""; os_name=""',
    'if [ -r /etc/os-release ]; then . /etc/os-release 2>/dev/null; os_id="$ID"; os_name="$PRETTY_NAME"; fi',
    'printf "%s\\n%s\\n%s\\n%s\\n%s\\n" "$u_uid" "$u_name" "$u_home" "$os_id" "$os_name"',
  ].join('\n');
  args.push('--', 'sh', '-c', probeSh, 'dsh-probe', trimmedUser ?? '');
  return args;
}

function parseProbeUserStdout(distro        , rawStdout        )                          {
  const lines = rawStdout.replace(/\r/g, '').split('\n');
  const uid = Number(lines[0]?.trim());
  const user = lines[1]?.trim() ?? '';
  const homeDir = lines[2]?.trim() ?? '';
  if (!Number.isSafeInteger(uid) || !user || !homeDir.startsWith('/')) return null;
  return {
    distro,
    uid,
    username: user,
    homeDir,
    osId: lines[3]?.trim() || undefined,
    osPrettyName: lines[4]?.trim() || undefined,
  };
}

/**
 * Probes the real non-root Linux UID, username, $HOME, and OS ID inside a registered WSL 2 distro.
 * Uses `--cd ~` so it never locks any Windows NTFS directory.
 */
export function probeWslDistroUser(distro        , username         )                          {
  if (process.platform !== 'win32' || isHostSpawnDisabled()) return null;
  const args = buildProbeUserArgs(distro, username);
  if (!args) return null;
  const res = spawnSync('wsl.exe', args, {
    encoding: 'utf8',
    timeout: 10_000,
    windowsHide: true,
  });
  if (res.status !== 0 || !res.stdout) return null;
  return parseProbeUserStdout(distro, res.stdout);
}

export async function probeWslDistroUserAsync(distro        , username         )                                   {
  if (process.platform !== 'win32' || isHostSpawnDisabled()) return null;
  const args = buildProbeUserArgs(distro, username);
  if (!args) return null;
  const res = await spawnBufferAsync('wsl.exe', args, 10_000);
  if (res.status !== 0 || res.stdout.length === 0) return null;
  return parseProbeUserStdout(distro, res.stdout.toString('utf8'));
}

/**
 * Checks whether a Windows path collides with any registered WSL distro's VHDX storage BasePath.
 */
export function isInsideLxssBasePath(candidateWindowsPath        , distros                                )                {
  const normCand = candidateWindowsPath.trim().replace(/\//g, '\\').replace(/\\+$/, '').toLowerCase();
  if (!normCand) return null;
  for (const d of distros) {
    if (!d.basePath) continue;
    const normBase = d.basePath.trim().replace(/\//g, '\\').replace(/\\+$/, '').toLowerCase();
    if (!normBase) continue;
    if (normCand === normBase || normCand.startsWith(normBase + '\\') || normBase.startsWith(normCand + '\\')) {
      return d.name;
    }
  }
  return null;
}
