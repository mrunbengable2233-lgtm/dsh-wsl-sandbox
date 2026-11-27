import { spawnSync } from 'node:child_process';
import { isInternalContainerDistro, isValidIdentifier } from '../../core/src/index.js';

                                      
                        
                         
                              
                              
                                        
                              
                                                                                                                               
                             
                                                                                                                          
                                          
                                                                                         
                                         
 

                                   
                          
                       
                            
                           
                         
                                 
 

                                     
                            
                                                   
                                     
                                    
                                         
                                  
                                     
    
 

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
    const m = line.match(/^\s*(\*)?\s*(\S+)\s+(\S+(?:\s+\S+)?)\s+(\d+)\s*$/);
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
      supported: wslVersion === 2 && !isInternal && isValidIdentifier(name),
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
      supported: ver === 2 && !isInternal && isValidIdentifier(name),
      basePath,
      isCustomDiskLocation: Boolean(
        basePath && !/[\\/]appdata[\\/]local[\\/]packages[\\/]/i.test(basePath),
      ),
      registeredDefaultUid: reg.DefaultUid !== undefined && reg.DefaultUid >= 0 ? reg.DefaultUid : undefined,
    });
  }

  return merged;
}

export function isHostSpawnDisabled()          {
  return process.env.DSH_WSL_NO_HOST_SPAWN === '1';
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

/**
 * Discovers all registered WSL distros on Windows (combining `wsl.exe -l -v` + read-only Lxss registry),
 * supporting Ubuntu 26.04, Ubuntu 24.04, Debian, Fedora, Arch, Kali, and custom WSL Manager imports.
 */
export function discoverWslDistros()                     {
  const sharedPaths = {
    windowsGlobalConfig: '%USERPROFILE%\\.wslconfig',
    distroConfig: '/etc/wsl.conf',
    lxssRegistryKey: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss',
  };

  if (process.platform !== 'win32' || isHostSpawnDisabled()) {
    return {
      platform: process.platform,
      distros: [],
      recommendedDistro:
        process.platform !== 'win32'
          ? (process.env.WSL_DISTRO_NAME || 'local-linux')
          : 'Ubuntu-26.04',
      wslSettingsSharedPaths: sharedPaths,
    };
  }

  const lxss = queryWindowsLxssRegistry();
  const res = spawnSync('wsl.exe', ['--list', '--verbose'], {
    timeout: 6000,
    windowsHide: true,
  });

  const parsed = res.status === 0 && res.stdout ? parseWslListVerbose(res.stdout) : [];
  const merged = mergeWslDistrosWithLxss(parsed, lxss);

  const preferred =
    merged.find((d) => d.supported && d.isDefault) ??
    merged.find((d) => d.supported) ??
    undefined;

  return {
    platform: process.platform,
    distros: merged,
    recommendedDistro: preferred?.name ?? 'Ubuntu-26.04',
    wslSettingsSharedPaths: sharedPaths,
  };
}

/**
 * Probes the real non-root Linux UID, username, $HOME, and OS ID inside a registered WSL 2 distro.
 * Uses `--cd ~` so it never locks any Windows NTFS directory.
 */
export function probeWslDistroUser(distro        , username         )                          {
  if (process.platform !== 'win32' || isHostSpawnDisabled() || !isValidIdentifier(distro)) return null;
  const args = ['-d', distro, '--cd', '~'];
  if (username && isValidIdentifier(username)) {
    args.push('-u', username);
  }
  args.push(
    '--',
    'sh',
    '-c',
    'os_id=""; os_name=""; if [ -r /etc/os-release ]; then . /etc/os-release 2>/dev/null; os_id="$ID"; os_name="$PRETTY_NAME"; fi; printf "%s\n%s\n%s\n%s\n%s\n" "$(id -u)" "$(id -un)" "$HOME" "$os_id" "$os_name"',
  );
  const res = spawnSync('wsl.exe', args, {
    encoding: 'utf8',
    timeout: 10_000,
    windowsHide: true,
  });
  if (res.status !== 0 || !res.stdout) return null;
  const lines = res.stdout.replace(/\r/g, '').split('\n');
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
