#!/usr/bin/env node
/**
 * `dsh-wsl-doctor` — Real Kernel Isolation, Config Masking, USB Driver & Codex Toolchain Diagnostic CLI.
 *
 * Verifies:
 * 1. OS, Linux distro (`/etc/os-release`), WSL 2 kernel detection & DrvFS automount status
 * 2. Non-root UID enforcement (blocks UID 0)
 * 3. Real `bwrap` execution, `--disable-userns` support
 * 4. Real `seccomp-bpf` kernel enforcement (`io_uring_setup` EPERM & `AF_VSOCK` EPERM)
 * 5. Escape-surface & private config masking self-test (`/mnt`, `/run`, and `$HOME/.config/dsh-wsl-sandbox` / `$HOME/.dsh`)
 * 6. Profile-aware Codex toolchain matrix (`core` / `standard` / `universal`, pure Node PATH resolver across mise/uv/cargo/bun/go)
 * 7. WSL 2 kernel USBIP (`vhci_hcd`) & attached device node diagnostics (generic: phones, USB NICs, HID/CDC/serial)
 * 8. Optional upstream proxy TCP reachability
 *
 * Usage:
 *   dsh-wsl-doctor [--profile core|standard|universal] [--json] [--proxy http://127.0.0.1:7890] [--strict-wsl2]
 */

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { compileSeccompBpf,                                         } from '../../core/src/index.js';

                            
                        
                                                                 
                            
                         
                            
 

                               
                             
                                               
                
                              
                          
                            
                             
                                    
                               
                                       
                                           
                                                                      
                               
    
                  
                         
                              
                              
    
                     
                                      
                                         
                                         
                                        
                                                   
                                                   
                                         
                                         
                                       
                               
    
                      
                                   
                                   
                                      
                                         
                                
    
                              
                     
                                    
                                         
                                                                
                                     
    
                                                     
                                 
 

const TOOL_MATRIX                 
                        
                                       
                                          
                                                                 
   = [
  { name: 'bwrap', binaries: ['bwrap'], versionArgs: ['--version'], tier: 'mandatory' },
  { name: 'prlimit', binaries: ['prlimit'], versionArgs: ['--version'], tier: 'mandatory' },
  { name: 'socat', binaries: ['socat'], versionArgs: ['-V'], tier: 'mandatory' },
  { name: 'bash', binaries: ['bash'], versionArgs: ['--version'], tier: 'mandatory' },
  { name: 'node', binaries: ['node'], versionArgs: ['-v'], tier: 'mandatory' },
  { name: 'git', binaries: ['git'], versionArgs: ['--version'], tier: 'core' },
  { name: 'rg', binaries: ['rg'], versionArgs: ['--version'], tier: 'core' },
  { name: 'fd', binaries: ['fd', 'fdfind'], versionArgs: ['--version'], tier: 'core' },
  { name: 'jq', binaries: ['jq'], versionArgs: ['--version'], tier: 'core' },
  { name: 'curl', binaries: ['curl'], versionArgs: ['--version'], tier: 'core' },
  { name: 'python3', binaries: ['python3'], versionArgs: ['--version'], tier: 'core' },
  { name: 'gcc', binaries: ['gcc'], versionArgs: ['--version'], tier: 'core' },
  { name: 'cmake', binaries: ['cmake'], versionArgs: ['--version'], tier: 'core' },
  { name: 'uv', binaries: ['uv'], versionArgs: ['--version'], tier: 'standard' },
  { name: 'pytest', binaries: ['pytest'], versionArgs: ['--version'], tier: 'standard' },
  { name: 'ruff', binaries: ['ruff'], versionArgs: ['--version'], tier: 'standard' },
  { name: 'pnpm', binaries: ['pnpm'], versionArgs: ['-v'], tier: 'standard' },
  { name: 'yarn', binaries: ['yarn'], versionArgs: ['-v'], tier: 'standard' },
  { name: 'bun', binaries: ['bun'], versionArgs: ['-v'], tier: 'standard' },
  { name: 'go', binaries: ['go'], versionArgs: ['version'], tier: 'standard' },
  { name: 'golangci-lint', binaries: ['golangci-lint'], versionArgs: ['--version'], tier: 'standard' },
  { name: 'rustc', binaries: ['rustc'], versionArgs: ['--version'], tier: 'standard' },
  { name: 'cargo', binaries: ['cargo'], versionArgs: ['--version'], tier: 'standard' },
  { name: 'mise', binaries: ['mise'], versionArgs: ['--version'], tier: 'standard' },
  { name: 'clang', binaries: ['clang'], versionArgs: ['--version'], tier: 'universal' },
  { name: 'bazelisk', binaries: ['bazelisk', 'bazel'], versionArgs: ['--version'], tier: 'universal' },
  { name: 'java', binaries: ['java'], versionArgs: ['-version'], tier: 'universal' },
  { name: 'mvn', binaries: ['mvn'], versionArgs: ['--version'], tier: 'universal' },
  { name: 'gradle', binaries: ['gradle'], versionArgs: ['--version'], tier: 'universal' },
  { name: 'ruby', binaries: ['ruby'], versionArgs: ['--version'], tier: 'universal' },
  { name: 'php', binaries: ['php'], versionArgs: ['--version'], tier: 'universal' },
  { name: 'poetry', binaries: ['poetry'], versionArgs: ['--version'], tier: 'universal' },
];

/**
 * Pure-Node executable resolver that ALSO checks standard user toolchain directories
 * (mise shims, ~/.local/bin, ~/.cargo/bin, ~/.bun/bin, /usr/local/go/bin) so non-login
 * `wsl.exe -d <Distro> -- node doctor.js` invocations accurately detect provisioned tools
 * on ALL distros (including minimal Fedora/Arch/Alpine without external `which`).
 */
function getSearchDirs()           {
  const home = os.homedir();
  const username = (() => {
    try {
      return os.userInfo().username;
    } catch {
      return path.basename(home);
    }
  })();
  const extra = [
    path.join(home, '.dsh', 'runtime', 'bin'),
    path.join(home, '.local', 'share', 'dsh', 'node', 'bin'),
    path.join(home, '.local', 'share', 'dsh-wsl-sandbox', 'toolchains', 'node', 'bin'),
    path.join(home, '.local', 'share', 'dsh-wsl-sandbox', 'toolchains', 'go', 'bin'),
    path.join(home, '.local', 'share', 'mise', 'shims'),
    path.join(home, '.local', 'bin'),
    path.join(home, '.nvm', 'current', 'bin'),
    path.join(home, '.local', 'share', 'fnm', 'aliases', 'default', 'bin'),
    path.join(home, '.fnm', 'aliases', 'default', 'bin'),
    path.join(home, '.volta', 'bin'),
    path.join(home, '.asdf', 'shims'),
    path.join(home, '.nix-profile', 'bin'),
    `/etc/profiles/per-user/${username}/bin`,
  ];

  const pushSortedVersions = (baseDir        , suffixParts                   , minMajor = 20)       => {
    try {
      if (fs.existsSync(baseDir)) {
        const vers = fs
          .readdirSync(baseDir)
          .filter((v) => {
            const m = v.match(/^v?(\d+)/);
            return m !== null && Number(m[1]) >= minMajor;
          })
          .sort((a, b) => b.localeCompare(a, undefined, { numeric: true }));
        for (const v of vers) {
          extra.push(path.join(baseDir, v, ...suffixParts));
        }
      }
    } catch {
      // ignore
    }
  };

  pushSortedVersions(path.join(home, '.nvm', 'versions', 'node'), ['bin'], 20);
  pushSortedVersions(path.join(home, '.local', 'share', 'fnm', 'node-versions'), ['installation', 'bin'], 20);
  pushSortedVersions(path.join(home, '.fnm', 'node-versions'), ['installation', 'bin'], 20);
  pushSortedVersions(path.join(home, '.asdf', 'installs', 'nodejs'), ['bin'], 20);

  extra.push(
    path.join(home, '.cargo', 'bin'),
    path.join(home, '.bun', 'bin'),
    '/run/current-system/sw/bin',
    '/nix/var/nix/profiles/default/bin',
    '/opt/dsh-toolchain/shims',
    '/opt/dsh-toolchain/bin',
    '/usr/local/go/bin',
  );
  const envDirs = (process.env.PATH ?? '')
    .split(path.delimiter)
    .filter((p) => Boolean(p) && !p.startsWith('/mnt/'));
  return [...new Set([...extra, ...envDirs, '/usr/local/bin', '/usr/bin', '/bin'])];
}

function detectInitSystem()                                              {
  try {
    if (fs.existsSync('/run/systemd/system')) return 'systemd';
    if (fs.existsSync('/run/openrc')) return 'openrc';
    if (fs.existsSync('/run/runit')) return 'runit';
  } catch {
    // ignore
  }
  return 'wsl-init';
}

function detectNixOs(distroId         )          {
  if (distroId?.toLowerCase() === 'nixos') return true;
  try {
    return fs.existsSync('/etc/nixos') || fs.existsSync('/run/current-system');
  } catch {
    return false;
  }
}

function parseHexRouteGatewayIpv4(hexGateway        )                     {
  if (!/^[0-9a-fA-F]{8}$/.test(hexGateway) || hexGateway === '00000000') return undefined;
  const bytes = [
    Number.parseInt(hexGateway.slice(0, 2), 16),
    Number.parseInt(hexGateway.slice(2, 4), 16),
    Number.parseInt(hexGateway.slice(4, 6), 16),
    Number.parseInt(hexGateway.slice(6, 8), 16),
  ];
  const ordered = os.endianness() === 'LE' ? bytes.reverse() : bytes;
  return ordered.join('.');
}

function detectWslNetworkHint()   
                                       
                       
  {
  let gatewayHint                    ;
  try {
    if (fs.existsSync('/proc/net/route')) {
      const lines = fs.readFileSync('/proc/net/route', 'utf8').split(/\r?\n/);
      for (const line of lines.slice(1)) {
        const cols = line.trim().split(/\s+/);
        if (cols.length >= 3 && cols[1] === '00000000') {
          gatewayHint = parseHexRouteGatewayIpv4(cols[2] );
          if (gatewayHint) break;
        }
      }
    }
  } catch {
    // ignore
  }
  if (!gatewayHint) {
    try {
      if (fs.existsSync('/etc/resolv.conf')) {
        const resolv = fs.readFileSync('/etc/resolv.conf', 'utf8');
        const m = resolv.match(/^nameserver\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/m);
        if (m?.[1] && !m[1].startsWith('10.255.255.')) {
          gatewayHint = m[1];
        }
      }
    } catch {
      // ignore
    }
  }
  try {
    if (fs.existsSync('/sys/class/net/loopback0')) {
      return { mode: 'mirrored', gatewayHint };
    }
  } catch {
    // ignore
  }
  if (gatewayHint) {
    const octets = gatewayHint.split('.').map(Number);
    if (octets[0] === 172 && octets[1] !== undefined && octets[1] >= 16 && octets[1] <= 31) {
      return { mode: 'nat', gatewayHint };
    }
  }
  return { mode: 'unknown', gatewayHint };
}

function findExecutable(bin        )                {
  for (const dir of getSearchDirs()) {
    const candidate = path.join(dir, bin);
    try {
      const st = fs.statSync(candidate);
      if (!st.isFile()) continue;
      fs.accessSync(candidate, fs.constants.X_OK);
      return candidate;
    } catch {
      // keep searching
    }
  }
  return null;
}

function detectWsl2(kernel        )          {
  if (/microsoft.*wsl2/i.test(kernel) || /wsl2/i.test(kernel)) return true;
  try {
    const procVer = fs.readFileSync('/proc/version', 'utf8');
    if (/microsoft-standard-wsl2/i.test(procVer)) return true;
  } catch {
    // ignore
  }
  return Boolean(process.env.WSL_DISTRO_NAME && fs.existsSync('/run/WSL'));
}

function detectDrvfsAutomount()          {
  try {
    const mounts = fs.readFileSync('/proc/mounts', 'utf8');
    return /\s\/mnt\/[a-z]\s+(?:9p|drvfs)\s/i.test(mounts);
  } catch {
    return false;
  }
}

function probeTool(spec                              )            {
  const enrichedPath = getSearchDirs().join(path.delimiter);
  for (const bin of spec.binaries) {
    const found = findExecutable(bin);
    if (!found) continue;
    let version                    ;
    try {
      const res = spawnSync(found, [...spec.versionArgs], {
        encoding: 'utf8',
        timeout: 3000,
        env: { ...process.env, PATH: enrichedPath },
      });
      // Tools like `java -version` print to stderr; tools like `gradle --version` lead with `----`
      const combined = `${res.stdout ?? ''}\n${res.stderr ?? ''}`;
      const firstLine = combined
        .split(/\r?\n/)
        .map((l) => l.trim())
        .find((l) => l.length > 0 && !/^[-=*_#]+$/.test(l));
      version = firstLine ? firstLine.slice(0, 80) : 'present';
    } catch {
      version = 'present';
    }
    return { name: spec.name, tier: spec.tier, present: true, path: found, version };
  }
  return { name: spec.name, tier: spec.tier, present: false };
}

function testTcpReachable(proxyUrl        )                   {
  return new Promise((resolve) => {
    try {
      const u = new URL(proxyUrl);
      const host = u.hostname;
      const port = Number(u.port || (u.protocol === 'https:' ? 443 : 80));
      const sock = net.connect({ host, port, timeout: 2500 });
      sock.once('connect', () => {
        sock.destroy();
        resolve(true);
      });
      sock.once('timeout', () => {
        sock.destroy();
        resolve(false);
      });
      sock.once('error', () => {
        sock.destroy();
        resolve(false);
      });
    } catch {
      resolve(false);
    }
  });
}

function runRealSeccompSelfTest(
  bwrapPath        ,
  arch           ,
)                                                                                     {
  const python3 = findExecutable('python3');
  if (!python3) {
    return { ioUringBlocked: null, afVsockBlocked: null, detail: 'python3 missing; skipped live seccomp syscall probe' };
  }

  const bpf = compileSeccompBpf({ arch, blockNetworkSockets: false });
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-doctor-bpf-'));
  const bpfPath = path.join(tmpDir, 'filter.bpf');
  let fd                    ;
  try {
    fs.writeFileSync(bpfPath, bpf, { mode: 0o600 });
    fd = fs.openSync(bpfPath, 'r');

    // SYS_io_uring_setup is 425 on both x86_64 and aarch64; AF_VSOCK is 40.
    const pyScript = [
      'import ctypes, json, socket',
      'libc = ctypes.CDLL(None, use_errno=True)',
      'buf = ctypes.create_string_buffer(120)',
      'ctypes.set_errno(0)',
      'r1 = libc.syscall(425, 1, buf)',
      'e1 = ctypes.get_errno()',
      'e2 = 0',
      'try:',
      '    s = socket.socket(40, socket.SOCK_STREAM)',
      '    s.close()',
      'except OSError as ex:',
      '    e2 = ex.errno',
      'print(json.dumps({"io_uring_ret": r1, "io_uring_errno": e1, "vsock_errno": e2}))',
    ].join('\n');

    const res = spawnSync(
      bwrapPath,
      [
        '--ro-bind', '/', '/',
        '--dev', '/dev',
        '--proc', '/proc',
        '--unshare-user',
        '--unshare-pid',
        '--unshare-net',
        '--new-session',
        '--die-with-parent',
        '--seccomp', '3',
        '--',
        python3, '-c', pyScript,
      ],
      {
        stdio: ['ignore', 'pipe', 'pipe', fd],
        encoding: 'utf8',
        timeout: 8000,
      },
    );

    if (res.status !== 0) {
      return {
        ioUringBlocked: false,
        afVsockBlocked: false,
        detail: `seccomp self-test failed (exit=${res.status}): ${(res.stderr || '').trim()}`,
      };
    }

    const parsed = JSON.parse((res.stdout || '{}').trim())     
                           
                             
                          
     ;
    const ioUringBlocked = parsed.io_uring_ret === -1 && parsed.io_uring_errno === 1;
    const afVsockBlocked = parsed.vsock_errno === 1;
    return {
      ioUringBlocked,
      afVsockBlocked,
      detail: `io_uring_errno=${parsed.io_uring_errno} (expect EPERM=1), vsock_errno=${parsed.vsock_errno} (expect EPERM=1)`,
    };
  } catch (err) {
    return {
      ioUringBlocked: false,
      afVsockBlocked: false,
      detail: `seccomp probe error: ${err instanceof Error ? err.message : String(err)}`,
    };
  } finally {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch { /* ignore */ }
    }
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function probeHardwareCapabilities()                           {
  const vhciHcdReady =
    fs.existsSync('/sys/devices/platform/vhci_hcd.0') ||
    fs.existsSync('/sys/module/vhci_hcd');
  const lsusbPresent = Boolean(findExecutable('lsusb'));

  let usbBusNodesCount = 0;
  try {
    if (fs.existsSync('/dev/bus/usb')) {
      for (const bus of fs.readdirSync('/dev/bus/usb')) {
        const busPath = path.join('/dev/bus/usb', bus);
        if (fs.statSync(busPath).isDirectory()) {
          usbBusNodesCount += fs.readdirSync(busPath).length;
        }
      }
    }
  } catch {
    // ignore
  }

  const serialAndHidNodes           = [];
  try {
    for (const ent of fs.readdirSync('/dev')) {
      if (/^(?:ttyUSB\d+|ttyACM\d+|hidraw\d+|cdc-wdm\d+|video\d+)$/.test(ent)) {
        serialAndHidNodes.push(`/dev/${ent}`);
      }
    }
    serialAndHidNodes.sort();
  } catch {
    // ignore
  }

  return {
    vhciHcdReady,
    lsusbPresent,
    usbBusNodesCount,
    serialAndHidNodes,
    driverNote:
      'Stock WSL 2 kernels ship minimal USB drivers: libusb/user-space devices (/dev/bus/usb/NNN/NNN, e.g. phone ADB/Fastboot/EDL/DFU) work over USBIP, whereas Windows OEM Bootloader tools or Windows-driverless USB NICs lacking Linux .ko modules should remain on Windows host under single-shot L3 approval (or load matching Linux kernel modules).',
  };
}

function readPersistedProfile()                                 {
  const envP = process.env.DSH_WSL_PROFILE;
  if (envP === 'core' || envP === 'standard' || envP === 'universal') return envP;
  try {
    const p = path.join(os.homedir(), '.config', 'dsh-wsl-sandbox', 'profile.json');
    if (fs.existsSync(p)) {
      const parsed = JSON.parse(fs.readFileSync(p, 'utf8'))                        ;
      if (parsed.profile === 'core' || parsed.profile === 'standard' || parsed.profile === 'universal') {
        return parsed.profile;
      }
    }
  } catch {
    // ignore
  }
  return undefined;
}

function readOsRelease()                                       {
  try {
    const raw = fs.readFileSync('/etc/os-release', 'utf8');
    const id = raw.match(/^ID=["']?([^"'\n]+)["']?/m)?.[1];
    const prettyName = raw.match(/^PRETTY_NAME=["']?([^"'\n]+)["']?/m)?.[1];
    return { id, prettyName };
  } catch {
    return {};
  }
}

function checkPrivateConfigPermissions()                                  {
  const home = os.homedir();
  const sensitiveDirs = [
    path.join(home, '.config', 'dsh-wsl-sandbox'),
    path.join(home, '.dsh', 'dsh-wsl-sandbox'),
  ];
  const issues           = [];
  for (const dir of sensitiveDirs) {
    try {
      if (!fs.existsSync(dir)) continue;
      const mode = fs.statSync(dir).mode & 0o777;
      if ((mode & 0o077) !== 0) {
        issues.push(`${dir} has overly broad permissions 0${mode.toString(8)} (expected 0700)`);
      }
    } catch {
      // ignore unreadable
    }
  }
  return issues.length === 0
    ? { ok: true, detail: 'private config directories have owner-only permissions (0700)' }
    : { ok: false, detail: issues.join('; ') };
}

export async function runDoctor(options    
                         
                       
                               
 )                        {
  const selectedProfile                     = options?.profile ?? readPersistedProfile() ?? 'standard';
  const platform = process.platform;
  const rawArch = os.arch();
  const arch                     = rawArch === 'x64' ? 'x86_64' : rawArch === 'arm64' ? 'aarch64' : rawArch;
  const kernel = os.release();
  const isWsl2 = detectWsl2(kernel);
  const drvfsAutomountActive = detectDrvfsAutomount();
  const osRel = readOsRelease();
  const initSystem = detectInitSystem();
  const isNixOs = detectNixOs(osRel.id);
  const netHint = detectWslNetworkHint();
  const uid = typeof process.getuid === 'function' ? process.getuid() : -1;
  const username = os.userInfo().username;
  const nonRoot = uid > 0;

  const remediation           = [];
  const sandboxDetails           = [
    `initSystem: ${initSystem} (dsh-wsl-sandbox runtime requires ZERO systemd dependency)`,
  ];
  if (isNixOs) {
    sandboxDetails.push('distroMode: NixOS / declarative immutable root (/run/current-system)');
  }

  if (!nonRoot) {
    remediation.push('Switch to a non-root WSL user (UID > 0); root execution is blocked by dsh-wsl-sandbox.');
  }
  if (options?.strictWsl2 && !isWsl2) {
    remediation.push('Run inside a WSL 2 distribution (not WSL 1 or non-WSL host).');
  }

  const permCheck = checkPrivateConfigPermissions();
  sandboxDetails.push(`config dir ACL: ${permCheck.detail}`);
  if (!permCheck.ok) {
    remediation.push(`Tighten config directory permissions: chmod 700 ~/.config/dsh-wsl-sandbox ~/.dsh/dsh-wsl-sandbox (${permCheck.detail})`);
  }

  const bwrapPath = findExecutable('bwrap');
  const shellBin = findExecutable('bash') ?? findExecutable('sh') ?? '/bin/sh';
  let bwrapVersion                = null;
  let unprivilegedUserns = false;
  let disableUsernsFlag = false;
  let seccompIoUringBlocked                 = null;
  let seccompAfVsockBlocked                 = null;
  let escapeMaskSelfTest = false;
  let configMaskSelfTest = false;

  if (!bwrapPath) {
    remediation.push('Install bubblewrap, util-linux (prlimit), and socat via provision-wsl.sh --step base.');
  } else {
    const verRes = spawnSync(bwrapPath, ['--version'], { encoding: 'utf8', timeout: 3000 });
    bwrapVersion = (verRes.stdout || verRes.stderr || 'unknown').trim() || 'unknown';

    const nsTest = spawnSync(
      bwrapPath,
      [
        '--ro-bind', '/', '/',
        '--dev', '/dev',
        '--proc', '/proc',
        '--unshare-user',
        '--unshare-pid',
        '--unshare-net',
        '--new-session',
        '--die-with-parent',
        '--',
        shellBin, '-c', ':',
      ],
      { encoding: 'utf8', timeout: 5000 },
    );
    unprivilegedUserns = nsTest.status === 0;
    if (!unprivilegedUserns) {
      sandboxDetails.push(`bwrap userns test failed: ${(nsTest.stderr || '').trim()}`);
      remediation.push('Enable unprivileged user namespaces (check Ubuntu 24.04+/26.04 AppArmor bwrap profile or kernel.unprivileged_userns_clone).');
    }

    const disableTest = spawnSync(
      bwrapPath,
      [
        '--ro-bind', '/', '/',
        '--dev', '/dev',
        '--proc', '/proc',
        '--unshare-user',
        '--disable-userns',
        '--unshare-pid',
        '--unshare-net',
        '--new-session',
        '--die-with-parent',
        '--',
        shellBin, '-c', ':',
      ],
      { encoding: 'utf8', timeout: 5000 },
    );
    disableUsernsFlag = disableTest.status === 0;
    sandboxDetails.push(`--disable-userns: ${disableUsernsFlag ? 'supported' : 'not supported (will rely on seccomp unshare/clone3 block)'}`);

    if (unprivilegedUserns) {
      const maskTest = spawnSync(
        bwrapPath,
        [
          '--ro-bind', '/', '/',
          '--dev', '/dev',
          '--proc', '/proc',
          '--tmpfs', '/mnt',
          '--tmpfs', '/run',
          '--unshare-user',
          '--unshare-pid',
          '--unshare-net',
          '--new-session',
          '--die-with-parent',
          '--',
          shellBin, '-c', 'test -z "$(ls -A /mnt 2>/dev/null)" && test -z "$(ls -A /run 2>/dev/null)"',
        ],
        { encoding: 'utf8', timeout: 5000 },
      );
      escapeMaskSelfTest = maskTest.status === 0;
      sandboxDetails.push(`escape-surface mask (/mnt + /run tmpfs): ${escapeMaskSelfTest ? 'PASS' : 'FAIL'}`);

      // Verify private config directory read-only empty tmpfs masking works on this kernel/bwrap
      const probeMaskTarget = path.join(os.homedir(), '.config');
      const maskArgs = [
        '--ro-bind', '/', '/',
        '--dev', '/dev',
        '--proc', '/proc',
      ];
      const checkDir = fs.existsSync(probeMaskTarget) ? probeMaskTarget : '/tmp';
      maskArgs.push(
        '--tmpfs', checkDir,
        '--remount-ro', checkDir,
        '--unshare-user',
        '--unshare-pid',
        '--unshare-net',
        '--new-session',
        '--die-with-parent',
        '--',
        shellBin, '-c', 'test -z "$(ls -A "$1" 2>/dev/null)" && ! touch "$1/__probe" 2>/dev/null', 'dsh-doctor-mask', checkDir,
      );
      const cfgMaskRes = spawnSync(bwrapPath, maskArgs, { encoding: 'utf8', timeout: 5000 });
      configMaskSelfTest = cfgMaskRes.status === 0;
      sandboxDetails.push(`config folder mask (--tmpfs + --remount-ro): ${configMaskSelfTest ? 'PASS' : 'FAIL'}`);

      if (arch === 'x86_64' || arch === 'aarch64') {
        const sec = runRealSeccompSelfTest(bwrapPath, arch);
        seccompIoUringBlocked = sec.ioUringBlocked;
        seccompAfVsockBlocked = sec.afVsockBlocked;
        sandboxDetails.push(`seccomp-bpf live probe: ${sec.detail}`);
        if (sec.ioUringBlocked === false || sec.afVsockBlocked === false) {
          remediation.push('Kernel seccomp-bpf filter did not return EPERM for io_uring_setup / AF_VSOCK; check kernel seccomp support.');
        }
      }
    }
  }

  const hardware = probeHardwareCapabilities();
  const tools = TOOL_MATRIX.map(probeTool);
  const missingMandatory = tools.filter((t) => t.tier === 'mandatory' && !t.present);
  const missingCore = tools.filter((t) => t.tier === 'core' && !t.present);
  const missingStandard = tools.filter((t) => t.tier === 'standard' && !t.present);
  const missingUniversal = tools.filter((t) => t.tier === 'universal' && !t.present);

  if (missingMandatory.length > 0) {
    if (isNixOs) {
      remediation.push(
        `NixOS detected — add missing sandbox primitives (${missingMandatory.map((t) => t.name).join(', ')}) to /etc/nixos/configuration.nix (environment.systemPackages = with pkgs; [ bubblewrap util-linux socat bash nodejs_24 ]) or run: nix profile install nixpkgs#bubblewrap nixpkgs#util-linux nixpkgs#socat nixpkgs#nodejs_24`,
      );
    } else {
      remediation.push(`Install mandatory sandbox tools: ${missingMandatory.map((t) => t.name).join(', ')} (run provision-wsl.sh --profile ${selectedProfile} --step base)`);
    }
  }
  if (missingCore.length > 0) {
    if (isNixOs) {
      remediation.push(
        `NixOS missing core tools (${missingCore.map((t) => t.name).join(', ')}) — add pkgs.{git,ripgrep,fd,jq,curl,python3,gcc,cmake} to configuration.nix (enable programs.nix-ld.enable = true if running generic glibc tarballs)`,
      );
    } else {
      remediation.push(`Install missing core Codex CLI tools: ${missingCore.map((t) => t.name).join(', ')} (run provision-wsl.sh --profile ${selectedProfile} --step cli)`);
    }
  }
  if ((selectedProfile === 'standard' || selectedProfile === 'universal') && missingStandard.length > 0) {
    remediation.push(`Missing '${selectedProfile}' profile tools: ${missingStandard.map((t) => t.name).join(', ')} (run provision-wsl.sh --profile ${selectedProfile})`);
  }
  if (selectedProfile === 'universal' && missingUniversal.length > 0) {
    remediation.push(`Missing 'universal' profile tools: ${missingUniversal.map((t) => t.name).join(', ')} (run provision-wsl.sh --profile universal)`);
  }

  let upstreamReachable                     ;
  if (options?.upstreamProxy) {
    upstreamReachable = await testTcpReachable(options.upstreamProxy);
    if (!upstreamReachable) {
      let proxyHost = '';
      let proxyPort = '7890';
      try {
        const u = new URL(options.upstreamProxy);
        proxyHost = u.hostname.toLowerCase();
        proxyPort = u.port || (u.protocol === 'https:' ? '443' : '80');
      } catch {
        // ignore invalid URL
      }
      if (isWsl2 && (proxyHost === '127.0.0.1' || proxyHost === 'localhost' || proxyHost === '::1')) {
        const gwHint = netHint.gatewayHint
          ? ` Detected NAT Windows host gateway: http://${netHint.gatewayHint}:${proxyPort}`
          : '';
        remediation.push(
          `Upstream proxy ${options.upstreamProxy} targets loopback (${proxyHost}), which resolves to the WSL VM itself under default NAT networking (mode=${netHint.mode}). Recommended for stability & USB/VPN testing: keep WSL networkingMode=NAT, enable "Allow LAN" in your Windows proxy client (Clash/Mihomo/v2rayN), and set upstreamProxy to the Windows NAT gateway IP.${gwHint} (Only if you specifically need 127.0.0.1 in WSL without Allow LAN on Win11 22H2+ & WSL >= 2.4.0, set networkingMode=mirrored in %USERPROFILE%\\.wslconfig).`,
        );
      } else {
        remediation.push(`Upstream proxy ${options.upstreamProxy} is unreachable from Linux; verify local proxy Allow LAN or host firewall rules.`);
      }
    }
  }

  const hardBlocked =
    !nonRoot ||
    !bwrapPath ||
    !unprivilegedUserns ||
    !escapeMaskSelfTest ||
    !configMaskSelfTest ||
    seccompIoUringBlocked === false ||
    seccompAfVsockBlocked === false ||
    missingMandatory.length > 0 ||
    Boolean(options?.strictWsl2 && !isWsl2);

  const profileDegraded =
    !permCheck.ok ||
    seccompIoUringBlocked === null ||
    seccompAfVsockBlocked === null ||
    missingCore.length > 0 ||
    ((selectedProfile === 'standard' || selectedProfile === 'universal') && missingStandard.length > 0) ||
    (selectedProfile === 'universal' && missingUniversal.length > 0) ||
    upstreamReachable === false;

  const verdict                                   = hardBlocked
    ? 'blocked'
    : profileDegraded
      ? 'degraded'
      : 'ready';

  return {
    timestamp: new Date().toISOString(),
    selectedProfile,
    os: {
      platform,
      arch,
      kernel,
      isWsl2,
      wslDistroName: process.env.WSL_DISTRO_NAME || undefined,
      distroId: osRel.id,
      distroPrettyName: osRel.prettyName,
      drvfsAutomountActive,
      initSystem,
      isNixOs,
    },
    user: { uid, username, nonRoot },
    sandbox: {
      bwrapPath,
      bwrapVersion,
      unprivilegedUserns,
      disableUsernsFlag,
      seccompIoUringBlocked,
      seccompAfVsockBlocked,
      escapeMaskSelfTest,
      configMaskSelfTest,
      configDirPermsOk: permCheck.ok,
      details: sandboxDetails,
    },
    hardware,
    tools,
    network: {
      upstreamProxy: options?.upstreamProxy,
      upstreamReachable,
      wslNetworkingMode: netHint.mode,
      natGatewayHint: netHint.gatewayHint,
    },
    verdict,
    remediation,
  };
}

function formatHumanReport(report              )         {
  const lines           = [];
  lines.push('============================================================');
  lines.push(` dsh-wsl-doctor  |  Profile: ${report.selectedProfile}  |  Verdict: ${report.verdict.toUpperCase()}`);
  lines.push('============================================================');
  lines.push(`OS       : ${report.os.distroPrettyName ?? report.os.platform} (${report.os.arch}, kernel ${report.os.kernel}, WSL2=${report.os.isWsl2}${report.os.wslDistroName ? `, distro=${report.os.wslDistroName}` : ''}, init=${report.os.initSystem ?? 'unknown'}${report.os.isNixOs ? ', NixOS' : ''})`);
  lines.push(`Mounts   : host DrvFS /mnt/* automount=${report.os.drvfsAutomountActive ? 'active (masked inside bwrap via --tmpfs /mnt)' : 'disabled'}`);
  lines.push(`User     : ${report.user.username} (uid=${report.user.uid}, nonRoot=${report.user.nonRoot})`);
  lines.push(`bwrap    : ${report.sandbox.bwrapVersion ?? 'MISSING'} (${report.sandbox.bwrapPath ?? 'not found'})`);
  lines.push(`Sandbox  : userns=${report.sandbox.unprivilegedUserns}, disable-userns=${report.sandbox.disableUsernsFlag}, escapeMask=${report.sandbox.escapeMaskSelfTest}, configMask=${report.sandbox.configMaskSelfTest}, configACL=${report.sandbox.configDirPermsOk}`);
  lines.push(`Seccomp  : io_uring_EPERM=${String(report.sandbox.seccompIoUringBlocked)}, AF_VSOCK_EPERM=${String(report.sandbox.seccompAfVsockBlocked)}`);
  lines.push(`USB/HW   : vhci_hcd=${report.hardware.vhciHcdReady}, lsusb=${report.hardware.lsusbPresent}, /dev/bus/usb nodes=${report.hardware.usbBusNodesCount}, charNodes=[${report.hardware.serialAndHidNodes.join(', ')}]`);
  if (report.network.upstreamProxy || report.network.wslNetworkingMode) {
    lines.push(`Network  : wslMode=${report.network.wslNetworkingMode ?? 'unknown'}${report.network.natGatewayHint ? `, gateway=${report.network.natGatewayHint}` : ''}${report.network.upstreamProxy ? `, proxy=${report.network.upstreamProxy} (reachable=${String(report.network.upstreamReachable)})` : ''}`);
  }
  lines.push('');
  lines.push(`Codex Tool Matrix (selected profile: ${report.selectedProfile}):`);
  for (const t of report.tools) {
    const mark = t.present ? '[OK]  ' : '[MISS]';
    lines.push(`  ${mark} ${t.name.padEnd(14)} (${t.tier.padEnd(9)}) ${t.version ?? ''}`);
  }
  if (report.remediation.length > 0) {
    lines.push('');
    lines.push('Remediation:');
    for (const r of report.remediation) {
      lines.push(`  - ${r}`);
    }
  }
  return lines.join('\n');
}

// CLI entrypoint (works whether invoked directly via .ts/.js OR via symlinked `dsh-wsl-doctor` bin)
let isDirectRun = false;
if (process.argv[1]) {
  try {
    isDirectRun = fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url));
  } catch {
    isDirectRun = process.argv[1].endsWith('doctor.ts') || process.argv[1].endsWith('doctor.js');
  }
}

if (isDirectRun) {
  const args = process.argv.slice(2);
  const asJson = args.includes('--json');
  const strictWsl2 = args.includes('--strict-wsl2');
  const proxyIdx = args.indexOf('--proxy');
  const upstreamProxy = proxyIdx !== -1 ? args[proxyIdx + 1] : undefined;
  const profileIdx = args.indexOf('--profile');
  let profile                                ;
  if (profileIdx !== -1) {
    const rawProfile = args[profileIdx + 1];
    if (rawProfile === 'core' || rawProfile === 'standard' || rawProfile === 'universal') {
      profile = rawProfile;
    } else {
      process.stderr.write(`[ERROR] Invalid --profile '${String(rawProfile ?? '')}' (expected core|standard|universal)\n`);
      process.exit(2);
    }
  }

  void runDoctor({ upstreamProxy, strictWsl2, profile }).then((report) => {
    if (asJson) {
      process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    } else {
      process.stdout.write(formatHumanReport(report) + '\n');
    }
    if (report.verdict === 'blocked') {
      process.exitCode = 1;
    }
  });
}
