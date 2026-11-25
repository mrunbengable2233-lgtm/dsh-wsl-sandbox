#!/usr/bin/env node
/**
 * `dsh-wsl-doctor` — Real Kernel Isolation & Codex Toolchain Diagnostic CLI.
 *
 * Verifies:
 * 1. OS & WSL 2 environment detection
 * 2. Non-root UID enforcement (blocks UID 0)
 * 3. Real `bwrap` execution, `--disable-userns` support
 * 4. Real `seccomp-bpf` kernel enforcement (`io_uring_setup` EPERM & `AF_VSOCK` EPERM)
 * 5. WSL 2 escape-surface masking self-test (`/mnt` and `/run/WSL` isolated via `--tmpfs`)
 * 6. 22-tool Codex matrix (required vs optional profile tools)
 * 7. Optional upstream proxy TCP reachability
 *
 * Usage:
 *   node packages/bootstrap/src/doctor.ts [--json] [--proxy http://127.0.0.1:7890] [--strict-wsl2]
 */

import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { compileSeccompBpf,                } from '../../core/src/index.js';

                            
                        
                                                   
                            
                         
                            
 

                               
                             
                
                              
                          
                            
                             
    
                  
                         
                              
                              
    
                     
                                      
                                         
                                         
                                        
                                                   
                                                   
                                         
                               
    
                              
                     
                                    
                                         
    
                                                     
                                 
 

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
  { name: 'bun', binaries: ['bun'], versionArgs: ['-v'], tier: 'standard' },
  { name: 'go', binaries: ['go'], versionArgs: ['version'], tier: 'standard' },
  { name: 'rustc', binaries: ['rustc'], versionArgs: ['--version'], tier: 'standard' },
  { name: 'cargo', binaries: ['cargo'], versionArgs: ['--version'], tier: 'standard' },
  { name: 'mise', binaries: ['mise'], versionArgs: ['--version'], tier: 'standard' },
];

function which(bin        )                {
  try {
    const out = execFileSync('which', [bin], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    return out || null;
  } catch {
    return null;
  }
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

function probeTool(spec                              )            {
  for (const bin of spec.binaries) {
    const found = which(bin);
    if (!found) continue;
    let version                    ;
    try {
      const out = execFileSync(found, [...spec.versionArgs], {
        encoding: 'utf8',
        timeout: 3000,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      const firstLine = out.split('\n').map((l) => l.trim()).find(Boolean);
      version = firstLine?.slice(0, 80);
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
  const python3 = which('python3');
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
      'import ctypes, errno, json, socket',
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

export async function runDoctor(options    
                         
                       
 )                        {
  const platform = process.platform;
  const rawArch = os.arch();
  const arch                     = rawArch === 'x64' ? 'x86_64' : rawArch === 'arm64' ? 'aarch64' : rawArch;
  const kernel = os.release();
  const isWsl2 = detectWsl2(kernel);
  const uid = typeof process.getuid === 'function' ? process.getuid() : -1;
  const username = os.userInfo().username;
  const nonRoot = uid > 0;

  const remediation           = [];
  const sandboxDetails           = [];

  if (!nonRoot) {
    remediation.push('Switch to a non-root WSL user (UID > 0); root execution is blocked by dsh-wsl-sandbox.');
  }
  if (options?.strictWsl2 && !isWsl2) {
    remediation.push('Run inside a WSL 2 distribution (not WSL 1 or non-WSL host).');
  }

  const bwrapPath = which('bwrap');
  let bwrapVersion                = null;
  let unprivilegedUserns = false;
  let disableUsernsFlag = false;
  let seccompIoUringBlocked                 = null;
  let seccompAfVsockBlocked                 = null;
  let escapeMaskSelfTest = false;

  if (!bwrapPath) {
    remediation.push('Install bubblewrap: sudo apt-get update && sudo apt-get install -y bubblewrap socat util-linux');
  } else {
    try {
      bwrapVersion = execFileSync(bwrapPath, ['--version'], { encoding: 'utf8', timeout: 3000 }).trim();
    } catch {
      bwrapVersion = 'unknown';
    }

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
        '/bin/true',
      ],
      { encoding: 'utf8', timeout: 5000 },
    );
    unprivilegedUserns = nsTest.status === 0;
    if (!unprivilegedUserns) {
      sandboxDetails.push(`bwrap userns test failed: ${(nsTest.stderr || '').trim()}`);
      remediation.push('Enable unprivileged user namespaces (check Ubuntu 24.04 AppArmor profile for bwrap or kernel.unprivileged_userns_clone).');
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
        '/bin/true',
      ],
      { encoding: 'utf8', timeout: 5000 },
    );
    disableUsernsFlag = disableTest.status === 0;
    sandboxDetails.push(`--disable-userns: ${disableUsernsFlag ? 'supported' : 'not supported (will rely on seccomp unshare/clone3 block)'}`);

    if (unprivilegedUserns) {
      // Escape-surface masking self-test (--tmpfs /run hides /run/WSL, dbus, docker; --tmpfs /mnt hides /mnt/c & /mnt/wslg)
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
          '/bin/bash', '-c', 'test -z "$(ls -A /mnt 2>/dev/null)" && test -z "$(ls -A /run 2>/dev/null)"',
        ],
        { encoding: 'utf8', timeout: 5000 },
      );
      escapeMaskSelfTest = maskTest.status === 0;
      sandboxDetails.push(`escape-surface mask (/mnt + /run tmpfs): ${escapeMaskSelfTest ? 'PASS' : 'FAIL'}`);

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

  const tools = TOOL_MATRIX.map(probeTool);
  const missingMandatory = tools.filter((t) => t.tier === 'mandatory' && !t.present);
  const missingCore = tools.filter((t) => t.tier === 'core' && !t.present);
  const missingStandard = tools.filter((t) => t.tier === 'standard' && !t.present);

  if (missingMandatory.length > 0) {
    remediation.push(`Install mandatory sandbox tools: ${missingMandatory.map((t) => t.name).join(', ')} (run provision-wsl.sh --step base)`);
  }
  if (missingCore.length > 0) {
    remediation.push(`Install missing core Codex CLI tools: ${missingCore.map((t) => t.name).join(', ')} (run provision-wsl.sh --step cli)`);
  }
  if (missingStandard.length > 0) {
    remediation.push(`Optional standard Codex tools missing: ${missingStandard.map((t) => t.name).join(', ')} (run provision-wsl.sh --profile standard)`);
  }

  let upstreamReachable                     ;
  if (options?.upstreamProxy) {
    upstreamReachable = await testTcpReachable(options.upstreamProxy);
    if (!upstreamReachable) {
      remediation.push(`Upstream proxy ${options.upstreamProxy} is unreachable from Linux; verify Clash/Mihomo Allow LAN or WSL networkingMode=mirrored.`);
    }
  }

  const hardBlocked =
    !nonRoot ||
    !bwrapPath ||
    !unprivilegedUserns ||
    !escapeMaskSelfTest ||
    seccompIoUringBlocked === false ||
    seccompAfVsockBlocked === false ||
    missingMandatory.length > 0 ||
    Boolean(options?.strictWsl2 && !isWsl2);

  const verdict                                   = hardBlocked
    ? 'blocked'
    : missingCore.length > 0 || upstreamReachable === false
      ? 'degraded'
      : 'ready';

  return {
    timestamp: new Date().toISOString(),
    os: { platform, arch, kernel, isWsl2 },
    user: { uid, username, nonRoot },
    sandbox: {
      bwrapPath,
      bwrapVersion,
      unprivilegedUserns,
      disableUsernsFlag,
      seccompIoUringBlocked,
      seccompAfVsockBlocked,
      escapeMaskSelfTest,
      details: sandboxDetails,
    },
    tools,
    network: {
      upstreamProxy: options?.upstreamProxy,
      upstreamReachable,
    },
    verdict,
    remediation,
  };
}

function formatHumanReport(report              )         {
  const lines           = [];
  lines.push('============================================================');
  lines.push(` dsh-wsl-doctor  |  Verdict: ${report.verdict.toUpperCase()}`);
  lines.push('============================================================');
  lines.push(`OS      : ${report.os.platform} ${report.os.arch} (kernel ${report.os.kernel}, WSL2=${report.os.isWsl2})`);
  lines.push(`User    : ${report.user.username} (uid=${report.user.uid}, nonRoot=${report.user.nonRoot})`);
  lines.push(`bwrap   : ${report.sandbox.bwrapVersion ?? 'MISSING'} (${report.sandbox.bwrapPath ?? 'not found'})`);
  lines.push(`Sandbox : userns=${report.sandbox.unprivilegedUserns}, disable-userns=${report.sandbox.disableUsernsFlag}, escapeMask=${report.sandbox.escapeMaskSelfTest}`);
  lines.push(`Seccomp : io_uring_EPERM=${String(report.sandbox.seccompIoUringBlocked)}, AF_VSOCK_EPERM=${String(report.sandbox.seccompAfVsockBlocked)}`);
  if (report.network.upstreamProxy) {
    lines.push(`Proxy   : ${report.network.upstreamProxy} (reachable=${String(report.network.upstreamReachable)})`);
  }
  lines.push('');
  lines.push('Codex Tool Matrix:');
  for (const t of report.tools) {
    const mark = t.present ? '[OK]  ' : '[MISS]';
    lines.push(`  ${mark} ${t.name.padEnd(10)} (${t.tier.padEnd(9)}) ${t.version ?? ''}`);
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

// CLI entrypoint
const isDirectRun =
  process.argv[1] &&
  (process.argv[1].endsWith('doctor.ts') || process.argv[1].endsWith('doctor.js'));

if (isDirectRun) {
  const args = process.argv.slice(2);
  const asJson = args.includes('--json');
  const strictWsl2 = args.includes('--strict-wsl2');
  const proxyIdx = args.indexOf('--proxy');
  const upstreamProxy = proxyIdx !== -1 ? args[proxyIdx + 1] : undefined;

  void runDoctor({ upstreamProxy, strictWsl2 }).then((report) => {
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
