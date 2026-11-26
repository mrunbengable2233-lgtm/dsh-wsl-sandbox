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
import { compileSeccompBpf, type EnvironmentProfile, type LinuxArch } from '../../core/src/index.ts';

export interface ToolProbe {
  readonly name: string;
  readonly tier: 'mandatory' | 'core' | 'standard' | 'universal';
  readonly present: boolean;
  readonly path?: string;
  readonly version?: string;
}

export interface DoctorReport {
  readonly timestamp: string;
  readonly selectedProfile: EnvironmentProfile;
  readonly os: {
    readonly platform: string;
    readonly arch: string;
    readonly kernel: string;
    readonly isWsl2: boolean;
    readonly wslDistroName?: string;
    readonly distroId?: string;
    readonly distroPrettyName?: string;
    readonly drvfsAutomountActive: boolean;
  };
  readonly user: {
    readonly uid: number;
    readonly username: string;
    readonly nonRoot: boolean;
  };
  readonly sandbox: {
    readonly bwrapPath: string | null;
    readonly bwrapVersion: string | null;
    readonly unprivilegedUserns: boolean;
    readonly disableUsernsFlag: boolean;
    readonly seccompIoUringBlocked: boolean | null;
    readonly seccompAfVsockBlocked: boolean | null;
    readonly escapeMaskSelfTest: boolean;
    readonly configMaskSelfTest: boolean;
    readonly configDirPermsOk: boolean;
    readonly details: string[];
  };
  readonly hardware: {
    readonly vhciHcdReady: boolean;
    readonly lsusbPresent: boolean;
    readonly usbBusNodesCount: number;
    readonly serialAndHidNodes: string[];
    readonly driverNote: string;
  };
  readonly tools: ToolProbe[];
  readonly network: {
    readonly upstreamProxy?: string;
    readonly upstreamReachable?: boolean;
  };
  readonly verdict: 'ready' | 'degraded' | 'blocked';
  readonly remediation: string[];
}

const TOOL_MATRIX: ReadonlyArray<{
  readonly name: string;
  readonly binaries: readonly string[];
  readonly versionArgs: readonly string[];
  readonly tier: 'mandatory' | 'core' | 'standard' | 'universal';
}> = [
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
function getSearchDirs(): string[] {
  const home = os.homedir();
  const extra = [
    path.join(home, '.local', 'share', 'mise', 'shims'),
    path.join(home, '.local', 'bin'),
    path.join(home, '.cargo', 'bin'),
    path.join(home, '.bun', 'bin'),
    '/usr/local/go/bin',
  ];
  const envDirs = (process.env.PATH ?? '').split(path.delimiter).filter(Boolean);
  return [...new Set([...extra, ...envDirs, '/usr/local/bin', '/usr/bin', '/bin'])];
}

function findExecutable(bin: string): string | null {
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

function detectWsl2(kernel: string): boolean {
  if (/microsoft.*wsl2/i.test(kernel) || /wsl2/i.test(kernel)) return true;
  try {
    const procVer = fs.readFileSync('/proc/version', 'utf8');
    if (/microsoft-standard-wsl2/i.test(procVer)) return true;
  } catch {
    // ignore
  }
  return Boolean(process.env.WSL_DISTRO_NAME && fs.existsSync('/run/WSL'));
}

function detectDrvfsAutomount(): boolean {
  try {
    const mounts = fs.readFileSync('/proc/mounts', 'utf8');
    return /\s\/mnt\/[a-z]\s+(?:9p|drvfs)\s/i.test(mounts);
  } catch {
    return false;
  }
}

function probeTool(spec: (typeof TOOL_MATRIX)[number]): ToolProbe {
  const enrichedPath = getSearchDirs().join(path.delimiter);
  for (const bin of spec.binaries) {
    const found = findExecutable(bin);
    if (!found) continue;
    let version: string | undefined;
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

function testTcpReachable(proxyUrl: string): Promise<boolean> {
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
  bwrapPath: string,
  arch: LinuxArch,
): { ioUringBlocked: boolean | null; afVsockBlocked: boolean | null; detail: string } {
  const python3 = findExecutable('python3');
  if (!python3) {
    return { ioUringBlocked: null, afVsockBlocked: null, detail: 'python3 missing; skipped live seccomp syscall probe' };
  }

  const bpf = compileSeccompBpf({ arch, blockNetworkSockets: false });
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-doctor-bpf-'));
  const bpfPath = path.join(tmpDir, 'filter.bpf');
  let fd: number | undefined;
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

    const parsed = JSON.parse((res.stdout || '{}').trim()) as {
      io_uring_ret: number;
      io_uring_errno: number;
      vsock_errno: number;
    };
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

function probeHardwareCapabilities(): DoctorReport['hardware'] {
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

  const serialAndHidNodes: string[] = [];
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

function readPersistedProfile(): EnvironmentProfile | undefined {
  const envP = process.env.DSH_WSL_PROFILE;
  if (envP === 'core' || envP === 'standard' || envP === 'universal') return envP;
  try {
    const p = path.join(os.homedir(), '.config', 'dsh-wsl-sandbox', 'profile.json');
    if (fs.existsSync(p)) {
      const parsed = JSON.parse(fs.readFileSync(p, 'utf8')) as { profile?: string };
      if (parsed.profile === 'core' || parsed.profile === 'standard' || parsed.profile === 'universal') {
        return parsed.profile;
      }
    }
  } catch {
    // ignore
  }
  return undefined;
}

function readOsRelease(): { id?: string; prettyName?: string } {
  try {
    const raw = fs.readFileSync('/etc/os-release', 'utf8');
    const id = raw.match(/^ID=["']?([^"'\n]+)["']?/m)?.[1];
    const prettyName = raw.match(/^PRETTY_NAME=["']?([^"'\n]+)["']?/m)?.[1];
    return { id, prettyName };
  } catch {
    return {};
  }
}

function checkPrivateConfigPermissions(): { ok: boolean; detail: string } {
  const home = os.homedir();
  const sensitiveDirs = [
    path.join(home, '.config', 'dsh-wsl-sandbox'),
    path.join(home, '.dsh', 'dsh-wsl-sandbox'),
  ];
  const issues: string[] = [];
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

export async function runDoctor(options?: {
  upstreamProxy?: string;
  strictWsl2?: boolean;
  profile?: EnvironmentProfile;
}): Promise<DoctorReport> {
  const selectedProfile: EnvironmentProfile = options?.profile ?? readPersistedProfile() ?? 'standard';
  const platform = process.platform;
  const rawArch = os.arch();
  const arch: LinuxArch | string = rawArch === 'x64' ? 'x86_64' : rawArch === 'arm64' ? 'aarch64' : rawArch;
  const kernel = os.release();
  const isWsl2 = detectWsl2(kernel);
  const drvfsAutomountActive = detectDrvfsAutomount();
  const osRel = readOsRelease();
  const uid = typeof process.getuid === 'function' ? process.getuid() : -1;
  const username = os.userInfo().username;
  const nonRoot = uid > 0;

  const remediation: string[] = [];
  const sandboxDetails: string[] = [];

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
  const trueBin = findExecutable('true') ?? '/bin/true';
  const shellBin = findExecutable('bash') ?? findExecutable('sh') ?? '/bin/sh';
  let bwrapVersion: string | null = null;
  let unprivilegedUserns = false;
  let disableUsernsFlag = false;
  let seccompIoUringBlocked: boolean | null = null;
  let seccompAfVsockBlocked: boolean | null = null;
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
        trueBin,
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
        trueBin,
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
        shellBin, '-c', `test -z "$(ls -A '${checkDir}' 2>/dev/null)" && ! touch '${checkDir}/__probe' 2>/dev/null`,
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
    remediation.push(`Install mandatory sandbox tools: ${missingMandatory.map((t) => t.name).join(', ')} (run provision-wsl.sh --profile ${selectedProfile} --step base)`);
  }
  if (missingCore.length > 0) {
    remediation.push(`Install missing core Codex CLI tools: ${missingCore.map((t) => t.name).join(', ')} (run provision-wsl.sh --profile ${selectedProfile} --step cli)`);
  }
  if ((selectedProfile === 'standard' || selectedProfile === 'universal') && missingStandard.length > 0) {
    remediation.push(`Missing '${selectedProfile}' profile tools: ${missingStandard.map((t) => t.name).join(', ')} (run provision-wsl.sh --profile ${selectedProfile})`);
  }
  if (selectedProfile === 'universal' && missingUniversal.length > 0) {
    remediation.push(`Missing 'universal' profile tools: ${missingUniversal.map((t) => t.name).join(', ')} (run provision-wsl.sh --profile universal)`);
  }

  let upstreamReachable: boolean | undefined;
  if (options?.upstreamProxy) {
    upstreamReachable = await testTcpReachable(options.upstreamProxy);
    if (!upstreamReachable) {
      remediation.push(`Upstream proxy ${options.upstreamProxy} is unreachable from Linux; verify local proxy Allow LAN or WSL networkingMode=mirrored.`);
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
    missingCore.length > 0 ||
    ((selectedProfile === 'standard' || selectedProfile === 'universal') && missingStandard.length > 0) ||
    (selectedProfile === 'universal' && missingUniversal.length > 0) ||
    upstreamReachable === false;

  const verdict: 'ready' | 'degraded' | 'blocked' = hardBlocked
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
    },
    verdict,
    remediation,
  };
}

function formatHumanReport(report: DoctorReport): string {
  const lines: string[] = [];
  lines.push('============================================================');
  lines.push(` dsh-wsl-doctor  |  Profile: ${report.selectedProfile}  |  Verdict: ${report.verdict.toUpperCase()}`);
  lines.push('============================================================');
  lines.push(`OS       : ${report.os.distroPrettyName ?? report.os.platform} (${report.os.arch}, kernel ${report.os.kernel}, WSL2=${report.os.isWsl2}${report.os.wslDistroName ? `, distro=${report.os.wslDistroName}` : ''})`);
  lines.push(`Mounts   : host DrvFS /mnt/* automount=${report.os.drvfsAutomountActive ? 'active (masked inside bwrap via --tmpfs /mnt)' : 'disabled'}`);
  lines.push(`User     : ${report.user.username} (uid=${report.user.uid}, nonRoot=${report.user.nonRoot})`);
  lines.push(`bwrap    : ${report.sandbox.bwrapVersion ?? 'MISSING'} (${report.sandbox.bwrapPath ?? 'not found'})`);
  lines.push(`Sandbox  : userns=${report.sandbox.unprivilegedUserns}, disable-userns=${report.sandbox.disableUsernsFlag}, escapeMask=${report.sandbox.escapeMaskSelfTest}, configMask=${report.sandbox.configMaskSelfTest}, configACL=${report.sandbox.configDirPermsOk}`);
  lines.push(`Seccomp  : io_uring_EPERM=${String(report.sandbox.seccompIoUringBlocked)}, AF_VSOCK_EPERM=${String(report.sandbox.seccompAfVsockBlocked)}`);
  lines.push(`USB/HW   : vhci_hcd=${report.hardware.vhciHcdReady}, lsusb=${report.hardware.lsusbPresent}, /dev/bus/usb nodes=${report.hardware.usbBusNodesCount}, charNodes=[${report.hardware.serialAndHidNodes.join(', ')}]`);
  if (report.network.upstreamProxy) {
    lines.push(`Proxy    : ${report.network.upstreamProxy} (reachable=${String(report.network.upstreamReachable)})`);
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
  let profile: EnvironmentProfile | undefined;
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
