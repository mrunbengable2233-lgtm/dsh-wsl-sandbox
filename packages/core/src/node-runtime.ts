import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { failSandbox } from './errors.ts';

/**
 * Shared Node.js runtime discovery & carrier helpers for `dsh-wsl-sandbox`.
 *
 * Design goals:
 * 1. Host side (Windows / Desktop / Web / Headless CLI):
 *    - `dsh-wsl-sandbox` runs 100% in-process inside DeepSeek Harness (`@deepseek-ai/dsh`, Node 24+
 *      or Node 22.19+ LTS) with ZERO native C++ addons and ZERO external npm runtime dependencies,
 *      sharing the exact same Node instance as DSH core and all peer DSH plugins.
 *    - Any local helper subprocess (`local-linux` runner, doctor, tests) reuses DSH's own carrier
 *      (`process.execPath`), automatically injecting `ELECTRON_RUN_AS_NODE=1` when hosted inside
 *      Electron (DSH Desktop) and scrubbing host `NODE_OPTIONS`/`TSX_*` inspector flags (matching
 *      `@deepseek-ai/dsh-subprocess-local`).
 * 2. WSL 2 Linux side:
 *    - Automatically discovers and shares any compatible Linux `node` (`>= 22`) already installed
 *      inside WSL by DSH headless/remote (`~/.dsh/runtime/bin`), `mise`, `nvm`, `fnm`, `volta`,
 *      or distro packages (`/usr/local/bin/node`, `/usr/bin/node`), avoiding duplicate Node installs
 *      and strictly rejecting `/mnt/*` Windows `.exe` binaries.
 */

export interface SharedHostNodeRuntime {
  readonly executable: string;
  readonly nodeVersion: string;
  readonly isElectronCarrier: boolean;
  readonly sharedWithHostProcess: boolean;
  readonly envOverrides: Readonly<Record<string, string>>;
}

const HOST_STRIP_ENV_PREFIXES = ['NODE_OPTIONS', 'TSX_'] as const;

/**
 * Resolves the active DSH / Node carrier executable and scrubbed child environment on the host.
 */
export function resolveSharedHostNodeRuntime(
  customExecutable?: string,
  baseEnv: NodeJS.ProcessEnv = process.env,
): SharedHostNodeRuntime {
  const trimmed = customExecutable?.trim();
  const executable = trimmed && trimmed !== 'auto' ? trimmed : process.execPath;
  const sharedWithHostProcess = executable === process.execPath;
  const isElectronCarrier =
    sharedWithHostProcess && Boolean((process.versions as Record<string, string | undefined>).electron);

  const envOverrides: Record<string, string> = {};
  if (isElectronCarrier) {
    envOverrides.ELECTRON_RUN_AS_NODE = '1';
  }

  // Ensure child Node processes never inherit --inspect / loader hooks from the parent host
  void baseEnv;
  return {
    executable,
    nodeVersion: process.version,
    isElectronCarrier,
    sharedWithHostProcess,
    envOverrides,
  };
}

/**
 * Builds a clean `NodeJS.ProcessEnv` for spawning a child Node carrier from DSH host.
 */
export function buildHostNodeChildEnv(
  baseEnv: NodeJS.ProcessEnv = process.env,
  extraEnv: Readonly<Record<string, string | undefined>> = {},
  customExecutable?: string,
): NodeJS.ProcessEnv {
  const runtime = resolveSharedHostNodeRuntime(customExecutable, baseEnv);
  const env: NodeJS.ProcessEnv = { ...baseEnv };
  for (const key of Object.keys(env)) {
    const upper = key.toUpperCase();
    if (HOST_STRIP_ENV_PREFIXES.some((prefix) => upper.startsWith(prefix))) {
      delete env[key];
    }
  }
  for (const [k, v] of Object.entries(runtime.envOverrides)) {
    env[k] = v;
  }
  for (const [k, v] of Object.entries(extraEnv)) {
    if (v === undefined) delete env[k];
    else env[k] = v;
  }
  return env;
}

/**
 * Ordered relative search locations inside a WSL 2 user's `$HOME` (plus system paths) where
 * DSH remote/headless, peer plugins (`dsh-ssh`, `dsh-remote`), or developer version managers
 * install Linux Node.js runtimes.
 */
export const WSL_SHARED_NODE_REL_DIRS: readonly string[] = [
  '.dsh/runtime/bin',
  '.local/share/dsh/node/bin',
  '.local/share/mise/shims',
  '.local/bin',
  '.nvm/current/bin',
  '.local/share/fnm/aliases/default/bin',
  '.fnm/aliases/default/bin',
  '.volta/bin',
  '.asdf/shims',
];

export const WSL_SYSTEM_NODE_DIRS: readonly string[] = [
  '/opt/dsh-toolchain/shims',
  '/opt/dsh-toolchain/bin',
  '/usr/local/bin',
  '/usr/bin',
  '/bin',
];

/**
 * Validates an optional user-configured WSL Node binary path or name.
 * Rejects `/mnt/*` DrvFS paths and `.exe` binaries so the Linux runner never launches Windows Node!
 */
export function validateWslNodeExecutable(raw?: string): string {
  if (!raw || !raw.trim() || raw.trim() === 'auto') {
    return 'auto';
  }
  const trimmed = raw.trim();
  if (trimmed.includes('\0') || /[\r\n]/.test(trimmed)) {
    failSandbox('INVALID_SETUP', 'Invalid wslNodePath containing control characters');
  }
  if (trimmed.startsWith('/mnt/') || /\.exe$/i.test(trimmed) || /^[A-Za-z]:[\\/]/.test(trimmed)) {
    failSandbox(
      'POLICY_BLOCK',
      `WSL runner must use a native Linux Node binary inside WSL, not a Windows /mnt or .exe binary: ${trimmed}`,
    );
  }
  return trimmed;
}

/**
 * Pure-Node search for a shared Linux `node` executable when already running on Linux / inside WSL.
 */
export function findLocalLinuxSharedNode(homeDir = os.homedir()): string | null {
  const candidates: string[] = [];
  for (const rel of WSL_SHARED_NODE_REL_DIRS) {
    candidates.push(path.posix.join(homeDir, rel, 'node'));
  }
  // Check ~/.nvm/versions/node/v*/bin/node (highest version first)
  const nvmVersDir = path.join(homeDir, '.nvm', 'versions', 'node');
  try {
    if (fs.existsSync(nvmVersDir)) {
      const vers = fs
        .readdirSync(nvmVersDir)
        .filter((v) => v.startsWith('v'))
        .sort((a, b) => b.localeCompare(a, undefined, { numeric: true }));
      for (const v of vers) {
        candidates.push(path.join(nvmVersDir, v, 'bin', 'node'));
      }
    }
  } catch {
    // ignore
  }
  for (const sysDir of WSL_SYSTEM_NODE_DIRS) {
    candidates.push(path.posix.join(sysDir, 'node'));
  }

  for (const candidate of candidates) {
    if (candidate.startsWith('/mnt/')) continue;
    try {
      const st = fs.statSync(candidate);
      if (st.isFile()) {
        fs.accessSync(candidate, fs.constants.X_OK);
        return candidate;
      }
    } catch {
      // continue
    }
  }
  return null;
}

/**
 * POSIX `sh -c` bootstrap script used after `wsl.exe -d <Distro> --cd ~ --` to locate a shared
 * Linux `node` binary across `.dsh-wsl-env.sh`, DSH runtime dirs, `mise`, `nvm`, `fnm`, `volta`,
 * and `/usr/bin`, then `exec` in-place (preserving exact PID and clean stdio, ZERO shell interpolation).
 *
 * Positional args passed to `sh -c <script> dsh-wsl-bootstrap <nodeSpec> <scriptPath> [...extraArgs]`:
 *   $1 = nodeExecutable ('auto' | 'node' | '/abs/path/to/node')
 *   $2 = target JS script path (e.g. runner `main.js` or `doctor.js`)
 *   $@ (after shift 2) = arguments forwarded to target JS script
 */
export const WSL_SHARED_NODE_EXEC_SH = [
  '[ -f "$HOME/.dsh-wsl-env.sh" ] && . "$HOME/.dsh-wsl-env.sh" >/dev/null 2>&1 || true',
  'NODE_SPEC="$1"',
  'TARGET_SCRIPT="$2"',
  'shift 2',
  // Strip any /mnt/* Windows PATH entries before resolving Linux `node` so we never hit Windows node.exe
  'CLEAN_PATH=""',
  'OLD_IFS="$IFS"; IFS=":"',
  'for p in $PATH; do',
  '  case "$p" in /mnt/*|"") ;; *) CLEAN_PATH="${CLEAN_PATH:+$CLEAN_PATH:}$p" ;; esac',
  'done',
  'IFS="$OLD_IFS"',
  'EXTRA_PATH="$HOME/.dsh/runtime/bin:$HOME/.local/share/dsh/node/bin:$HOME/.local/share/mise/shims:$HOME/.local/bin:$HOME/.nvm/current/bin:$HOME/.local/share/fnm/aliases/default/bin:$HOME/.volta/bin:/opt/dsh-toolchain/shims:/opt/dsh-toolchain/bin:/usr/local/bin:/usr/bin:/bin"',
  'export PATH="$EXTRA_PATH${CLEAN_PATH:+:$CLEAN_PATH}"',
  'NODE_BIN=""',
  'if [ -n "$NODE_SPEC" ] && [ "$NODE_SPEC" != "auto" ] && [ "$NODE_SPEC" != "node" ]; then',
  '  NODE_BIN="$NODE_SPEC"',
  'elif command -v node >/dev/null 2>&1; then',
  '  NODE_BIN="$(command -v node)"',
  'else',
  '  for d in "$HOME"/.nvm/versions/node/v*/bin; do',
  '    if [ -x "$d/node" ]; then NODE_BIN="$d/node"; fi',
  '  done',
  'fi',
  'if [ -z "$NODE_BIN" ] || [ ! -x "$NODE_BIN" ]; then',
  '  echo "[dsh-wsl-sandbox] No Linux Node.js (>=22 / 24 LTS) found inside WSL. Run provision-wsl.sh --step node to install or link a shared Node runtime." >&2',
  '  exit 127',
  'fi',
  'unset NODE_OPTIONS',
  'exec "$NODE_BIN" "$TARGET_SCRIPT" "$@"',
].join('; ');

/**
 * Builds the `wsl.exe` argument vector to invoke a JS entrypoint inside WSL using the shared Linux Node runtime.
 */
export function buildWslNodeSpawnArgs(options: {
  readonly distro: string;
  readonly username?: string;
  readonly nodeExecutable?: string;
  readonly scriptPath: string;
  readonly scriptArgs?: readonly string[];
  readonly logLevel?: string;
  readonly leaseMs?: number;
}): string[] {
  const nodeSpec = validateWslNodeExecutable(options.nodeExecutable);
  const args: string[] = ['-d', options.distro, '--cd', '~'];
  if (options.username) {
    args.push('-u', options.username);
  }
  const envPrefix: string[] = [];
  if (options.leaseMs !== undefined && options.leaseMs > 0) {
    envPrefix.push(`DSH_WSL_RUNNER_LEASE_MS=${String(Math.floor(options.leaseMs))}`);
  }
  if (options.logLevel && /^[a-z]+$/.test(options.logLevel)) {
    envPrefix.push(`DSH_WSL_LOG_LEVEL=${options.logLevel}`);
  }
  args.push('--');
  if (envPrefix.length > 0) {
    args.push('env', ...envPrefix);
  }
  args.push(
    'sh',
    '-c',
    WSL_SHARED_NODE_EXEC_SH,
    'dsh-wsl-node',
    nodeSpec,
    options.scriptPath,
    ...(options.scriptArgs ?? []),
  );
  return args;
}
