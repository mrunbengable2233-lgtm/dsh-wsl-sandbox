import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { isValidDistroName, isValidLinuxUsername } from './binding.js';
import { failSandbox } from './errors.js';

/**
 * `dsh-wsl-sandbox` 共用 Node.js 运行时探测与进程载体工具。
 *
 * 设计目标：
 * 1. Windows 宿主机侧（Desktop / Web / Headless CLI）：
 *    - 本插件以纯 TypeScript 在 DeepSeek Harness（`@deepseek-ai/dsh`，Node >=20.11 / 22 LTS / 24 LTS）
 *      进程内直接运行，零 C++ 原生扩展、零第三方 npm 运行时依赖，与核心框架及其他插件共用同一运行时实例。
 *    - 子进程按需复用宿主 `process.execPath`（Electron 桌面端自动注入 `ELECTRON_RUN_AS_NODE=1`），并剥离
 *      `NODE_OPTIONS` / `TSX_*` 等调试 Hook 注入面。
 * 2. WSL 2 Linux 侧：
 *    - 在非登录 Shell 中主动发现并复用已安装的原生 Linux `node`（`>= 20`，优先 DSH `~/.dsh/runtime/bin`、
 *      `mise`、`nvm`、`fnm`、`volta`、`asdf`、NixOS `/run/current-system/sw/bin` 与 `~/.nix-profile/bin`
 *      以及发行版系统包），严格拦截并拒绝任何 `/mnt/*` 下的 Windows `.exe`（含符号链接穿透）。
 */

                                        
                              
                               
                                      
                                          
                                                          
 

const HOST_STRIP_ENV_PREFIXES = ['NODE_OPTIONS', 'TSX_']         ;

/**
 * Resolves the active DSH / Node carrier executable and scrubbed child environment on the host.
 */
export function resolveSharedHostNodeRuntime(
  customExecutable         ,
  baseEnv                    = process.env,
)                        {
  const trimmed = customExecutable?.trim();
  const executable = trimmed && trimmed !== 'auto' ? trimmed : process.execPath;
  const sharedWithHostProcess = executable === process.execPath;
  const isElectronCarrier =
    sharedWithHostProcess && Boolean((process.versions                                      ).electron);

  const envOverrides                         = {};
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
  baseEnv                    = process.env,
  extraEnv                                               = {},
  customExecutable         ,
)                    {
  const runtime = resolveSharedHostNodeRuntime(customExecutable, baseEnv);
  const env                    = { ...baseEnv };
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
export const WSL_SHARED_NODE_REL_DIRS                    = [
  '.dsh/runtime/bin',
  '.local/share/dsh/node/bin',
  '.local/share/dsh-wsl-sandbox/toolchains/node/bin',
  '.local/share/mise/shims',
  '.local/bin',
  '.nvm/current/bin',
  '.local/share/fnm/aliases/default/bin',
  '.fnm/aliases/default/bin',
  '.volta/bin',
  '.asdf/shims',
  '.nix-profile/bin',
];

export const WSL_SYSTEM_NODE_DIRS                    = [
  '/opt/dsh-toolchain/shims',
  '/opt/dsh-toolchain/bin',
  '/run/current-system/sw/bin',
  '/nix/var/nix/profiles/default/bin',
  '/usr/local/bin',
  '/usr/bin',
  '/bin',
];

/**
 * Validates an optional user-configured WSL Node binary path or name.
 * Rejects `/mnt/*` DrvFS paths and `.exe` binaries so the Linux runner never launches Windows Node!
 */
export function validateWslNodeExecutable(raw         )         {
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
 * Verifies realpathSync against `/mnt/` and `.exe` so symlinked Windows binaries are rejected.
 */
export function findLocalLinuxSharedNode(homeDir = os.homedir())                {
  const candidates           = [];
  for (const rel of WSL_SHARED_NODE_REL_DIRS) {
    candidates.push(path.posix.join(homeDir, rel, 'node'));
  }

  const pushSortedVersions = (baseDir        , suffixParts                   )       => {
    try {
      if (fs.existsSync(baseDir)) {
        const vers = fs
          .readdirSync(baseDir)
          .filter((v) => /^v?\d+/.test(v))
          .sort((a, b) => b.localeCompare(a, undefined, { numeric: true }));
        for (const v of vers) {
          candidates.push(path.join(baseDir, v, ...suffixParts));
        }
      }
    } catch {
      // ignore
    }
  };

  pushSortedVersions(path.join(homeDir, '.nvm', 'versions', 'node'), ['bin', 'node']);
  pushSortedVersions(path.join(homeDir, '.local', 'share', 'fnm', 'node-versions'), ['installation', 'bin', 'node']);
  pushSortedVersions(path.join(homeDir, '.fnm', 'node-versions'), ['installation', 'bin', 'node']);
  pushSortedVersions(path.join(homeDir, '.asdf', 'installs', 'nodejs'), ['bin', 'node']);

  const homeUser = path.posix.basename(homeDir.replace(/\/+$/, ''));
  if (homeUser && homeUser !== '/') {
    candidates.push(`/etc/profiles/per-user/${homeUser}/bin/node`);
  }

  for (const sysDir of WSL_SYSTEM_NODE_DIRS) {
    candidates.push(path.posix.join(sysDir, 'node'));
  }

  for (const candidate of candidates) {
    if (candidate.startsWith('/mnt/') || /\.exe$/i.test(candidate)) continue;
    try {
      const real = fs.realpathSync(candidate);
      if (real.startsWith('/mnt/') || /\.exe$/i.test(real)) continue;
      const st = fs.statSync(real);
      if (st.isFile()) {
        fs.accessSync(real, fs.constants.X_OK);
        return candidate;
      }
    } catch {
      // continue
    }
  }
  return null;
}

/**
 * 在 `wsl.exe -d <Distro> --cd ~ --` 后执行的 POSIX `sh -c` 启动脚本：
 * 主动切回 `$HOME`（兼容 `< 2.4` 旧版 WSL）、剥离 `/mnt/*` 宿主机 `PATH`，并跨 `.dsh-wsl-env.sh`、
 * `~/.dsh/runtime/bin`、`mise`、`nvm`、`fnm`、`volta`、`asdf`、NixOS profile 与 `/usr/bin` 查找共享 Linux Node，
 * 随后以 `exec` 原地替换进程（保持精确 PID，零 Shell 字符串插值）。
 */
export const WSL_SHARED_NODE_EXEC_SH = [
  'cd "$HOME" 2>/dev/null || true',
  'NODE_SPEC="$1"',
  'TARGET_SCRIPT="$2"',
  'shift 2',
  '[ -f "$HOME/.dsh-wsl-env.sh" ] && . "$HOME/.dsh-wsl-env.sh" >/dev/null 2>&1 || true',
  'NIX_USER="${USER:-${HOME##*/}}"',
  // 剥离所有 /mnt/* Windows PATH 条目，杜绝误调 Windows node.exe
  'CLEAN_PATH=""',
  'OLD_IFS="$IFS"; IFS=":"',
  'for p in $PATH; do',
  '  case "$p" in /mnt/*|"") ;; *) CLEAN_PATH="${CLEAN_PATH:+$CLEAN_PATH:}$p" ;; esac',
  'done',
  'IFS="$OLD_IFS"',
  'EXTRA_PATH="$HOME/.dsh/runtime/bin:$HOME/.local/share/dsh/node/bin:$HOME/.local/share/dsh-wsl-sandbox/toolchains/node/bin:$HOME/.local/share/dsh-wsl-sandbox/toolchains/go/bin:$HOME/.local/share/mise/shims:$HOME/.local/bin:$HOME/.nvm/current/bin:$HOME/.local/share/fnm/aliases/default/bin:$HOME/.fnm/aliases/default/bin:$HOME/.volta/bin:$HOME/.asdf/shims:$HOME/.nix-profile/bin:/etc/profiles/per-user/$NIX_USER/bin:/run/current-system/sw/bin:/nix/var/nix/profiles/default/bin:/opt/dsh-toolchain/shims:/opt/dsh-toolchain/bin:/usr/local/bin:/usr/bin:/bin"',
  'export PATH="$EXTRA_PATH${CLEAN_PATH:+:$CLEAN_PATH}"',
  'is_valid_node() {',
  '  c="$1"',
  '  [ -n "$c" ] && [ -x "$c" ] || return 1',
  '  case "$c" in /mnt/*|*.exe|*.EXE) return 1 ;; esac',
  '  if command -v readlink >/dev/null 2>&1; then',
  '    rp="$(readlink -f "$c" 2>/dev/null || printf "%s" "$c")"',
  '    case "$rp" in /mnt/*|*.exe|*.EXE) return 1 ;; esac',
  '  fi',
  '  ver="$("$c" -v 2>/dev/null || true)"',
  '  maj="${ver#v}"; maj="${maj%%.*}"',
  '  case "$maj" in ""|*[!0-9]*) return 1 ;; esac',
  '  [ "$maj" -ge 20 ]',
  '}',
  'NODE_BIN=""',
  'if [ -n "$NODE_SPEC" ] && [ "$NODE_SPEC" != "auto" ] && [ "$NODE_SPEC" != "node" ]; then',
  '  NODE_BIN="$NODE_SPEC"',
  'else',
  '  for d in "$HOME/.dsh/runtime/bin" "$HOME/.local/share/dsh/node/bin" "$HOME/.local/share/dsh-wsl-sandbox/toolchains/node/bin" "$HOME/.local/share/mise/shims" "$HOME/.local/bin" "$HOME/.nvm/current/bin" "$HOME/.local/share/fnm/aliases/default/bin" "$HOME/.fnm/aliases/default/bin" "$HOME/.volta/bin" "$HOME/.asdf/shims" "$HOME/.nix-profile/bin" "/etc/profiles/per-user/$NIX_USER/bin" "/run/current-system/sw/bin"; do',
  '    if is_valid_node "$d/node"; then NODE_BIN="$d/node"; break; fi',
  '  done',
  '  if [ -z "$NODE_BIN" ] && [ -d "$HOME/.nvm/versions/node" ]; then',
  '    for d in $(ls -1d "$HOME"/.nvm/versions/node/v*/bin 2>/dev/null | sort -V -r 2>/dev/null || ls -1dr "$HOME"/.nvm/versions/node/v*/bin 2>/dev/null); do',
  '      if is_valid_node "$d/node"; then NODE_BIN="$d/node"; break; fi',
  '    done',
  '  fi',
  '  if [ -z "$NODE_BIN" ]; then',
  '    for d in $(ls -1d "$HOME"/.local/share/fnm/node-versions/v*/installation/bin "$HOME"/.fnm/node-versions/v*/installation/bin "$HOME"/.asdf/installs/nodejs/*/bin 2>/dev/null | sort -V -r 2>/dev/null || true); do',
  '      if is_valid_node "$d/node"; then NODE_BIN="$d/node"; break; fi',
  '    done',
  '  fi',
  '  if [ -z "$NODE_BIN" ]; then',
  '    OLD_IFS="$IFS"; IFS=":"',
  '    for d in $PATH; do',
  '      if is_valid_node "$d/node"; then NODE_BIN="$d/node"; break; fi',
  '    done',
  '    IFS="$OLD_IFS"',
  '  fi',
  'fi',
  'if [ -z "$NODE_BIN" ] || [ ! -x "$NODE_BIN" ]; then',
  '  echo "[dsh-wsl-sandbox] No Linux Node.js (>=20 / 22 / 24 LTS) found inside WSL. Run provision-wsl.sh --step node to install or link a shared Node runtime." >&2',
  '  exit 127',
  'fi',
  'unset NODE_OPTIONS',
  'exec "$NODE_BIN" "$TARGET_SCRIPT" "$@"',
].join('; ');

/**
 * Builds the `wsl.exe` argument vector to invoke a JS entrypoint inside WSL using the shared Linux Node runtime.
 */
export function buildWslNodeSpawnArgs(options   
                          
                             
                                   
                              
                                          
                             
                            
 )           {
  if (!isValidDistroName(options.distro)) {
    failSandbox('INVALID_SETUP', `Invalid WSL distribution name: ${String(options.distro)}`);
  }
  if (options.username !== undefined && options.username !== '' && !isValidLinuxUsername(options.username)) {
    failSandbox('INVALID_SETUP', `Invalid Linux username: ${String(options.username)}`);
  }
  const nodeSpec = validateWslNodeExecutable(options.nodeExecutable);
  const args           = ['-d', options.distro, '--cd', '~'];
  if (options.username) {
    args.push('-u', options.username);
  }
  const envPrefix           = [];
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
