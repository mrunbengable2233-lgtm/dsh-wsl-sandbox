export const STRIPPED_ENV_VARS = new Set        ([
  // WSL interop & host display/audio channels
  'WSL_INTEROP',
  'WSLENV',
  'DISPLAY',
  'WAYLAND_DISPLAY',
  'PULSE_SERVER',
  'PULSE_COOKIE',
  'XAUTHORITY',
  'DBUS_SESSION_BUS_ADDRESS',
  'DBUS_SYSTEM_BUS_ADDRESS',
  // Credential / agent sockets
  'SSH_AUTH_SOCK',
  'SSH_AGENT_PID',
  'GPG_AGENT_INFO',
  // Dynamic linker / shell / runtime injection vectors (CVE-2026-12537 class)
  'LD_PRELOAD',
  'LD_LIBRARY_PATH',
  'LD_AUDIT',
  'LD_DEBUG',
  'BASH_ENV',
  'ENV',
  'PROMPT_COMMAND',
  'CDPATH',
  'GLOBIGNORE',
  'SHELLOPTS',
  'BASHOPTS',
  'NODE_OPTIONS',
  'NODE_EXTRA_CA_CERTS',
  'PYTHONSTARTUP',
  'PYTHONPATH',
  'PYTHONHOME',
  'GIT_SSH_COMMAND',
  'GIT_SSH',
  'GIT_EXEC_PATH',
  'GIT_CONFIG_PARAMETERS',
  'GIT_CONFIG_COUNT',
  'PERL5OPT',
  'PERL5LIB',
  'RUBYOPT',
  'RUBYLIB',
  'JAVA_TOOL_OPTIONS',
  'RUSTC_WRAPPER',
]);

const CREDENTIAL_NAME_RE = /(?:API_KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_KEY|ACCESS_KEY|CREDENTIAL|AUTH)/i;

export const DEFAULT_SANDBOX_PATH = [
  '/opt/dsh-toolchain/shims',
  '/opt/dsh-toolchain/bin',
  '/usr/local/go/bin',
  '/usr/local/sbin',
  '/usr/local/bin',
  '/usr/sbin',
  '/usr/bin',
  '/sbin',
  '/bin',
].join(':');

/**
 * Builds a clean POSIX `PATH` inside the `bwrap` sandbox that includes user-installed prebuilt
 * toolchains (`~/.dsh/runtime/bin`, `mise` shims, `uv`/`~/.local/bin`, `cargo`, `bun`, `/usr/local/go/bin`)
 * while strictly excluding `/mnt/*` Windows host directories.
 */
export function buildDefaultSandboxPath(homeDir         )         {
  const cleanHome = homeDir?.trim().replace(/\/+$/, '');
  if (!cleanHome || !cleanHome.startsWith('/') || cleanHome.startsWith('/mnt/')) {
    return DEFAULT_SANDBOX_PATH;
  }
  return [
    `${cleanHome}/.dsh/runtime/bin`,
    `${cleanHome}/.local/share/dsh/node/bin`,
    `${cleanHome}/.local/share/mise/shims`,
    `${cleanHome}/.local/bin`,
    `${cleanHome}/.nvm/current/bin`,
    `${cleanHome}/.volta/bin`,
    `${cleanHome}/.cargo/bin`,
    `${cleanHome}/.bun/bin`,
    DEFAULT_SANDBOX_PATH,
  ].join(':');
}

                                     
                                                                  
                                                                   
                                                     
                           
                                           
                                 
                             
                              
 

export function sanitizeSandboxEnv(options                    )                         {
  const out                         = {};
  const fallbackPath = buildDefaultSandboxPath(options.homeDir);

  const safePath = options.pathEntries && options.pathEntries.length > 0
    ? options.pathEntries.filter((p) => p.startsWith('/') && !p.startsWith('/mnt/')).join(':')
    : fallbackPath;

  out.PATH = safePath || fallbackPath;
  out.HOME = options.homeDir;
  out.TMPDIR = '/tmp';
  out.TEMP = '/tmp';
  out.TMP = '/tmp';
  out.LANG = 'C.UTF-8';
  out.LC_ALL = 'C.UTF-8';
  out.TERM = 'xterm-256color';
  out.TZ = options.baseEnv?.TZ || 'UTC';
  out.UV_NO_PROGRESS = '1';
  out.COREPACK_ENABLE_DOWNLOAD_PROMPT = '0';

  // Redirect writable toolchain caches away from read-only real $HOME while keeping read-only RUSTUP_HOME
  const cacheBase = options.cacheRootDir || '/tmp/.dsh-cache';
  out.XDG_CACHE_HOME = cacheBase;
  out.UV_CACHE_DIR = `${cacheBase}/uv`;
  out.PIP_CACHE_DIR = `${cacheBase}/pip`;
  out.npm_config_cache = `${cacheBase}/npm`;
  out.PNPM_HOME = `${cacheBase}/pnpm`;
  out.GOCACHE = `${cacheBase}/go-build`;
  out.GOMODCACHE = `${cacheBase}/go-mod`;
  out.CARGO_HOME = `${cacheBase}/cargo`;
  if (options.homeDir.startsWith('/') && !options.homeDir.startsWith('/mnt/')) {
    out.RUSTUP_HOME = `${options.homeDir.replace(/\/+$/, '')}/.rustup`;
  }

  if (options.mirrorCn) {
    out.npm_config_registry = 'https://registry.npmmirror.com';
    out.PIP_INDEX_URL = 'https://pypi.tuna.tsinghua.edu.cn/simple';
    out.UV_INDEX_URL = 'https://pypi.tuna.tsinghua.edu.cn/simple';
    out.GOPROXY = 'https://goproxy.cn,direct';
    out.RUSTUP_DIST_SERVER = 'https://rsproxy.cn';
    out.RUSTUP_UPDATE_ROOT = 'https://rsproxy.cn/rustup';
  }

  // Only allow trusted caller extraEnv entries that are not in blocklist, DSH_*, or credential-shaped
  if (options.extraEnv) {
    for (const [key, val] of Object.entries(options.extraEnv)) {
      if (val === undefined) {
        delete out[key];
        continue;
      }
      if (key.startsWith('DSH_')) continue;
      if (STRIPPED_ENV_VARS.has(key)) continue;
      if (CREDENTIAL_NAME_RE.test(key)) continue;
      if (val.includes('\0')) continue;
      out[key] = val;
    }
  }

  // Controlled sandbox proxy env (only when UDS proxy bridge is active)
  if (options.proxyUrl) {
    out.HTTP_PROXY = options.proxyUrl;
    out.HTTPS_PROXY = options.proxyUrl;
    out.http_proxy = options.proxyUrl;
    out.https_proxy = options.proxyUrl;
    out.NO_PROXY = '';
    out.no_proxy = '';
  } else {
    delete out.HTTP_PROXY;
    delete out.HTTPS_PROXY;
    delete out.ALL_PROXY;
    delete out.http_proxy;
    delete out.https_proxy;
    delete out.all_proxy;
  }

  // Harness-owned DSH_* variables merge last so ambient/extra values can never displace them
  if (options.dshEnv) {
    for (const [key, val] of Object.entries(options.dshEnv)) {
      if (key.startsWith('DSH_') && typeof val === 'string' && !val.includes('\0')) {
        out[key] = val;
      }
    }
  }

  return out;
}
