import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
                          
                            
                       
                 
                          
  failSandbox,
  isValidDistroName,
  isValidLinuxUsername,
  isValidLogLevel,
                
                   
  parseIpv4Cidr,
                   
  validateDeviceNode,
  validateShareEntry,
  validateWslNodeExecutable,
  validateWorkspaceRoot,
} from '../../core/src/index.js';

                                        
                                                                                               
                                              
                                                                                                
                                                        
                                                                                            
                                            
                                                                                          
                                            
                                                   
                                                   
 

                                   
                            
                            
                                                
                          
                             
                                 
                              
                                                                                               
                                
                                                                                             
                                                  
                                    
                                                  
                                    
                                 
                             
                                
                                                                                        
                              
                                     
                                    
                                          
                                                                                       
                                                    
                                                                                                           
                              
                                           
 

                                       
       
                     
               
                     
              
                
                     
                  
                   
                          
                   
                          
                   
                     
                
                 
                
                         
                       
                             
                             
                 
   
  

                                                                                            

const VALID_TRANSPORT_MODES = new Set                                   (['wsl', 'local-linux']);
const VALID_ENV_PROFILES = new Set                    (['core', 'standard', 'universal']);
const VALID_SANDBOX_MODES = new Set             (['read-only', 'workspace-write']);
const VALID_APPROVAL_MODES = new Set                    (['balanced', 'strict', 'trust-workspace']);
const VALID_NETWORK_MODES = new Set             (['allowlist-proxy', 'offline']);
const VALID_CACHE_MODES = new Set           (['workspace-persistent', 'ephemeral-tmp']);

export function getDefaultConfigDir(dshHome         )         {
  const base = dshHome ?? process.env.DSH_HOME ?? path.join(os.homedir(), '.dsh');
  return path.join(base, 'dsh-wsl-sandbox');
}

export function getDefaultConfigPath(dshHome         )         {
  return path.join(getDefaultConfigDir(dshHome), 'config.json');
}

export function getDefaultBackupDir(dshHome         )         {
  return path.join(getDefaultConfigDir(dshHome), 'backups');
}

export function getDefaultLogDir(dshHome         )         {
  return path.join(getDefaultConfigDir(dshHome), 'logs');
}

/**
 * Restricts a plugin-owned private directory or file to owner-only access.
 * On POSIX uses `chmod 0700` / `0600`; on Windows NTFS removes inherited broad `Users`/`Everyone`
 * read/write ACLs via `icacls /inheritance:r` (NEVER called on `%USERPROFILE%` or WSL Settings paths).
 */
export function hardenPrivatePath(targetPath        , kind                                  )       {
  if (process.platform === 'win32') {
    const user = process.env.USERNAME;
    if (user && /^[A-Za-z0-9_.\- ]+$/.test(user)) {
      const perm = kind === 'dir' ? '(OI)(CI)F' : 'F';
      const args = [
        targetPath,
        '/inheritance:r',
        '/grant:r',
        `*S-1-5-18:${perm}`,
        `${user}:${perm}`,
      ];
      spawnSync('icacls.exe', args, { stdio: 'ignore', shell: false, windowsHide: true, timeout: 4000 });
    }
    if (kind === 'readonly-file') {
      spawnSync('attrib.exe', ['+R', targetPath], { stdio: 'ignore', shell: false, windowsHide: true, timeout: 3000 });
    }
    return;
  }

  try {
    const mode = kind === 'dir' ? 0o700 : kind === 'readonly-file' ? 0o400 : 0o600;
    fs.chmodSync(targetPath, mode);
  } catch {
    // Best-effort on virtual filesystems
  }
}

/**
 * Validates a user-selected backup directory.
 * Explicitly blocks drive roots, OS system directories, `%USERPROFILE%` / `$HOME` roots
 * (where WSL Settings & WSL Manager share `.wslconfig`), live plugin config directories,
 * and Windows WSL VHDX storage paths (`AppData\Local\Packages`, `AppData\Local\wsl`).
 */
export function validateBackupDirPath(rawDir                    )                     {
  if (rawDir === undefined) return undefined;
  let trimmed = rawDir.trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length >= 2) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'") && trimmed.length >= 2)
  ) {
    trimmed = trimmed.slice(1, -1).trim();
  }
  if (!trimmed) return undefined;
  if (trimmed.includes('\0')) {
    failSandbox('POLICY_BLOCK', 'Invalid backupDir containing NUL byte');
  }

  const slashNorm = trimmed.replace(/\\/g, '/').replace(/\/+$/, '');
  const lower = slashNorm.toLowerCase();

  // Reject drive roots, OS system directories, Windows user profile roots, and WSL VHDX folders
  if (
    /^[a-z]:?$/.test(lower) ||
    slashNorm === '' ||
    slashNorm === '/' ||
    /^[a-z]:\/(windows|program files|program files \(x86\)|programdata)(\/|$)/i.test(slashNorm) ||
    /^[a-z]:\/users\/[^/]+$/i.test(slashNorm) ||
    /^[a-z]:\/users\/[^/]+\/appdata\/local\/(packages|wsl)(\/|$)/i.test(slashNorm) ||
    /^\/(etc|proc|sys|dev|boot|bin|sbin|usr|lib|lib64|var|run|mnt)(\/|$)/i.test(slashNorm) ||
    /^\/home\/[^/]+$/i.test(slashNorm)
  ) {
    failSandbox(
      'POLICY_BLOCK',
      `Refusing to use drive root, user profile root (shared with WSL Settings/WSL Manager .wslconfig), OS system dir, or WSL VHDX storage as backupDir: ${trimmed}`,
    );
  }

  // Reject pointing backupDir directly at live plugin config root (`~/.dsh` or `~/.dsh/dsh-wsl-sandbox` or `~/.config/dsh-wsl-sandbox`)
  const homeNorm = os.homedir().replace(/\\/g, '/').replace(/\/+$/, '').toLowerCase();
  const cfgDirNorm = getDefaultConfigDir().replace(/\\/g, '/').replace(/\/+$/, '').toLowerCase();
  const dshRootNorm = path.dirname(cfgDirNorm);
  if (
    lower === homeNorm ||
    lower === dshRootNorm ||
    lower === cfgDirNorm ||
    lower === `${homeNorm}/.config/dsh-wsl-sandbox` ||
    lower === `${homeNorm}/.ssh` ||
    lower === `${homeNorm}/.gnupg`
  ) {
    failSandbox(
      'POLICY_BLOCK',
      `Refusing to place backups directly in live config root (${trimmed}); choose a dedicated backup subdirectory instead.`,
    );
  }

  return trimmed;
}

function inferDefaultLinuxUser()         {
  if (process.platform !== 'win32') {
    try {
      const u = os.userInfo().username;
      if (u && u !== 'root' && isValidLinuxUsername(u)) {
        return u;
      }
    } catch {
      // ignore
    }
  }
  return 'dev';
}

function resolveDefaultRunnerPath(isWin         , defaultUser        )         {
  const stagedPath = `/home/${defaultUser}/.local/share/dsh-wsl-sandbox/runner/dist/packages/wsl-runner/src/main.js`;
  if (isWin) return stagedPath;
  if (fs.existsSync(stagedPath)) return stagedPath;

  const localCandidates = [
    path.resolve(import.meta.dirname, '../../wsl-runner/src/main.js'),
    path.resolve(import.meta.dirname, '../../../dist/packages/wsl-runner/src/main.js'),
    path.resolve(import.meta.dirname, '../../wsl-runner/src/main.ts'),
  ];
  for (const candidate of localCandidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return stagedPath;
}

export function createDefaultConfig(overrides                            )                   {
  const isWin = process.platform === 'win32';
  const defaultUser = inferDefaultLinuxUser();
  const base                   = {
    revision: 'rev-1',
    enabled: true,
    transportMode: isWin ? 'wsl' : 'local-linux',
    // On Windows: defaults to modern Ubuntu-26.04 LTS until installer/discovery binds the user's real distro;
    // on native Linux devbox: uses WSL_DISTRO_NAME if inside WSL or 'local-linux'.
    distro: isWin ? 'Ubuntu-26.04' : (process.env.WSL_DISTRO_NAME || 'local-linux'),
    workspaceRoot: `/home/${defaultUser}/workspace`,
    runnerPath: resolveDefaultRunnerPath(isWin, defaultUser),
    wslNodePath: 'auto',
    environmentProfile: 'standard',
    sandboxMode: 'workspace-write',
    approvalPolicyMode: 'balanced',
    networkMode: 'allowlist-proxy',
    upstreamProxy: '',
    mirrorCn: false,
    cacheMode: 'workspace-persistent',
    logLevel: 'info',
    approvalTimeoutMs: 60_000,
    enablePwshGuard: true,
    enablePromptInjection: true,
    unmaskedEnvWorkspaces: [],
    backupDir: getDefaultBackupDir(),
    advanced: {
      shares: [],
      deviceNodes: [],
      localLabCidrs: [],
      localLabPorts: [],
      customAllowedDomains: [],
    },
  };
  return validateFullConfig({
    ...base,
    ...overrides,
    advanced: {
      ...base.advanced,
      ...(overrides?.advanced ?? {}),
    },
  });
}

function validateUpstreamProxy(value        )         {
  const trimmed = value.trim();
  if (!trimmed) return '';
  let parsed     ;
  try {
    parsed = new URL(trimmed);
  } catch {
    failSandbox('INVALID_SETUP', `Invalid upstreamProxy URL: ${trimmed}`);
  }
  if (!['http:', 'https:', 'socks5:', 'socks5h:'].includes(parsed.protocol)) {
    failSandbox('INVALID_SETUP', `Unsupported upstreamProxy protocol: ${parsed.protocol}`);
  }
  return trimmed;
}

function validateDomain(domain        )         {
  const clean = domain.trim().toLowerCase();
  if (!/^(?:\*\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(clean)) {
    failSandbox('POLICY_BLOCK', `Invalid domain allowlist entry: ${domain}`);
  }
  return clean;
}

export function validateFullConfig(raw                  )                   {
  if (!isValidDistroName(raw.distro)) {
    failSandbox('INVALID_SETUP', `Invalid WSL distro name: ${raw.distro}`);
  }
  if (raw.username !== undefined && raw.username !== '' && !isValidLinuxUsername(raw.username)) {
    failSandbox('INVALID_SETUP', `Invalid Linux username: ${raw.username}`);
  }
  validateWorkspaceRoot(raw.workspaceRoot, raw.username);

  if (!VALID_TRANSPORT_MODES.has(raw.transportMode)) {
    failSandbox('INVALID_SETUP', `Invalid transportMode: ${String(raw.transportMode)}`);
  }
  const runnerPath = typeof raw.runnerPath === 'string' ? raw.runnerPath.trim() : '';
  if (!runnerPath || runnerPath.includes('\0') || /[\r\n]/.test(runnerPath)) {
    failSandbox('INVALID_SETUP', `Invalid runnerPath: ${String(raw.runnerPath)}`);
  }
  if (raw.transportMode === 'wsl') {
    if (!runnerPath.startsWith('/') || runnerPath === '/mnt' || runnerPath.startsWith('/mnt/') || /\.exe$/i.test(runnerPath)) {
      failSandbox(
        'POLICY_BLOCK',
        `WSL runnerPath must be a native Linux ext4 path (starting with '/', not '/mnt/*' or '.exe'): ${runnerPath}`,
      );
    }
  }
  const environmentProfile                     = raw.environmentProfile ?? 'standard';
  if (!VALID_ENV_PROFILES.has(environmentProfile)) {
    failSandbox('INVALID_SETUP', `Invalid environmentProfile: ${String(environmentProfile)}`);
  }
  if (!VALID_SANDBOX_MODES.has(raw.sandboxMode)) {
    failSandbox('INVALID_SETUP', `Invalid sandboxMode: ${String(raw.sandboxMode)}`);
  }
  if (!VALID_APPROVAL_MODES.has(raw.approvalPolicyMode)) {
    failSandbox('INVALID_SETUP', `Invalid approvalPolicyMode: ${String(raw.approvalPolicyMode)}`);
  }
  if (!VALID_NETWORK_MODES.has(raw.networkMode)) {
    failSandbox('INVALID_SETUP', `Invalid networkMode: ${String(raw.networkMode)}`);
  }
  if (!VALID_CACHE_MODES.has(raw.cacheMode)) {
    failSandbox('INVALID_SETUP', `Invalid cacheMode: ${String(raw.cacheMode)}`);
  }
  const logLevel           = raw.logLevel ?? 'info';
  if (!isValidLogLevel(logLevel)) {
    failSandbox('INVALID_SETUP', `Invalid logLevel: ${String(logLevel)}`);
  }
  if (!Number.isSafeInteger(raw.approvalTimeoutMs) || raw.approvalTimeoutMs < 1000 || raw.approvalTimeoutMs > 600_000) {
    failSandbox('INVALID_SETUP', `Invalid approvalTimeoutMs: ${raw.approvalTimeoutMs}`);
  }

  const wslNodePath = validateWslNodeExecutable(raw.wslNodePath);
  const upstreamProxy = validateUpstreamProxy(raw.upstreamProxy ?? '');
  const shares = (raw.advanced?.shares ?? []).map(validateShareEntry);
  const deviceNodes = (raw.advanced?.deviceNodes ?? []).map(validateDeviceNode);

  const localLabCidrs = (raw.advanced?.localLabCidrs ?? []).map((c) => {
    const trimmed = c.trim();
    if (!parseIpv4Cidr(trimmed)) {
      failSandbox('POLICY_BLOCK', `Invalid localLabCidr: ${c}`);
    }
    return trimmed;
  });

  const localLabPorts = (raw.advanced?.localLabPorts ?? []).map((p) => {
    if (!Number.isInteger(p) || p < 1 || p > 65535) {
      failSandbox('POLICY_BLOCK', `Invalid localLabPort: ${p}`);
    }
    return p;
  });

  const customAllowedDomains = (raw.advanced?.customAllowedDomains ?? []).map(validateDomain);
  const backupDir = validateBackupDirPath(raw.backupDir) ?? getDefaultBackupDir();

  return {
    ...raw,
    runnerPath,
    wslNodePath,
    environmentProfile,
    logLevel,
    upstreamProxy,
    backupDir,
    unmaskedEnvWorkspaces: [...new Set(raw.unmaskedEnvWorkspaces ?? [])],
    advanced: {
      shares,
      deviceNodes,
      localLabCidrs,
      localLabPorts,
      customAllowedDomains,
    },
  };
}

function nextRevision(current        )         {
  const m = current.match(/^rev-(\d+)$/);
  const n = m ? Number(m[1]) + 1 : Date.now();
  return `rev-${n}`;
}

/**
 * Human-only persistent configuration store (`0600` on POSIX / owner-only ACL on Windows NTFS).
 * Model tools NEVER receive write access to this store; only authenticated host HTTP routes
 * or host-side initialization may mutate it.
 */
export class ConfigStore {
                   filePath        ;
                   persistToDisk         ;
          config                  ;
                   listeners = new Set                      ();

  constructor(options    
                      
                            
                                        
   ) {
    this.filePath = options?.filePath ?? getDefaultConfigPath();
    this.persistToDisk = options?.persistToDisk ?? true;
    this.config = this.loadOrInit(options?.initial);
  }

  getConfigFilePath()         {
    return this.filePath;
  }

  getConfigDir()         {
    return path.dirname(this.filePath);
  }

  isPersistent()          {
    return this.persistToDisk;
  }

          loadOrInit(initial                            )                   {
    if (this.persistToDisk && fs.existsSync(this.filePath)) {
      try {
        const parsed = JSON.parse(fs.readFileSync(this.filePath, 'utf8'))                             ;
        const mergedAdvanced =
          initial?.advanced || parsed.advanced
            ? {
                shares: parsed.advanced?.shares ?? initial?.advanced?.shares ?? [],
                deviceNodes: parsed.advanced?.deviceNodes ?? initial?.advanced?.deviceNodes ?? [],
                localLabCidrs: parsed.advanced?.localLabCidrs ?? initial?.advanced?.localLabCidrs ?? [],
                localLabPorts: parsed.advanced?.localLabPorts ?? initial?.advanced?.localLabPorts ?? [],
                customAllowedDomains:
                  parsed.advanced?.customAllowedDomains ?? initial?.advanced?.customAllowedDomains ?? [],
              }
            : undefined;
        return createDefaultConfig({
          ...initial,
          ...parsed,
          ...(mergedAdvanced ? { advanced: mergedAdvanced } : {}),
        });
      } catch {
        // Fall through to defaults if corrupted
      }
    }
    const defaults = createDefaultConfig(initial);
    if (this.persistToDisk) {
      this.saveAtomic(defaults);
    }
    return defaults;
  }

          saveAtomic(cfg                  )       {
    const dir = path.dirname(this.filePath);
    const dirExisted = fs.existsSync(dir);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    if (!dirExisted) {
      hardenPrivatePath(dir, 'dir');
    }
    const tmpPath = `${this.filePath}.tmp.${process.pid}.${randomBytes(4).toString('hex')}`;
    try {
      fs.writeFileSync(tmpPath, JSON.stringify(cfg, null, 2) + '\n', { mode: 0o600 });
      let lastErr         ;
      for (let attempt = 0; attempt < 3; attempt++) {
        try {
          fs.renameSync(tmpPath, this.filePath);
          lastErr = undefined;
          break;
        } catch (err) {
          lastErr = err;
          const code = (err                         ).code;
          if (code !== 'EPERM' && code !== 'EBUSY') throw err;
        }
      }
      if (lastErr) throw lastErr;
      hardenPrivatePath(this.filePath, 'file');
    } finally {
      if (fs.existsSync(tmpPath)) {
        try { fs.rmSync(tmpPath, { force: true }); } catch { /* ignore */ }
      }
    }
  }

  get()                   {
    return this.config;
  }

  /**
   * 从磁盘重新读取并校验 `config.json`（用于同步外部安装向导落盘的最新配置，无变更时不触发递增）。
   */
  reloadFromDisk()                   {
    if (!this.persistToDisk || !fs.existsSync(this.filePath)) {
      return this.config;
    }
    const prev = this.config;
    try {
      const parsed = JSON.parse(fs.readFileSync(this.filePath, 'utf8'))                             ;
      const mergedAdvanced =
        parsed.advanced
          ? {
              shares: parsed.advanced.shares ?? prev.advanced.shares,
              deviceNodes: parsed.advanced.deviceNodes ?? prev.advanced.deviceNodes,
              localLabCidrs: parsed.advanced.localLabCidrs ?? prev.advanced.localLabCidrs,
              localLabPorts: parsed.advanced.localLabPorts ?? prev.advanced.localLabPorts,
              customAllowedDomains: parsed.advanced.customAllowedDomains ?? prev.advanced.customAllowedDomains,
            }
          : prev.advanced;
      const loaded = createDefaultConfig({
        ...prev,
        ...parsed,
        advanced: mergedAdvanced,
      });
      const stripRev = (c                  ) => ({ ...c, revision: '' });
      if (JSON.stringify(stripRev(loaded)) === JSON.stringify(stripRev(prev))) {
        return this.config;
      }
      const next = validateFullConfig({
        ...loaded,
        revision: nextRevision(prev.revision),
      });
      this.config = next;
      for (const listener of this.listeners) {
        listener(next, prev);
      }
      return next;
    } catch {
      return this.config;
    }
  }

  onChange(listener                      )             {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

          commit(nextUnrev                  )                   {
    const prev = this.config;
    const next = validateFullConfig({
      ...nextUnrev,
      revision: nextRevision(prev.revision),
    });
    this.config = next;
    if (this.persistToDisk) {
      this.saveAtomic(next);
    }
    for (const listener of this.listeners) {
      listener(next, prev);
    }
    return next;
  }

  /** Update basic settings only. Explicitly forbids smuggling `/mnt` full-drive mounts here (Q8). */
  updateBasic(patch                                            )                   {
    if ('mountFullWindowsDrives' in patch || 'mntMount' in patch || 'advanced' in patch) {
      failSandbox(
        'POLICY_BLOCK',
        'Full Windows drive (/mnt) mounting is disabled in basic config; use Advanced single-directory /shares/<alias> instead.',
      );
    }
    return this.commit({
      ...this.config,
      enabled: patch.enabled ?? this.config.enabled,
      transportMode: patch.transportMode ?? this.config.transportMode,
      distro: patch.distro ?? this.config.distro,
      username: patch.username !== undefined ? patch.username : this.config.username,
      workspaceRoot: patch.workspaceRoot ?? this.config.workspaceRoot,
      runnerPath: patch.runnerPath ?? this.config.runnerPath,
      wslNodePath: patch.wslNodePath !== undefined ? patch.wslNodePath : this.config.wslNodePath,
      environmentProfile: patch.environmentProfile ?? this.config.environmentProfile,
      sandboxMode: patch.sandboxMode ?? this.config.sandboxMode,
      approvalPolicyMode: patch.approvalPolicyMode ?? this.config.approvalPolicyMode,
      networkMode: patch.networkMode ?? this.config.networkMode,
      upstreamProxy: patch.upstreamProxy !== undefined ? patch.upstreamProxy : this.config.upstreamProxy,
      mirrorCn: patch.mirrorCn ?? this.config.mirrorCn,
      cacheMode: patch.cacheMode ?? this.config.cacheMode,
      logLevel: patch.logLevel ?? this.config.logLevel,
      approvalTimeoutMs: patch.approvalTimeoutMs ?? this.config.approvalTimeoutMs,
      enablePwshGuard: patch.enablePwshGuard ?? this.config.enablePwshGuard,
      enablePromptInjection: patch.enablePromptInjection ?? this.config.enablePromptInjection,
      unmaskedEnvWorkspaces: patch.unmaskedEnvWorkspaces ?? this.config.unmaskedEnvWorkspaces,
      backupDir: patch.backupDir !== undefined ? patch.backupDir : this.config.backupDir,
    });
  }

  /** Advanced: authorize a single directory mounted under `/shares/<alias>` (default `ro`). */
  addShare(share                 )                   {
    const validated = validateShareEntry({ ...share, mode: share.mode ?? 'ro' });
    const filtered = this.config.advanced.shares.filter(
      (s) => s.id !== validated.id && s.alias !== validated.alias,
    );
    return this.commit({
      ...this.config,
      advanced: {
        ...this.config.advanced,
        shares: [...filtered, validated],
      },
    });
  }

  /** Advanced: immediately revoke a single-directory share (triggers generation++ & kill). */
  removeShare(shareId        )                   {
    const filtered = this.config.advanced.shares.filter((s) => s.id !== shareId);
    return this.commit({
      ...this.config,
      advanced: {
        ...this.config.advanced,
        shares: filtered,
      },
    });
  }

  /** Advanced: update explicit single-device passthrough whitelist (Q13). */
  setDeviceNodes(nodes                                 )                   {
    const validated = nodes.map(validateDeviceNode);
    return this.commit({
      ...this.config,
      advanced: {
        ...this.config.advanced,
        deviceNodes: validated,
      },
    });
  }

  /** Advanced: update UDS proxy local lab CIDRs/ports and custom domain allowlist (Q16). */
  updateAdvancedNetwork(patch   
                                      
                                      
                                             
   )                   {
    return this.commit({
      ...this.config,
      advanced: {
        ...this.config.advanced,
        localLabCidrs: patch.localLabCidrs ?? this.config.advanced.localLabCidrs,
        localLabPorts: patch.localLabPorts ?? this.config.advanced.localLabPorts,
        customAllowedDomains: patch.customAllowedDomains ?? this.config.advanced.customAllowedDomains,
      },
    });
  }

  isWorkspaceEnvMasked(workspaceRoot        )          {
    return !this.config.unmaskedEnvWorkspaces.includes(workspaceRoot);
  }
}
