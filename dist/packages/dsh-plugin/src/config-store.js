import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
                          
                            
                       
                 
  failSandbox,
  isValidIdentifier,
                   
  parseIpv4Cidr,
                   
  validateDeviceNode,
  validateShareEntry,
  validateWorkspaceRoot,
} from '../../core/src/index.js';

                                        
                                                                                               
                                              
                                                                                                
                                                        
                                                                                            
                                            
                                                                                          
                                            
                                                   
                                                   
 

                                   
                            
                            
                                                
                          
                             
                                 
                              
                                    
                                                  
                                    
                                 
                             
                                
                                     
                                    
                                          
                                                                                       
                                                    
                                                                                                           
                              
                                           
 

                                       
       
                     
               
                     
              
                
                     
                  
                   
                          
                   
                     
                
                 
                         
                       
                             
                             
                 
   
  

                                                                                            

const VALID_TRANSPORT_MODES = new Set                                   (['wsl', 'local-linux']);
const VALID_SANDBOX_MODES = new Set             (['read-only', 'workspace-write']);
const VALID_APPROVAL_MODES = new Set                    (['balanced', 'strict', 'trust-workspace']);
const VALID_NETWORK_MODES = new Set             (['allowlist-proxy', 'offline']);
const VALID_CACHE_MODES = new Set           (['workspace-persistent', 'ephemeral-tmp']);

export function getDefaultConfigPath(dshHome         )         {
  const base = dshHome ?? process.env.DSH_HOME ?? path.join(os.homedir(), '.dsh');
  return path.join(base, 'dsh-wsl-sandbox', 'config.json');
}

export function getDefaultBackupDir(dshHome         )         {
  const base = dshHome ?? process.env.DSH_HOME ?? path.join(os.homedir(), '.dsh');
  return path.join(base, 'dsh-wsl-sandbox', 'backups');
}

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
  if (/^[A-Za-z]:\\?$/.test(trimmed) || trimmed === '/' || /^([A-Za-z]:\\Windows(\\|$)|\/(etc|proc|sys|dev|boot)(\/|$))/i.test(trimmed)) {
    failSandbox('POLICY_BLOCK', `Refusing to use drive root or OS system directory as backupDir: ${trimmed}`);
  }
  return trimmed;
}

export function createDefaultConfig(overrides                            )                   {
  const isWin = process.platform === 'win32';
  const base                   = {
    revision: 'rev-1',
    enabled: true,
    transportMode: isWin ? 'wsl' : 'local-linux',
    distro: 'Ubuntu-24.04',
    workspaceRoot: '/home/dev/workspace',
    runnerPath: '/opt/dsh-wsl-sandbox/dist/wsl-runner/src/main.js',
    sandboxMode: 'workspace-write',
    approvalPolicyMode: 'balanced',
    networkMode: 'allowlist-proxy',
    upstreamProxy: '',
    mirrorCn: false,
    cacheMode: 'workspace-persistent',
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
  if (!isValidIdentifier(raw.distro)) {
    failSandbox('INVALID_SETUP', `Invalid WSL distro name: ${raw.distro}`);
  }
  if (raw.username !== undefined && raw.username !== '' && !/^[a-z_][a-z0-9_-]{0,31}$/.test(raw.username)) {
    failSandbox('INVALID_SETUP', `Invalid Linux username: ${raw.username}`);
  }
  validateWorkspaceRoot(raw.workspaceRoot, raw.username);

  if (!VALID_TRANSPORT_MODES.has(raw.transportMode)) {
    failSandbox('INVALID_SETUP', `Invalid transportMode: ${String(raw.transportMode)}`);
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
  if (!Number.isSafeInteger(raw.approvalTimeoutMs) || raw.approvalTimeoutMs < 1000 || raw.approvalTimeoutMs > 600_000) {
    failSandbox('INVALID_SETUP', `Invalid approvalTimeoutMs: ${raw.approvalTimeoutMs}`);
  }

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
 * Human-only persistent configuration store (`0600` file permissions).
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

          loadOrInit(initial                            )                   {
    if (this.persistToDisk && fs.existsSync(this.filePath)) {
      try {
        const parsed = JSON.parse(fs.readFileSync(this.filePath, 'utf8'))                             ;
        return createDefaultConfig({ ...parsed, ...initial });
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
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const tmpPath = `${this.filePath}.tmp.${process.pid}`;
    fs.writeFileSync(tmpPath, JSON.stringify(cfg, null, 2) + '\n', { mode: 0o600 });
    fs.renameSync(tmpPath, this.filePath);
    try {
      fs.chmodSync(this.filePath, 0o600);
    } catch {
      // Best-effort on Windows NTFS
    }
  }

  get()                   {
    return this.config;
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
      sandboxMode: patch.sandboxMode ?? this.config.sandboxMode,
      approvalPolicyMode: patch.approvalPolicyMode ?? this.config.approvalPolicyMode,
      networkMode: patch.networkMode ?? this.config.networkMode,
      upstreamProxy: patch.upstreamProxy !== undefined ? patch.upstreamProxy : this.config.upstreamProxy,
      mirrorCn: patch.mirrorCn ?? this.config.mirrorCn,
      cacheMode: patch.cacheMode ?? this.config.cacheMode,
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
