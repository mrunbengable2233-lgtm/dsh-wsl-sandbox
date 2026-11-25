import { posix } from 'node:path';
import { failSandbox } from './errors.js';

                                                          
                                                        
                                                                 
                                                                           
                                             

                                  
                      
                         
                                   
                             
                             
 

                                       
                        
                          
 

                                 
                             
                                   
                              
                                
                       
                            
                                    
                                 
                       
                                
                            
                            
                                 
                                           
                                 
                                           
                                             
                                                         
                                                               
 

                                 
                             
                          
                         
                                
                       
                            
                           
                                 
                       
                                
                            
                              
                            
                              
                                           
                                          
                                            
                                                        
                                                              
 

const VALID_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;
const VALID_SHARE_ALIAS_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
const ALLOWED_DEVICE_RE = /^\/dev\/(ttyUSB\d+|ttyACM\d+|ttyS\d+|bus\/usb\/\d{3}\/\d{3})$/;

const INTERNAL_DISTRO_PATTERNS = [
  /^docker-desktop$/i,
  /^docker-desktop-data$/i,
  /^rancher-desktop/i,
  /^podman-machine/i,
];

const FORBIDDEN_WORKSPACE_ROOTS = new Set([
  '/',
  '/bin',
  '/boot',
  '/dev',
  '/etc',
  '/home',
  '/lib',
  '/lib64',
  '/mnt',
  '/mnt/wsl',
  '/mnt/wslg',
  '/mnt/wslg/distro',
  '/opt',
  '/proc',
  '/root',
  '/run',
  '/run/WSL',
  '/sbin',
  '/srv',
  '/sys',
  '/tmp',
  '/usr',
  '/var',
]);

const FORBIDDEN_WORKSPACE_PREFIXES = [
  '/dev/',
  '/etc/',
  '/mnt/',
  '/proc/',
  '/run/',
  '/sys/',
];

export function isValidIdentifier(value         )                  {
  return typeof value === 'string' && VALID_ID_RE.test(value);
}

export function isSafeAbsoluteLinuxPath(value         )                  {
  if (typeof value !== 'string' || value.length === 0 || value.length > 4096) {
    return false;
  }
  if (value.includes('\0') || value.startsWith('//') || !value.startsWith('/')) {
    return false;
  }
  if (value.length > 1 && value.endsWith('/')) {
    return false;
  }
  return posix.normalize(value) === value;
}

export function isPathInside(root        , candidate        )          {
  const normRoot = posix.normalize(root);
  const normCand = posix.normalize(candidate);
  if (normRoot === '/') return normCand.startsWith('/');
  return normCand === normRoot || normCand.startsWith(normRoot + '/');
}

export function validateWorkspaceRoot(linuxPath        , username         )         {
  if (!isSafeAbsoluteLinuxPath(linuxPath)) {
    failSandbox('POLICY_BLOCK', `Invalid Linux workspace path: ${linuxPath}`);
  }
  if (FORBIDDEN_WORKSPACE_ROOTS.has(linuxPath)) {
    failSandbox('POLICY_BLOCK', `Forbidden system or root directory as workspaceRoot: ${linuxPath}`);
  }
  for (const prefix of FORBIDDEN_WORKSPACE_PREFIXES) {
    if (linuxPath.startsWith(prefix)) {
      failSandbox('POLICY_BLOCK', `Workspace root cannot live under protected mount ${prefix}: ${linuxPath}`);
    }
  }
  if (username && (linuxPath === `/home/${username}` || linuxPath === '/root')) {
    failSandbox('POLICY_BLOCK', `Entire user home directory cannot be mounted as workspaceRoot: ${linuxPath}`);
  }
  return linuxPath;
}

const FORBIDDEN_WINDOWS_MOUNT_PATTERNS = [
  /^\/mnt\/[a-z]$/i,
  /^\/mnt\/[a-z]\/windows(?:\/|$)/i,
  /^\/mnt\/[a-z]\/program files(?: \(x86\))?(?:\/|$)/i,
  /^\/mnt\/[a-z]\/programdata(?:\/|$)/i,
  /^\/mnt\/[a-z]\/system volume information(?:\/|$)/i,
  /^\/mnt\/[a-z]\/\$recycle\.bin(?:\/|$)/i,
  /^\/mnt\/[a-z]\/recovery(?:\/|$)/i,
  /^\/mnt\/[a-z]\/users\/[^/]+$/i,
];

/**
 * Converts a Windows folder path (e.g. `D:\Datasets\ESP32` or `"C:/Users/Alice/Downloads/spec"`)
 * or a Linux path into a canonical normalized POSIX path without trailing slash.
 * Rejects UNC paths and bare drive roots (`C:\`, `D:\`) at validation time.
 */
export function normalizeSharePathInput(rawInput        )         {
  if (typeof rawInput !== 'string') {
    failSandbox('POLICY_BLOCK', 'Share path must be a string');
  }
  let trimmed = rawInput.trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length >= 2) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'") && trimmed.length >= 2)
  ) {
    trimmed = trimmed.slice(1, -1).trim();
  }
  if (!trimmed || trimmed.includes('\0')) {
    failSandbox('POLICY_BLOCK', 'Share path cannot be empty or contain NUL bytes');
  }
  if (trimmed.startsWith('\\\\')) {
    failSandbox(
      'POLICY_BLOCK',
      `Windows UNC share paths are not supported directly (${trimmed}); use a local drive subfolder (e.g. D:\\Folder) or native Linux path.`,
    );
  }

  const winDriveMatch = trimmed.match(/^([A-Za-z]):(?:[\\/](.*))?$/);
  if (winDriveMatch) {
    const drive = winDriveMatch[1] .toLowerCase();
    const rest = (winDriveMatch[2] ?? '').replace(/\\/g, '/').replace(/\/+$/, '');
    if (!rest) {
      failSandbox(
        'POLICY_BLOCK',
        `Refusing to mount entire Windows drive root (${drive.toUpperCase()}:\\ -> /mnt/${drive}); specify a concrete subdirectory such as ${drive.toUpperCase()}:\\Projects\\MyFolder`,
      );
    }
    const candidate = posix.normalize(`/mnt/${drive}/${rest}`);
    const trimmedCandidate =
      candidate.length > 1 && candidate.endsWith('/') ? candidate.slice(0, -1) : candidate;
    if (!trimmedCandidate.startsWith(`/mnt/${drive}/`)) {
      failSandbox('POLICY_BLOCK', `Share path traversal outside /mnt/${drive}/ is forbidden: ${rawInput}`);
    }
    return trimmedCandidate;
  }

  const slashTrimmed = trimmed.length > 1 && trimmed.endsWith('/') ? trimmed.replace(/\/+$/, '') : trimmed;
  return slashTrimmed || '/';
}

/**
 * Derives a safe `/shares/<alias>` identifier from a folder basename when user leaves alias blank.
 */
export function deriveShareAlias(normalizedLinuxPath        )         {
  const base = posix.basename(normalizedLinuxPath);
  const cleaned = base
    .replace(/[^A-Za-z0-9_.-]+/g, '-')
    .replace(/^[^A-Za-z0-9]+/, '')
    .replace(/-+/g, '-')
    .slice(0, 48);
  return cleaned && VALID_SHARE_ALIAS_RE.test(cleaned) ? cleaned : `share-${Date.now().toString(36).slice(-4)}`;
}

export function validateShareEntry(share                 )                  {
  const normalizedSource = normalizeSharePathInput(share.sourceLinuxPath);
  const effectiveId =
    typeof share.id === 'string' && share.id.trim() === ''
      ? `sh-${Date.now().toString(36)}`
      : share.id;
  const effectiveAlias =
    typeof share.alias === 'string' && share.alias.trim() === ''
      ? deriveShareAlias(normalizedSource)
      : share.alias;

  if (!isValidIdentifier(effectiveId) || !VALID_SHARE_ALIAS_RE.test(effectiveAlias)) {
    failSandbox('POLICY_BLOCK', `Invalid share id or alias: ${String(effectiveId)} / ${String(effectiveAlias)}`);
  }
  if (!isSafeAbsoluteLinuxPath(normalizedSource)) {
    failSandbox('POLICY_BLOCK', `Invalid share source path: ${share.sourceLinuxPath}`);
  }
  if (
    FORBIDDEN_WORKSPACE_ROOTS.has(normalizedSource) ||
    FORBIDDEN_WINDOWS_MOUNT_PATTERNS.some((re) => re.test(normalizedSource)) ||
    normalizedSource.startsWith('/mnt/wslg/distro') ||
    normalizedSource.startsWith('/mnt/wsl/') ||
    normalizedSource.startsWith('/run/WSL') ||
    normalizedSource.startsWith('/etc') ||
    normalizedSource.startsWith('/proc') ||
    normalizedSource.startsWith('/sys') ||
    normalizedSource.startsWith('/dev')
  ) {
    failSandbox('POLICY_BLOCK', `Refusing to share full drive, user profile root, or protected OS path: ${normalizedSource}`);
  }
  if (share.mode !== 'ro' && share.mode !== 'rw') {
    failSandbox('POLICY_BLOCK', `Invalid share mode: ${String(share.mode)}`);
  }
  return Object.freeze({
    id: effectiveId,
    alias: effectiveAlias,
    sourceLinuxPath: normalizedSource,
    mode: share.mode,
    oneShot: Boolean(share.oneShot),
  });
}

export function validateDeviceNode(node                      )                       {
  if (typeof node.path !== 'string' || !ALLOWED_DEVICE_RE.test(node.path)) {
    failSandbox(
      'POLICY_BLOCK',
      `Only explicit serial/USB device nodes (/dev/ttyUSB*, /dev/ttyACM*, /dev/bus/usb/NNN/NNN) are allowed: ${node.path}`,
    );
  }
  return Object.freeze({ path: node.path, label: node.label });
}

export function isInternalContainerDistro(distro        )          {
  return INTERNAL_DISTRO_PATTERNS.some((re) => re.test(distro));
}

export function parseWslUncPath(uncPath        )                                                     {
  const match = uncPath.match(/^\\\\(?:wsl\.localhost|wsl\$)\\([^\\]+)(.*)$/i);
  if (!match) return null;
  const distribution = match[1];
  const rest = match[2] ?? '';
  if (!distribution || !isValidIdentifier(distribution)) return null;
  const linuxPath = posix.normalize('/' + rest.replace(/\\/g, '/'));
  const normalized = linuxPath.length > 1 && linuxPath.endsWith('/') ? linuxPath.slice(0, -1) : linuxPath;
  if (!isSafeAbsoluteLinuxPath(normalized)) return null;
  return { distribution, linuxPath: normalized };
}

export function validateProbeAndCreateBinding(
  probe                ,
  generation        ,
)                 {
  if (!probe || probe.backend !== 'wsl') {
    failSandbox('BACKEND_UNAVAILABLE', 'Target backend must be WSL 2; silent fallback to Windows is forbidden');
  }
  if (probe.wslVersion !== 2) {
    failSandbox('BACKEND_UNAVAILABLE', `WSL version ${probe.wslVersion} is unsupported; WSL 2 is required`);
  }
  if (!isValidIdentifier(probe.sessionId) || !isValidIdentifier(probe.distribution)) {
    failSandbox('BACKEND_UNAVAILABLE', 'Invalid sessionId or distribution name');
  }
  if (isInternalContainerDistro(probe.distribution)) {
    failSandbox('BACKEND_UNAVAILABLE', `Refusing to bind internal container distribution: ${probe.distribution}`);
  }
  if (!Number.isSafeInteger(probe.uid) || probe.uid <= 0) {
    failSandbox('BACKEND_UNAVAILABLE', `Non-root Linux UID required (got ${probe.uid})`);
  }
  if (!isValidIdentifier(probe.username)) {
    failSandbox('BACKEND_UNAVAILABLE', `Invalid Linux username: ${probe.username}`);
  }
  if (probe.arch !== 'x86_64' && probe.arch !== 'aarch64') {
    failSandbox('BACKEND_UNAVAILABLE', `Unsupported Linux architecture: ${probe.arch}`);
  }
  if (!isValidIdentifier(probe.revision) || !isValidIdentifier(probe.runnerId)) {
    failSandbox('BACKEND_UNAVAILABLE', 'Invalid revision or runnerId');
  }
  if (probe.sandboxReady !== true) {
    failSandbox('SANDBOX_UNAVAILABLE', 'WSL 2 bubblewrap/seccomp probe did not pass; refusing unconfined execution');
  }
  if (probe.profile !== 'read-only' && probe.profile !== 'workspace-write') {
    failSandbox('POLICY_BLOCK', `Unsupported confined sandbox profile: ${String(probe.profile)}`);
  }

  const workspaceRoot = validateWorkspaceRoot(probe.workspaceRoot, probe.username);
  if (!isSafeAbsoluteLinuxPath(probe.cwd)) {
    failSandbox('POLICY_BLOCK', `Invalid cwd: ${probe.cwd}`);
  }
  if (probe.cwd.startsWith('/mnt/wslg/distro')) {
    failSandbox('POLICY_BLOCK', `Refusing to execute inside WSLg distro mirror: ${probe.cwd}`);
  }
  if (!isPathInside(workspaceRoot, probe.cwd)) {
    failSandbox('POLICY_BLOCK', `cwd (${probe.cwd}) must reside inside workspaceRoot (${workspaceRoot})`);
  }

  const shares                    = [];
  const seenAliases = new Set        ();
  for (const s of probe.authorizedShares ?? []) {
    const validated = validateShareEntry(s);
    if (seenAliases.has(validated.alias)) {
      failSandbox('POLICY_BLOCK', `Duplicate share alias: ${validated.alias}`);
    }
    seenAliases.add(validated.alias);
    shares.push(validated);
  }

  const devices                         = [];
  const seenDevices = new Set        ();
  for (const d of probe.authorizedDevices ?? []) {
    const validated = validateDeviceNode(d);
    if (!seenDevices.has(validated.path)) {
      seenDevices.add(validated.path);
      devices.push(validated);
    }
  }

  return Object.freeze({
    sessionId: probe.sessionId,
    backend: 'wsl',
    wslVersion: 2,
    distribution: probe.distribution,
    uid: probe.uid,
    username: probe.username,
    arch: probe.arch,
    workspaceRoot,
    cwd: probe.cwd,
    profile: probe.profile,
    revision: probe.revision,
    generation,
    runnerId: probe.runnerId,
    sandboxReady: true,
    enforcement: probe.enforcement === 'full' ? 'full' : 'partial',
    supportsDisableUserns: Boolean(probe.supportsDisableUserns),
    probedSockets: Object.freeze([...(probe.probedSockets ?? [])]),
    authorizedShares: Object.freeze(shares),
    authorizedDevices: Object.freeze(devices),
  });
}

                                     
                                     
                                        
                                         
                               
                                        
                                    
                              
                                                         
                                                               
 

export function assertVerifiedProbe(
  probe                ,
  expected                    ,
)                 {
  if (probe.sessionId !== expected.expectedSessionId) {
    failSandbox('STALE_BINDING', `Probe sessionId mismatch: ${probe.sessionId} !== ${expected.expectedSessionId}`);
  }
  if (probe.distribution !== expected.expectedDistribution) {
    failSandbox('STALE_BINDING', `Probe distribution mismatch: ${probe.distribution} !== ${expected.expectedDistribution}`);
  }
  if (probe.workspaceRoot !== expected.expectedWorkspaceRoot) {
    failSandbox('STALE_BINDING', `Probe workspaceRoot mismatch: ${probe.workspaceRoot} !== ${expected.expectedWorkspaceRoot}`);
  }
  if (probe.cwd !== expected.expectedCwd) {
    failSandbox('STALE_BINDING', `Probe cwd mismatch: ${probe.cwd} !== ${expected.expectedCwd}`);
  }
  if (probe.profile !== expected.expectedProfile) {
    failSandbox('STALE_BINDING', `Probe profile mismatch: ${probe.profile} !== ${expected.expectedProfile}`);
  }
  if (probe.revision !== expected.expectedRevision) {
    failSandbox('STALE_BINDING', `Probe revision mismatch: ${probe.revision} !== ${expected.expectedRevision}`);
  }
  return validateProbeAndCreateBinding(
    {
      ...probe,
      authorizedShares: expected.authorizedShares ?? probe.authorizedShares,
      authorizedDevices: expected.authorizedDevices ?? probe.authorizedDevices,
    },
    expected.generation,
  );
}
