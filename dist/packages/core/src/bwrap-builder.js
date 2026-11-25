import fs from 'node:fs';
import { posix } from 'node:path';
             
                       
                  
              
              
                      
import {
  DANGEROUS_DIRECTORIES,
  DANGEROUS_FILES,
  scanEnvSecretFiles,
} from './dangerous-paths.js';
import { failSandbox } from './errors.js';

export const HIGH_RISK_SYSTEM_SOCKETS = [
  '/run/dbus/system_bus_socket',
  '/run/docker.sock',
  '/var/run/docker.sock',
  '/run/podman/podman.sock',
  '/var/run/podman/podman.sock',
  '/run/containerd/containerd.sock',
  '/var/run/containerd/containerd.sock',
  '/run/crio/crio.sock',
  '/run/k3s/containerd/containerd.sock',
]         ;

export const WSL_DISPLAY_AUDIO_PATHS = [
  '/tmp/.X11-unix',
  '/mnt/wslg/.X11-unix',
  '/mnt/wslg/PulseServer',
]         ;

                               
                         
                          
                              
 

export const DEFAULT_RLIMITS               = Object.freeze({
  nproc: 256,
  nofile: 1024,
  fsizeBytes: 512 * 1024 * 1024, // 512 MiB
});

                            
                        
                                            
                               
 

                                  
                                   
                       
                                 
                             
                                    
                                          
                              
                                                 
                                           
                                
                                               
                                                     
                                                       
                             
                                    
                                      
                                        
                                                  
                                                                                  
                                              
                                                                                 
                                               
                                                                              
                                                
                                                                           
                                                                                             
                                                                                                 
                                                  
 

                                   
                               
                                   
                                    
                                    
                                                                                                                  
                                         
                                    
                                           
 

const SKIP_TOP_LEVEL = new Set(['dev', 'proc', 'sys', 'tmp', 'run', 'mnt', 'shares']);

function readLinuxRootEntries()              {
  if (process.platform !== 'linux') {
    return [
      { name: 'bin', kind: 'symlink', linkTarget: 'usr/bin' },
      { name: 'lib', kind: 'symlink', linkTarget: 'usr/lib' },
      { name: 'lib64', kind: 'symlink', linkTarget: 'usr/lib64' },
      { name: 'sbin', kind: 'symlink', linkTarget: 'usr/sbin' },
      { name: 'etc', kind: 'dir' },
      { name: 'home', kind: 'dir' },
      { name: 'opt', kind: 'dir' },
      { name: 'usr', kind: 'dir' },
      { name: 'var', kind: 'dir' },
    ];
  }
  const entries              = [];
  for (const name of fs.readdirSync('/').sort()) {
    if (SKIP_TOP_LEVEL.has(name)) continue;
    const full = `/${name}`;
    try {
      const st = fs.lstatSync(full);
      if (st.isSymbolicLink()) {
        entries.push({ name, kind: 'symlink', linkTarget: fs.readlinkSync(full) });
      } else if (st.isDirectory()) {
        entries.push({ name, kind: 'dir' });
      } else if (st.isFile()) {
        entries.push({ name, kind: 'file' });
      }
    } catch {
      // Ignore unreadable root entries
    }
  }
  return entries;
}

function defaultLstatKind(p        )                                                         {
  try {
    const st = fs.lstatSync(p);
    if (st.isSymbolicLink()) return 'symlink';
    if (st.isDirectory()) return 'dir';
    if (st.isFile()) return 'file';
    if (st.isSocket()) return 'socket';
    return 'other';
  } catch {
    return null;
  }
}

export function discoverSocketsToMask(
  env                                              ,
  extraSockets                    = [],
  realpathSync                        = (p) => fs.realpathSync(p),
  existsSync                         = (p) => fs.existsSync(p),
)           {
  const candidates = new Set        (HIGH_RISK_SYSTEM_SOCKETS);
  const xdg = env.XDG_RUNTIME_DIR;
  if (xdg && xdg.startsWith('/')) {
    candidates.add(posix.join(xdg, 'bus'));
    candidates.add(posix.join(xdg, 'systemd', 'private'));
  }
  if (env.SSH_AUTH_SOCK && env.SSH_AUTH_SOCK.startsWith('/')) {
    candidates.add(env.SSH_AUTH_SOCK);
  }
  if (env.GPG_AGENT_INFO) {
    const gpgSock = env.GPG_AGENT_INFO.split(':')[0];
    if (gpgSock && gpgSock.startsWith('/')) {
      candidates.add(gpgSock);
    }
  }
  for (const s of extraSockets) {
    if (s.startsWith('/')) candidates.add(s);
  }

  const resolved = new Set        ();
  for (const candidate of candidates) {
    if (!existsSync(candidate)) continue;
    try {
      const target = realpathSync(candidate);
      resolved.add(target);
      if (target !== candidate) {
        resolved.add(candidate);
      }
    } catch {
      // Fail-closed: if a high-risk socket exists but cannot be resolved, abort preparation
      failSandbox('SANDBOX_PREPARATION_FAILED', `Failed to resolve high-risk socket for masking: ${candidate}`);
    }
  }

  return Array.from(resolved).sort();
}

export function buildBwrapArgs(input                 )                   {
  if (!input.argv || input.argv.length === 0) {
    failSandbox('INVALID_ACTION', 'bwrap argv must be non-empty');
  }
  if (input.cwd.startsWith('/mnt/wslg/distro') || input.workspaceRoot.startsWith('/mnt/wslg/distro')) {
    failSandbox('POLICY_BLOCK', 'Refusing to launch bwrap under /mnt/wslg/distro');
  }

  const exists = input.existsSync ?? ((p        ) => fs.existsSync(p));
  const realpath = input.realpathSync ?? ((p        ) => fs.realpathSync(p));
  const lstatKind = input.lstatKind ?? defaultLstatKind;
  const rootEntries = input.rootEntries ?? readLinuxRootEntries();

  const args           = [];

  // 1. Namespace & terminal isolation
  args.push('--unshare-user');
  if (input.supportsDisableUserns) {
    args.push('--disable-userns');
  }
  args.push('--unshare-pid', '--unshare-ipc', '--unshare-net', '--new-session', '--die-with-parent');

  // 2. Clean environment inside sandbox
  args.push('--clearenv');
  for (const [k, v] of Object.entries(input.env)) {
    if (k.includes('\0') || v.includes('\0')) continue;
    args.push('--setenv', k, v);
  }

  // 3. Base read-only root built over bwrap's fresh tmpfs `/`, enabling clean `/shares`
  //    and atomic tmpfs masking of `/run` (hiding /run/WSL, dbus, docker/podman/containerd/k3s)
  //    and `/mnt` (hiding /mnt/c, /mnt/wsl, /mnt/wslg/distro, WSLg X11/PulseAudio).
  for (const entry of rootEntries) {
    if (SKIP_TOP_LEVEL.has(entry.name)) continue;
    const full = `/${entry.name}`;
    if (entry.kind === 'symlink' && entry.linkTarget) {
      args.push('--symlink', entry.linkTarget, full);
    } else {
      args.push('--ro-bind', full, full);
    }
  }

  args.push('--dev', '/dev');
  args.push('--proc', '/proc');
  if (lstatKind('/sys') === 'dir') {
    args.push('--ro-bind', '/sys', '/sys');
  }
  args.push('--tmpfs', '/tmp');
  args.push('--tmpfs', '/var/tmp');
  args.push('--tmpfs', '/run');
  args.push('--tmpfs', '/mnt');

  // 4. Mask any extra non-/run, non-/tmp, non-/mnt high-risk sockets (e.g. custom SSH_AUTH_SOCK)
  const maskedSockets = discoverSocketsToMask(
    process.env,
    input.extraSocketsToMask ?? [],
    realpath,
    exists,
  );
  for (const sock of maskedSockets) {
    if (
      sock.startsWith('/tmp/') ||
      sock.startsWith('/mnt/') ||
      sock.startsWith('/run/') ||
      sock.startsWith('/var/run/')
    ) {
      continue; // already hidden under fresh empty tmpfs
    }
    args.push('--ro-bind', '/dev/null', sock);
  }

  // 5. Controlled UDS proxy socket mount inside private `/run/dsh-proxy`
  if (input.networkMode === 'allowlist-proxy' && input.proxySocketHostPath) {
    if (!exists(input.proxySocketHostPath)) {
      failSandbox('SANDBOX_PREPARATION_FAILED', `UDS proxy socket not found: ${input.proxySocketHostPath}`);
    }
    args.push('--tmpfs', '/run/dsh-proxy');
    args.push('--bind', input.proxySocketHostPath, '/run/dsh-proxy/proxy.sock');
  }

  // 6. Advanced human-authorized shares mapped ONLY to `/shares/<alias>`
  if (input.shares && input.shares.length > 0) {
    args.push('--tmpfs', '/shares');
    for (const share of input.shares) {
      const dest = `/shares/${share.alias}`;
      const mountFlag = share.mode === 'rw' && input.mode === 'workspace-write' ? '--bind' : '--ro-bind';
      args.push(mountFlag, share.sourceLinuxPath, dest);
    }
  }

  // Lock `/` itself read-only after creating top-level mountpoints (`/shares`, `/run`, `/mnt`, etc.)
  args.push('--remount-ro', '/');

  // 7. Workspace & isolated cache (workspace-write only for rw)
  if (input.mode === 'workspace-write') {
    args.push('--bind', input.workspaceRoot, input.workspaceRoot);

    for (const extraRoot of input.additionalWritableRoots ?? []) {
      const kind = lstatKind(extraRoot);
      if (kind !== 'dir') {
        failSandbox('SANDBOX_PREPARATION_FAILED', `additionalWritableRoot must be a physical directory: ${extraRoot}`);
      }
      args.push('--bind', extraRoot, extraRoot);
    }

    if (input.cacheDir) {
      args.push('--bind', input.cacheDir, input.cacheDir);
    }
  } else if (input.workspaceRoot.startsWith('/tmp/')) {
    // Even in read-only mode, if workspace lives under /tmp (e.g. test dirs), expose it read-only
    args.push('--ro-bind', input.workspaceRoot, input.workspaceRoot);
  }

  // 8. Checklist B: Workspace-internal read-only locks (applied AFTER --bind workspaceRoot!)
  const protectedPaths           = [];
  const createdPlaceholders           = [];
  if (input.mode === 'workspace-write') {
    const emptyMask = input.emptyMaskFilePath ?? '/dev/null';

    for (const relFile of DANGEROUS_FILES) {
      const target = posix.join(input.workspaceRoot, relFile);
      const kind = lstatKind(target);
      if (kind !== null) {
        args.push('--ro-bind', target, target);
        protectedPaths.push(target);
      } else {
        // Non-existent dangerous file: bind /dev/null read-only to prevent in-sandbox creation!
        args.push('--ro-bind', '/dev/null', target);
        protectedPaths.push(target);
        createdPlaceholders.push(target);
      }
    }

    for (const relDirOrFile of DANGEROUS_DIRECTORIES) {
      const target = posix.join(input.workspaceRoot, relDirOrFile);
      const parentDir = posix.dirname(target);
      const kind = lstatKind(target);
      if (kind !== null) {
        args.push('--ro-bind', target, target);
        protectedPaths.push(target);
      } else if (lstatKind(parentDir) === 'dir') {
        // Parent exists (e.g. .git exists, .git/hooks missing): block creation with read-only placeholder
        args.push('--ro-bind', emptyMask, target);
        protectedPaths.push(target);
        createdPlaceholders.push(target);
      }
    }
  }

  // 9. Depth-limited .env* secret read masking (applies in BOTH read-only and workspace-write)
  const maskedEnvFiles           = [];
  if (input.maskEnvSecrets !== false) {
    const envFiles = input.preScannedEnvFiles
      ? [...input.preScannedEnvFiles]
      : scanEnvSecretFiles(input.workspaceRoot, 3);
    const maskSource = input.emptyMaskFilePath ?? '/dev/null';
    for (const envFile of envFiles) {
      args.push('--ro-bind', maskSource, envFile);
      maskedEnvFiles.push(envFile);
    }
  }

  // 10. Advanced physical device passthrough (ONLY human-explicit single nodes)
  const mountedDevices           = [];
  for (const dev of input.devices ?? []) {
    if (!exists(dev.path)) {
      failSandbox('SANDBOX_PREPARATION_FAILED', `Authorized physical device node not found: ${dev.path}`);
    }
    args.push('--dev-bind', dev.path, dev.path);
    mountedDevices.push(dev.path);
  }

  // 11. Seccomp BPF fd
  if (input.seccompFd !== undefined) {
    args.push('--seccomp', String(input.seccompFd));
  }

  // 12. Working directory
  args.push('--chdir', input.cwd);
  args.push('--');

  // 13. Optional prlimit resource caps (nsjail-inspired fork-bomb & disk-fill defense)
  if (input.usePrlimit !== false) {
    const rl               = {
      nproc: input.rlimits?.nproc ?? DEFAULT_RLIMITS.nproc,
      nofile: input.rlimits?.nofile ?? DEFAULT_RLIMITS.nofile,
      fsizeBytes: input.rlimits?.fsizeBytes ?? DEFAULT_RLIMITS.fsizeBytes,
    };
    args.push(
      'prlimit',
      `--nproc=${rl.nproc}`,
      `--nofile=${rl.nofile}`,
      `--fsize=${rl.fsizeBytes}`,
      '--',
    );
  }

  args.push(...input.argv);

  return {
    bwrapArgs: args,
    maskedSockets,
    maskedEnvFiles,
    protectedPaths,
    createdPlaceholders,
    mountedDevices,
    enforcement: input.seccompFd !== undefined && input.supportsDisableUserns ? 'full' : 'partial',
  };
}
