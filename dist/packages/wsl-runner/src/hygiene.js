import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

                                 
                        
                           
                             
                              
 

export function summarizePathTree(targetPath        )                 {
  if (!fs.existsSync(targetPath)) {
    return { path: targetPath, exists: false, fileCount: 0, totalBytes: 0 };
  }
  let fileCount = 0;
  let totalBytes = 0;

  const walk = (curr        )       => {
    let st          ;
    try {
      st = fs.lstatSync(curr);
    } catch {
      return;
    }
    if (st.isSymbolicLink() || st.isFile()) {
      fileCount++;
      totalBytes += st.size;
      return;
    }
    if (st.isDirectory()) {
      let entries           = [];
      try {
        entries = fs.readdirSync(curr);
      } catch {
        return;
      }
      for (const name of entries) {
        walk(path.join(curr, name));
      }
    }
  };

  walk(targetPath);
  return { path: targetPath, exists: true, fileCount, totalBytes };
}

function chmodNoFollow(target        , isDir         , mode        )       {
  if (process.platform === 'linux') {
    const flags =
      fs.constants.O_RDONLY |
      (fs.constants.O_NOFOLLOW || 0) |
      (isDir ? (fs.constants.O_DIRECTORY || 0) : 0);
    let fd                    ;
    try {
      fd = fs.openSync(target, flags);
      fs.fchmodSync(fd, mode);
      return;
    } catch {
      // Fallback below if mode blocks O_RDONLY (e.g. 0000); still verify !isSymbolicLink immediately before chmod
    } finally {
      if (fd !== undefined) {
        try {
          fs.closeSync(fd);
        } catch {
          // ignore
        }
      }
    }
  }
  try {
    const check = fs.lstatSync(target);
    if (!check.isSymbolicLink()) {
      fs.chmodSync(target, mode);
    }
  } catch {
    // ignore
  }
}

/**
 * Safely unlocks `0400` / `0444` / read-only files and directories before recursive deletion.
 */
export function forceRemoveReadOnlyTree(targetPath        )          {
  if (!fs.existsSync(targetPath)) return false;

  const unlock = (curr        )       => {
    let st          ;
    try {
      st = fs.lstatSync(curr);
    } catch {
      return;
    }
    if (st.isSymbolicLink()) return;
    if (st.isDirectory()) {
      chmodNoFollow(curr, true, 0o700);
      let entries           = [];
      try {
        entries = fs.readdirSync(curr);
      } catch {
        return;
      }
      for (const name of entries) {
        unlock(path.join(curr, name));
      }
    } else {
      chmodNoFollow(curr, false, 0o600);
    }
  };

  unlock(targetPath);
  fs.rmSync(targetPath, { recursive: true, force: true });
  return true;
}

function isPidAlive(pid        )          {
  if (!Number.isInteger(pid) || pid <= 1) return false;
  if (pid === process.pid) return true;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    const code = (err                         ).code;
    // EPERM means process exists under another UID; ESRCH means dead.
    return code === 'EPERM';
  }
}

/**
 * In WSL 2 (e.g. Ubuntu 24.04), `/tmp` is backed by the root `ext4.vhdx` disk (`/dev/sdd`),
 * whereas `/run/user/<uid>` (`XDG_RUNTIME_DIR`) and `/dev/shm` are real in-RAM `tmpfs` mounts!
 * Preferring a verified `tmpfs` root avoids SSD/VHDX writes AND guarantees automatic kernel
 * vaporization whenever `wsl.exe --terminate` stops the VM.
 */
export function resolveEphemeralRamTmpRoot()         {
  if (process.platform !== 'linux') {
    return os.tmpdir();
  }
  const myUid = typeof process.getuid === 'function' ? process.getuid() : undefined;
  let mountsRaw = '';
  try {
    mountsRaw = fs.readFileSync('/proc/mounts', 'utf8');
  } catch {
    return os.tmpdir();
  }

  const tmpfsMounts = new Set        ();
  for (const line of mountsRaw.split('\n')) {
    const parts = line.split(' ');
    if (parts.length >= 3 && parts[2] === 'tmpfs') {
      tmpfsMounts.add(parts[1] );
    }
  }

  const candidates           = [];
  const xdg = process.env.XDG_RUNTIME_DIR?.trim();
  if (xdg && xdg.startsWith('/')) candidates.push(xdg);
  if (myUid !== undefined) candidates.push(`/run/user/${myUid}`);
  candidates.push('/dev/shm');

  for (const cand of candidates) {
    if (!tmpfsMounts.has(cand)) continue;
    try {
      const st = fs.statSync(cand);
      if (!st.isDirectory()) continue;
      if (cand.startsWith('/run/user/') && myUid !== undefined && st.uid !== myUid) continue;
      fs.accessSync(cand, fs.constants.W_OK | fs.constants.X_OK);
      return cand;
    } catch {
      continue;
    }
  }

  return os.tmpdir();
}

export function getCandidateRunnerTmpRoots(explicitRoot         )           {
  if (explicitRoot) return [explicitRoot];
  const set = new Set        ();
  if (process.platform === 'linux') {
    const xdg = process.env.XDG_RUNTIME_DIR?.trim();
    if (xdg && xdg.startsWith('/')) set.add(xdg);
    if (typeof process.getuid === 'function') set.add(`/run/user/${process.getuid()}`);
    set.add('/dev/shm');
  }
  set.add(os.tmpdir());
  return Array.from(set).filter((p) => {
    try {
      return fs.existsSync(p) && fs.statSync(p).isDirectory();
    } catch {
      return false;
    }
  });
}

/**
 * Cleans up `dsh-wsl-runner-*` and `dsh-wsl-proxy-*` directories across RAM `tmpfs` and `/tmp`
 * left behind when a previous runner was abruptly terminated via `SIGKILL` (`kill -9`).
 */
export function sweepOrphanedRunnerTempDirs(options    
                            
                                           
                                   
 )                                   {
  const roots = getCandidateRunnerTmpRoots(options?.tmpRoot);
  const exclude = new Set((options?.excludeDirs ?? []).map((p) => path.resolve(p)));
  const maxLegacyAgeMs = options?.maxLegacyAgeMs ?? 10 * 60_000;
  const myUid = typeof process.getuid === 'function' ? process.getuid() : undefined;
  const now = Date.now();
  const sweptDirs           = [];

  for (const tmpRoot of roots) {
    let entries              = [];
    try {
      entries = fs.readdirSync(tmpRoot, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const ent of entries) {
      if (!ent.isDirectory()) continue;
      if (!ent.name.startsWith('dsh-wsl-runner-') && !ent.name.startsWith('dsh-wsl-proxy-')) continue;

      const fullPath = path.resolve(tmpRoot, ent.name);
      if (exclude.has(fullPath)) continue;

      let st          ;
      try {
        st = fs.lstatSync(fullPath);
      } catch {
        continue;
      }
      if (myUid !== undefined && st.uid !== myUid) continue;

      const ownerPidFile = path.join(fullPath, 'owner.pid');
      let shouldSweep = false;

      if (fs.existsSync(ownerPidFile)) {
        try {
          const rawPid = Number(fs.readFileSync(ownerPidFile, 'utf8').trim());
          if (!isPidAlive(rawPid)) {
            shouldSweep = true;
          }
        } catch {
          shouldSweep = true;
        }
      } else if (now - st.mtimeMs >= maxLegacyAgeMs) {
        shouldSweep = true;
      }

      if (shouldSweep) {
        try {
          forceRemoveReadOnlyTree(fullPath);
          sweptDirs.push(fullPath);
        } catch {
          // ignore race
        }
      }
    }
  }

  return { sweptDirs };
}

/**
 * Prunes stale or all `~/.cache/dsh-wsl-sandbox/<sha256>` workspace package caches.
 */
export function pruneWorkspaceCaches(options    
                              
                               
                              
 )                                                                     {
  const cacheRoot =
    options?.cacheRoot ?? path.join(os.homedir(), '.cache', 'dsh-wsl-sandbox');
  const purgeAll = Boolean(options?.purgeAll);
  const maxAgeMs = Math.max(1, options?.maxAgeDays ?? 30) * 86_400_000;
  const now = Date.now();
  const removedDirs           = [];

  if (!fs.existsSync(cacheRoot)) {
    return { removedDirs, remainingDirs: 0 };
  }

  if (purgeAll) {
    forceRemoveReadOnlyTree(cacheRoot);
    return { removedDirs: [cacheRoot], remainingDirs: 0 };
  }

  let remainingDirs = 0;
  let entries              = [];
  try {
    entries = fs.readdirSync(cacheRoot, { withFileTypes: true });
  } catch {
    return { removedDirs, remainingDirs: 0 };
  }

  for (const ent of entries) {
    const full = path.join(cacheRoot, ent.name);
    if (!ent.isDirectory()) continue;
    try {
      const st = fs.statSync(full);
      let effectiveMtimeMs = st.mtimeMs;
      const lastUsedPath = path.join(full, '.last-used');
      try {
        const lastUsedSt = fs.lstatSync(lastUsedPath);
        if (!lastUsedSt.isSymbolicLink() && lastUsedSt.isFile()) {
          effectiveMtimeMs = lastUsedSt.mtimeMs;
        }
      } catch {
        // Fallback to directory mtimeMs when `.last-used` does not exist yet
      }
      if (now - effectiveMtimeMs >= maxAgeMs) {
        forceRemoveReadOnlyTree(full);
        removedDirs.push(full);
      } else {
        remainingDirs++;
      }
    } catch {
      // ignore
    }
  }

  return { removedDirs, remainingDirs };
}

function sha256Text(content        )         {
  return createHash('sha256').update(content, 'utf8').digest('hex');
}

/**
 * Writes pristine `.orig` once (`0400`), deduplicates rolling timestamped snapshots by SHA-256
 * so repeated runs NEVER accumulate identical `.bak` files, and caps rolling snapshots to `maxRolling`.
 */
export function writeDeduplicatedReadOnlyBackup(options   
                             
                                
                                 
                              
                             
                           
                               
 )                                                                    {
  const {
    backupDir,
    origFileName,
    rollingPrefix,
    rollingExt,
    timestamp,
    content,
    maxRolling = 5,
  } = options;

  fs.mkdirSync(backupDir, { recursive: true, mode: 0o700 });
  try {
    fs.chmodSync(backupDir, 0o700);
  } catch {
    // ignore on win32
  }

  const savedPaths           = [];
  const targetHash = sha256Text(content);

  const writeRo = (filePath        )       => {
    if (fs.existsSync(filePath)) {
      try {
        fs.chmodSync(filePath, 0o600);
      } catch {
        // ignore
      }
    }
    fs.writeFileSync(filePath, content, { encoding: 'utf8', mode: 0o400 });
    try {
      fs.chmodSync(filePath, 0o400);
    } catch {
      // ignore
    }
    savedPaths.push(filePath);
  };

  const origPath = path.join(backupDir, origFileName);
  if (!fs.existsSync(origPath)) {
    writeRo(origPath);
  }

  // Find existing rolling snapshots for this prefix
  const existingRolling = fs
    .readdirSync(backupDir)
    .filter(
      (f) =>
        f !== origFileName &&
        f.startsWith(`${rollingPrefix}.`) &&
        f.endsWith(`.${rollingExt}`),
    )
    .sort();

  // Check SHA-256 against latest rolling snapshot (or .orig if no rolling exists yet)
  const compareTarget =
    existingRolling.length > 0
      ? path.join(backupDir, existingRolling[existingRolling.length - 1] )
      : origPath;

  if (fs.existsSync(compareTarget)) {
    try {
      const prevHash = sha256Text(fs.readFileSync(compareTarget, 'utf8'));
      if (prevHash === targetHash && existingRolling.length > 0) {
        return { savedPaths, deduplicated: true };
      }
      // Also skip creating an extra .bak on the very first run when identical to .orig!
      if (prevHash === targetHash && compareTarget === origPath && savedPaths.includes(origPath)) {
        return { savedPaths, deduplicated: true };
      }
      if (prevHash === targetHash && compareTarget === origPath && existingRolling.length === 0) {
        return { savedPaths, deduplicated: true };
      }
    } catch {
      // Fall through and write snapshot
    }
  }

  const rollingPath = path.join(backupDir, `${rollingPrefix}.${timestamp}.${rollingExt}`);
  writeRo(rollingPath);

  const updatedRolling = fs
    .readdirSync(backupDir)
    .filter(
      (f) =>
        f !== origFileName &&
        f.startsWith(`${rollingPrefix}.`) &&
        f.endsWith(`.${rollingExt}`),
    )
    .sort();

  while (updatedRolling.length > maxRolling) {
    const oldest = updatedRolling.shift() ;
    const oldestPath = path.join(backupDir, oldest);
    try {
      fs.chmodSync(oldestPath, 0o600);
    } catch {
      // ignore
    }
    try {
      fs.rmSync(oldestPath, { force: true });
    } catch {
      // ignore
    }
  }

  return { savedPaths, deduplicated: false };
}

export function collectWslFootprint(options    
                            
                            
 )                          {
  const homeDir = options?.homeDir ?? os.homedir();
  const tmpRoot = options?.tmpRoot ?? os.tmpdir();

  const runnerRoot = path.join(homeDir, '.local', 'share', 'dsh-wsl-sandbox');
  const configRoot = path.join(homeDir, '.config', 'dsh-wsl-sandbox');
  const cacheRoot = path.join(homeDir, '.cache', 'dsh-wsl-sandbox');
  const envShPath = path.join(homeDir, '.dsh-wsl-env.sh');
  const defaultWorkspace = path.join(homeDir, 'workspace');
  const provisionManifestPath = path.join(configRoot, 'provision-manifest.json');

  const rcFiles = ['.bashrc', '.profile', '.bash_profile', '.zshrc']
    .map((f) => path.join(homeDir, f))
    .filter((f) => {
      try {
        return fs.existsSync(f) && fs.readFileSync(f, 'utf8').includes('.dsh-wsl-env.sh');
      } catch {
        return false;
      }
    });

  const tmpDirs           = [];
  for (const candRoot of getCandidateRunnerTmpRoots(options?.tmpRoot)) {
    try {
      for (const n of fs.readdirSync(candRoot)) {
        if (n.startsWith('dsh-wsl-runner-') || n.startsWith('dsh-wsl-proxy-')) {
          tmpDirs.push(path.join(candRoot, n));
        }
      }
    } catch {
      // ignore
    }
  }

  let provisionManifest          = null;
  if (fs.existsSync(provisionManifestPath)) {
    try {
      provisionManifest = JSON.parse(fs.readFileSync(provisionManifestPath, 'utf8'));
    } catch {
      provisionManifest = null;
    }
  }

  let workspaceEmpty                 = null;
  if (fs.existsSync(defaultWorkspace)) {
    try {
      workspaceEmpty = fs.readdirSync(defaultWorkspace).length === 0;
    } catch {
      workspaceEmpty = null;
    }
  }

  return {
    homeDir,
    runnerAndToolchains: summarizePathTree(runnerRoot),
    configAndBackups: summarizePathTree(configRoot),
    workspaceCache: summarizePathTree(cacheRoot),
    envShFile: { path: envShPath, exists: fs.existsSync(envShPath) },
    hookedShellRcFiles: rcFiles,
    defaultWorkspace: {
      path: defaultWorkspace,
      exists: fs.existsSync(defaultWorkspace),
      isEmpty: workspaceEmpty,
    },
    runtimeTempDirs: tmpDirs,
    provisionManifest,
  };
}
