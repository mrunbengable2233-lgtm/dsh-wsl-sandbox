import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import { posix } from 'node:path';
import {
  failSandbox,
  type FsDirEntry,
  type GrepMatch,
  isMaskedEnvRead,
  isPathInside,
  isProtectedWorkspaceWrite,
  type SessionBinding,
} from '../../core/src/index.ts';

export interface FsPathResolution {
  readonly realPath: string;
  readonly insideShare: boolean;
  readonly shareWritable: boolean;
}

/**
 * Resolve a requested path inside the bound workspaceRoot or an authorized `/shares/<alias>`,
 * preventing symlink escapes and TOCTOU parent traversals.
 */
export function resolveConfinedFsPath(
  binding: SessionBinding,
  requestedPath: string,
  mustExist: boolean,
): FsPathResolution {
  if (typeof requestedPath !== 'string' || requestedPath.length === 0 || requestedPath.includes('\0')) {
    failSandbox('POLICY_BLOCK', `Invalid filesystem path: ${String(requestedPath)}`);
  }

  // Handle /shares/<alias>/... mapped paths
  if (requestedPath === '/shares' || requestedPath.startsWith('/shares/')) {
    const norm = posix.normalize(requestedPath);
    const parts = norm.split('/').filter(Boolean); // ['shares', alias, ...rest]
    const alias = parts[1];
    const share = binding.authorizedShares.find((s) => s.alias === alias);
    if (!share) {
      failSandbox('POLICY_BLOCK', `Unauthorized share path: ${requestedPath}`);
    }
    const shareRootReal = fs.realpathSync(share.sourceLinuxPath);
    const subRel = parts.slice(2).join('/');
    const candidate = subRel ? posix.join(shareRootReal, subRel) : shareRootReal;
    const resolved = canonicalizeWithinRoot(shareRootReal, candidate, mustExist);
    return {
      realPath: resolved,
      insideShare: true,
      shareWritable: share.mode === 'rw',
    };
  }

  const workspaceReal = fs.realpathSync(binding.workspaceRoot);
  const rawAbs = requestedPath.startsWith('/')
    ? posix.normalize(requestedPath)
    : posix.normalize(posix.join(binding.cwd, requestedPath));

  if (!isPathInside(workspaceReal, rawAbs)) {
    failSandbox('POLICY_BLOCK', `Path escapes workspaceRoot (${workspaceReal}): ${requestedPath}`);
  }

  const resolved = canonicalizeWithinRoot(workspaceReal, rawAbs, mustExist);
  return {
    realPath: resolved,
    insideShare: false,
    shareWritable: false,
  };
}

function canonicalizeWithinRoot(rootReal: string, absTarget: string, mustExist: boolean): string {
  if (fs.existsSync(absTarget)) {
    const targetReal = fs.realpathSync(absTarget);
    if (!isPathInside(rootReal, targetReal)) {
      failSandbox('POLICY_BLOCK', `Symlink escape blocked: ${absTarget} -> ${targetReal}`);
    }
    return targetReal;
  }

  if (mustExist) {
    failSandbox('POLICY_BLOCK', `Path does not exist: ${absTarget}`);
  }

  // Walk up to nearest existing ancestor to prevent creating files through a symlinked parent pointing outside root
  let probe = absTarget;
  const missingTail: string[] = [];
  while (!fs.existsSync(probe)) {
    const parent = posix.dirname(probe);
    if (parent === probe) {
      failSandbox('POLICY_BLOCK', `Cannot resolve ancestor for ${absTarget}`);
    }
    missingTail.unshift(posix.basename(probe));
    probe = parent;
  }
  const ancestorReal = fs.realpathSync(probe);
  if (!isPathInside(rootReal, ancestorReal)) {
    failSandbox('POLICY_BLOCK', `Ancestor symlink escape blocked: ${probe} -> ${ancestorReal}`);
  }
  const finalCandidate = posix.join(ancestorReal, ...missingTail);
  if (!isPathInside(rootReal, finalCandidate)) {
    failSandbox('POLICY_BLOCK', `Constructed path escapes root: ${finalCandidate}`);
  }
  return finalCandidate;
}

function assertWriteAllowed(binding: SessionBinding, res: FsPathResolution, requestedPath: string): void {
  if (binding.profile !== 'workspace-write') {
    failSandbox('POLICY_BLOCK', `Write denied under ${binding.profile} sandbox mode: ${requestedPath}`);
  }
  if (res.insideShare) {
    if (!res.shareWritable) {
      failSandbox('POLICY_BLOCK', `Share is mounted read-only: ${requestedPath}`);
    }
    return;
  }
  const check = isProtectedWorkspaceWrite(binding.workspaceRoot, res.realPath);
  if (check.blocked) {
    failSandbox('POLICY_BLOCK', check.reason ?? `Protected path cannot be modified: ${requestedPath}`);
  }
}

function atomicWriteNoFollow(targetPath: string, content: string): number {
  const dir = posix.dirname(targetPath);
  fs.mkdirSync(dir, { recursive: true });

  // Refuse to write through an existing symlink at the target
  try {
    const st = fs.lstatSync(targetPath);
    if (st.isSymbolicLink()) {
      failSandbox('POLICY_BLOCK', `Refusing to write through symlink: ${targetPath}`);
    }
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
  }

  const tmpName = `.dsh-tmp-${process.pid}-${randomBytes(6).toString('hex')}`;
  const tmpPath = posix.join(dir, tmpName);
  const data = Buffer.from(content, 'utf8');
  const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW;
  let fd: number | undefined;
  try {
    fd = fs.openSync(tmpPath, flags, 0o644);
    fs.writeSync(fd, data, 0, data.length);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(tmpPath, targetPath);
    return data.length;
  } catch (err) {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch { /* ignore */ }
    }
    fs.rmSync(tmpPath, { force: true });
    throw err;
  }
}

function globToRegExp(pattern: string): RegExp {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*\//g, '(?:.+/)?')
    .replace(/\*\*/g, '.*')
    .replace(/\*/g, '[^/]*')
    .replace(/\?/g, '[^/]');
  return new RegExp(`^${escaped}$`);
}

export class ConfinedFsService {
  stat(params: { binding: SessionBinding; path: string; maskEnvSecrets?: boolean }): {
    exists: boolean;
    kind: 'file' | 'dir' | 'symlink' | 'other' | 'missing';
    size: number;
    mtimeMs: number;
    maskedEnv: boolean;
  } {
    const res = resolveConfinedFsPath(params.binding, params.path, false);
    if (!fs.existsSync(res.realPath)) {
      return { exists: false, kind: 'missing', size: 0, mtimeMs: 0, maskedEnv: false };
    }
    const st = fs.lstatSync(res.realPath);
    const maskedEnv = !res.insideShare && isMaskedEnvRead(
      params.binding.workspaceRoot,
      res.realPath,
      params.maskEnvSecrets !== false,
    );
    const kind = st.isFile() ? 'file' : st.isDirectory() ? 'dir' : st.isSymbolicLink() ? 'symlink' : 'other';
    return {
      exists: true,
      kind,
      size: maskedEnv ? 0 : st.size,
      mtimeMs: st.mtimeMs,
      maskedEnv,
    };
  }

  read(params: {
    binding: SessionBinding;
    path: string;
    offset?: number;
    limit?: number;
    maskEnvSecrets?: boolean;
  }): {
    content: string;
    truncated: boolean;
    totalBytes: number;
    totalLines: number;
    startLine: number;
    endLine: number;
    maskedEnv: boolean;
  } {
    const res = resolveConfinedFsPath(params.binding, params.path, true);
    const maskedEnv = !res.insideShare && isMaskedEnvRead(
      params.binding.workspaceRoot,
      res.realPath,
      params.maskEnvSecrets !== false,
    );
    if (maskedEnv) {
      return {
        content: '',
        truncated: false,
        totalBytes: 0,
        totalLines: 0,
        startLine: 1,
        endLine: 0,
        maskedEnv: true,
      };
    }

    const raw = fs.readFileSync(res.realPath, 'utf8');
    const totalBytes = Buffer.byteLength(raw, 'utf8');
    if (raw.length === 0) {
      return {
        content: '',
        truncated: false,
        totalBytes: 0,
        totalLines: 0,
        startLine: 1,
        endLine: 0,
        maskedEnv: false,
      };
    }

    const allLines = raw.split(/\r?\n/);
    // Drop trailing empty element produced by final newline for accurate line count while preserving newline behavior
    const hasTrailingNewline = raw.endsWith('\n');
    const logicalLines = hasTrailingNewline ? allLines.slice(0, -1) : allLines;
    const totalLines = logicalLines.length;

    const startLine = Math.max(1, Math.floor(params.offset ?? 1));
    const maxLines = Math.max(1, Math.min(20_000, Math.floor(params.limit ?? 2000)));
    const MAX_BYTES = 256 * 1024;

    if (startLine > totalLines) {
      return {
        content: '',
        truncated: false,
        totalBytes,
        totalLines,
        startLine,
        endLine: startLine - 1,
        maskedEnv: false,
      };
    }

    const startIdx = startLine - 1;
    const picked: string[] = [];
    let usedBytes = 0;
    let byteCapped = false;

    for (let i = startIdx; i < totalLines && picked.length < maxLines; i++) {
      const line = logicalLines[i]!;
      const lineBytes = Buffer.byteLength(line, 'utf8') + 1;
      if (picked.length > 0 && usedBytes + lineBytes > MAX_BYTES) {
        byteCapped = true;
        break;
      }
      if (picked.length === 0 && lineBytes > MAX_BYTES) {
        picked.push(Buffer.from(line, 'utf8').subarray(0, MAX_BYTES).toString('utf8'));
        byteCapped = true;
        break;
      }
      picked.push(line);
      usedBytes += lineBytes;
    }

    const endLine = startLine + picked.length - 1;
    const moreLinesRemain = endLine < totalLines;
    const suffix = hasTrailingNewline && !moreLinesRemain && !byteCapped ? '\n' : '';
    return {
      content: picked.join('\n') + suffix,
      truncated: moreLinesRemain || byteCapped,
      totalBytes,
      totalLines,
      startLine,
      endLine,
      maskedEnv: false,
    };
  }

  write(params: { binding: SessionBinding; path: string; content: string }): {
    bytesWritten: number;
    canonicalPath: string;
  } {
    const res = resolveConfinedFsPath(params.binding, params.path, false);
    assertWriteAllowed(params.binding, res, params.path);
    const bytesWritten = atomicWriteNoFollow(res.realPath, params.content);
    return { bytesWritten, canonicalPath: res.realPath };
  }

  edit(params: {
    binding: SessionBinding;
    path: string;
    oldText: string;
    newText: string;
    replaceAll?: boolean;
  }): { replacements: number; canonicalPath: string } {
    const res = resolveConfinedFsPath(params.binding, params.path, true);
    assertWriteAllowed(params.binding, res, params.path);
    if (!params.oldText) {
      failSandbox('INVALID_ACTION', 'edit oldText must be non-empty');
    }
    const content = fs.readFileSync(res.realPath, 'utf8');
    let replacements = 0;
    let updated: string;
    if (params.replaceAll) {
      const parts = content.split(params.oldText);
      replacements = parts.length - 1;
      updated = parts.join(params.newText);
    } else {
      const idx = content.indexOf(params.oldText);
      if (idx === -1) {
        failSandbox('INVALID_ACTION', `oldText not found in ${params.path}`);
      }
      replacements = 1;
      updated = content.slice(0, idx) + params.newText + content.slice(idx + params.oldText.length);
    }
    if (replacements === 0) {
      failSandbox('INVALID_ACTION', `oldText not found in ${params.path}`);
    }
    atomicWriteNoFollow(res.realPath, updated);
    return { replacements, canonicalPath: res.realPath };
  }

  list(params: { binding: SessionBinding; path: string; maxEntries?: number }): {
    entries: FsDirEntry[];
  } {
    const res = resolveConfinedFsPath(params.binding, params.path, true);
    const cap = Math.min(2000, Math.max(1, params.maxEntries ?? 500));
    const dirents = fs.readdirSync(res.realPath, { withFileTypes: true });
    const entries: FsDirEntry[] = [];
    for (const d of dirents.slice(0, cap)) {
      let size = 0;
      const full = posix.join(res.realPath, d.name);
      try {
        size = fs.lstatSync(full).size;
      } catch {
        // ignore
      }
      entries.push({
        name: d.name,
        kind: d.isFile() ? 'file' : d.isDirectory() ? 'dir' : d.isSymbolicLink() ? 'symlink' : 'other',
        size,
      });
    }
    return { entries };
  }

  glob(params: {
    binding: SessionBinding;
    pattern: string;
    cwd?: string;
    maxResults?: number;
  }): { matches: string[]; truncated: boolean } {
    const base = resolveConfinedFsPath(params.binding, params.cwd ?? params.binding.cwd, true);
    const re = globToRegExp(params.pattern);
    const cap = Math.min(2000, Math.max(1, params.maxResults ?? 200));
    const matches: string[] = [];
    let truncated = false;

    const skip = new Set(['.git', 'node_modules', '.venv', '__pycache__', 'target']);

    const walk = (dir: string, relPrefix: string): void => {
      if (truncated) return;
      let entries: fs.Dirent[];
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        return;
      }
      for (const entry of entries) {
        if (truncated) return;
        if (entry.isSymbolicLink()) continue;
        const rel = relPrefix ? `${relPrefix}/${entry.name}` : entry.name;
        const full = posix.join(dir, entry.name);
        if (entry.isDirectory()) {
          if (skip.has(entry.name)) continue;
          walk(full, rel);
        } else if (entry.isFile()) {
          if (re.test(rel)) {
            if (matches.length >= cap) {
              truncated = true;
              return;
            }
            matches.push(rel);
          }
        }
      }
    };

    walk(base.realPath, '');
    matches.sort();
    return { matches, truncated };
  }

  grep(params: {
    binding: SessionBinding;
    query: string;
    cwd?: string;
    regex?: boolean;
    maxMatches?: number;
    maskEnvSecrets?: boolean;
  }): { matches: GrepMatch[]; truncated: boolean } {
    const base = resolveConfinedFsPath(params.binding, params.cwd ?? params.binding.cwd, true);
    const cap = Math.min(500, Math.max(1, params.maxMatches ?? 100));
    const maskEnv = params.maskEnvSecrets !== false;

    // Prefer fast ripgrep (`rg`) inside distro if available
    const rgArgs = ['--no-heading', '--line-number', '--color=never', '--max-count=50'];
    if (!params.regex) rgArgs.push('--fixed-strings');
    rgArgs.push('--', params.query, base.realPath);

    const rgRes = spawnSync('rg', rgArgs, { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024, timeout: 15_000 });
    if (!rgRes.error && (rgRes.status === 0 || rgRes.status === 1)) {
      const matches: GrepMatch[] = [];
      let truncated = false;
      const lines = (rgRes.stdout || '').split('\n').filter(Boolean);
      for (const line of lines) {
        const firstColon = line.indexOf(':');
        if (firstColon === -1) continue;
        const secondColon = line.indexOf(':', firstColon + 1);
        if (secondColon === -1) continue;
        const filePath = line.slice(0, firstColon);
        const lineNum = Number(line.slice(firstColon + 1, secondColon));
        const text = line.slice(secondColon + 1);
        if (isMaskedEnvRead(params.binding.workspaceRoot, filePath, maskEnv)) {
          continue;
        }
        if (matches.length >= cap) {
          truncated = true;
          break;
        }
        matches.push({
          file: posix.relative(base.realPath, filePath),
          line: Number.isFinite(lineNum) ? lineNum : 0,
          text,
        });
      }
      return { matches, truncated };
    }

    // Pure JS fallback when `rg` is not installed yet
    const matcher = params.regex ? new RegExp(params.query) : null;
    const matches: GrepMatch[] = [];
    let truncated = false;
    const { matches: files } = this.glob({ binding: params.binding, pattern: '**', cwd: base.realPath, maxResults: 1000 });
    for (const rel of files) {
      if (truncated) break;
      const full = posix.join(base.realPath, rel);
      if (isMaskedEnvRead(params.binding.workspaceRoot, full, maskEnv)) continue;
      let content: string;
      try {
        const st = fs.statSync(full);
        if (st.size > 2 * 1024 * 1024) continue;
        content = fs.readFileSync(full, 'utf8');
      } catch {
        continue;
      }
      if (content.includes('\0')) continue;
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const text = lines[i]!;
        const hit = matcher ? matcher.test(text) : text.includes(params.query);
        if (hit) {
          if (matches.length >= cap) {
            truncated = true;
            break;
          }
          matches.push({ file: rel, line: i + 1, text });
        }
      }
    }
    return { matches, truncated };
  }

  delete(params: { binding: SessionBinding; path: string }): { deleted: true } {
    const res = resolveConfinedFsPath(params.binding, params.path, true);
    assertWriteAllowed(params.binding, res, params.path);
    if (res.realPath === fs.realpathSync(params.binding.workspaceRoot)) {
      failSandbox('POLICY_BLOCK', 'Cannot delete workspaceRoot itself');
    }
    fs.rmSync(res.realPath, { recursive: false, force: false });
    return { deleted: true };
  }

  move(params: { binding: SessionBinding; from: string; to: string }): { moved: true } {
    const src = resolveConfinedFsPath(params.binding, params.from, true);
    const dst = resolveConfinedFsPath(params.binding, params.to, false);
    assertWriteAllowed(params.binding, src, params.from);
    assertWriteAllowed(params.binding, dst, params.to);
    fs.mkdirSync(posix.dirname(dst.realPath), { recursive: true });
    fs.renameSync(src.realPath, dst.realPath);
    return { moved: true };
  }
}
