import { spawn } from 'node:child_process';
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

const MAX_READ_FILE_BYTES = 16 * 1024 * 1024; // 16 MiB safety cap for wsl_read / wsl_edit
const BINARY_NUL_SNIFF_BYTES = 8192;
const MAX_RG_STDOUT_BYTES = 4 * 1024 * 1024;

export interface FsPathResolution {
  readonly rootReal: string;
  readonly realPath: string;
  readonly insideShare: boolean;
  readonly shareWritable: boolean;
}

export function toPosixPath(p: string): string {
  return p.replace(/\\/g, '/');
}

function isAbsolutePosixOrWin(p: string): boolean {
  return p.startsWith('/') || /^[A-Za-z]:\//.test(p);
}

function lstatOrNull(targetPath: string): fs.Stats | null {
  try {
    return fs.lstatSync(targetPath);
  } catch {
    return null;
  }
}

function canonicalizeAncestorWithinRoot(rootReal: string, absTarget: string): string {
  let probe = absTarget;
  const missingTail: string[] = [];
  for (;;) {
    const st = lstatOrNull(probe);
    if (st) {
      if (st.isSymbolicLink() && !fs.existsSync(probe)) {
        failSandbox('POLICY_BLOCK', `Ancestor symlink target does not exist: ${probe}`);
      }
      break;
    }
    const parent = posix.dirname(probe);
    if (parent === probe) {
      failSandbox('POLICY_BLOCK', `Cannot resolve ancestor for ${absTarget}`);
    }
    missingTail.unshift(posix.basename(probe));
    probe = parent;
  }
  const ancestorReal = toPosixPath(fs.realpathSync(probe));
  if (!isPathInside(rootReal, ancestorReal)) {
    failSandbox('POLICY_BLOCK', `Ancestor symlink escape blocked: ${probe} -> ${ancestorReal}`);
  }
  const finalCandidate = missingTail.length > 0 ? posix.join(ancestorReal, ...missingTail) : ancestorReal;
  if (!isPathInside(rootReal, finalCandidate)) {
    failSandbox('POLICY_BLOCK', `Constructed path escapes root: ${finalCandidate}`);
  }
  return finalCandidate;
}

/**
 * Resolve a requested path inside the bound workspaceRoot or an authorized `/shares/<alias>`,
 * preventing symlink escapes and TOCTOU parent traversals.
 */
export function resolveConfinedFsPath(
  binding: SessionBinding,
  requestedPath: string,
  mustExist: boolean,
  options?: { readonly allowDanglingSymlink?: boolean },
): FsPathResolution {
  if (typeof requestedPath !== 'string' || requestedPath.length === 0 || requestedPath.includes('\0')) {
    failSandbox('POLICY_BLOCK', `Invalid filesystem path: ${String(requestedPath)}`);
  }

  const reqPosix = toPosixPath(requestedPath);

  // Handle /shares/<alias>/... mapped paths
  if (reqPosix === '/shares' || reqPosix.startsWith('/shares/')) {
    const norm = posix.normalize(reqPosix);
    const parts = norm.split('/').filter(Boolean); // ['shares', alias, ...rest]
    const alias = parts[1];
    const share = binding.authorizedShares.find((s) => s.alias === alias);
    if (!share) {
      failSandbox('POLICY_BLOCK', `Unauthorized share path: ${requestedPath}`);
    }
    const shareRootReal = toPosixPath(fs.realpathSync(share.sourceLinuxPath));
    const subRel = parts.slice(2).join('/');
    const candidate = subRel ? posix.join(shareRootReal, subRel) : shareRootReal;
    const resolved = canonicalizeWithinRoot(shareRootReal, candidate, mustExist, options);
    return {
      rootReal: shareRootReal,
      realPath: resolved,
      insideShare: true,
      shareWritable: share.mode === 'rw',
    };
  }

  const workspaceReal = toPosixPath(fs.realpathSync(binding.workspaceRoot));
  const rawWs = posix.normalize(toPosixPath(binding.workspaceRoot));
  const cwdPosix = posix.normalize(toPosixPath(binding.cwd));
  let rawAbs = isAbsolutePosixOrWin(reqPosix)
    ? posix.normalize(reqPosix)
    : posix.normalize(posix.join(cwdPosix, reqPosix));

  if (!isPathInside(workspaceReal, rawAbs)) {
    if (isPathInside(rawWs, rawAbs)) {
      const rel = rawAbs === rawWs ? '' : rawAbs.slice(rawWs.length + 1);
      rawAbs = rel ? posix.join(workspaceReal, rel) : workspaceReal;
    } else {
      failSandbox('POLICY_BLOCK', `Path escapes workspaceRoot (${workspaceReal}): ${requestedPath}`);
    }
  }

  const resolved = canonicalizeWithinRoot(workspaceReal, rawAbs, mustExist, options);
  return {
    rootReal: workspaceReal,
    realPath: resolved,
    insideShare: false,
    shareWritable: false,
  };
}

function canonicalizeWithinRoot(
  rootReal: string,
  absTarget: string,
  mustExist: boolean,
  options?: { readonly allowDanglingSymlink?: boolean },
): string {
  const existing = lstatOrNull(absTarget);
  if (existing) {
    if (existing.isSymbolicLink() && !fs.existsSync(absTarget)) {
      // Dangling symlink: verify parent resolves inside root before allowing stat/delete/move-src
      const parentReal = canonicalizeAncestorWithinRoot(rootReal, posix.dirname(absTarget));
      const linkPath = posix.join(parentReal, posix.basename(absTarget));
      if (!isPathInside(rootReal, linkPath)) {
        failSandbox('POLICY_BLOCK', `Symlink escapes root: ${absTarget}`);
      }
      if (options?.allowDanglingSymlink) {
        return linkPath;
      }
      failSandbox('POLICY_BLOCK', `Dangling symlink target cannot be traversed: ${absTarget}`);
    }
    const targetReal = toPosixPath(fs.realpathSync(absTarget));
    if (!isPathInside(rootReal, targetReal)) {
      failSandbox('POLICY_BLOCK', `Symlink escape blocked: ${absTarget} -> ${targetReal}`);
    }
    return targetReal;
  }

  if (mustExist) {
    failSandbox('POLICY_BLOCK', `Path does not exist: ${absTarget}`);
  }

  // Walk up to nearest existing ancestor to prevent creating files through a symlinked parent pointing outside root
  return canonicalizeAncestorWithinRoot(rootReal, absTarget);
}

function assertWriteAllowed(binding: SessionBinding, res: FsPathResolution, requestedPath: string): void {
  if (binding.profile !== 'workspace-write') {
    failSandbox('POLICY_BLOCK', `Write denied under ${binding.profile} sandbox mode: ${requestedPath}`);
  }
  if (res.insideShare && !res.shareWritable) {
    failSandbox('POLICY_BLOCK', `Share is mounted read-only: ${requestedPath}`);
  }
  const check = isProtectedWorkspaceWrite(res.rootReal, res.realPath);
  if (check.blocked) {
    failSandbox('POLICY_BLOCK', check.reason ?? `Protected path cannot be modified: ${requestedPath}`);
  }
}

function readUtf8RegularFile(
  filePath: string,
  requestedPath: string,
  maxBytes = MAX_READ_FILE_BYTES,
): { content: string; mode: number } {
  const lst = lstatOrNull(filePath);
  if (!lst) {
    failSandbox('POLICY_BLOCK', `Path does not exist: ${requestedPath}`);
  }
  if (lst.isDirectory()) {
    failSandbox('INVALID_ACTION', `Path is a directory, expected regular file: ${requestedPath}`);
  }

  const openFlags =
    fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK || 0) | (fs.constants.O_NOFOLLOW || 0);
  let fd: number | undefined;
  try {
    fd = fs.openSync(filePath, openFlags);
    const fst = fs.fstatSync(fd);
    if (!fst.isFile()) {
      failSandbox('INVALID_ACTION', `Path is not a regular file (refusing FIFO/device/socket): ${requestedPath}`);
    }
    if (fst.size > maxBytes) {
      failSandbox(
        'OUTPUT_LIMIT',
        `File exceeds ${Math.floor(maxBytes / (1024 * 1024))} MiB limit (${fst.size} bytes): ${requestedPath}`,
      );
    }

    const chunks: Buffer[] = [];
    let total = 0;
    const chunkBuf = Buffer.allocUnsafe(64 * 1024);
    for (;;) {
      const n = fs.readSync(fd, chunkBuf, 0, chunkBuf.length, null);
      if (n === 0) break;
      total += n;
      if (total > maxBytes) {
        failSandbox(
          'OUTPUT_LIMIT',
          `File exceeds ${Math.floor(maxBytes / (1024 * 1024))} MiB limit while reading: ${requestedPath}`,
        );
      }
      chunks.push(Buffer.from(chunkBuf.subarray(0, n)));
    }

    const buf = chunks.length === 1 ? chunks[0]! : Buffer.concat(chunks, total);
    const probeLen = Math.min(buf.length, BINARY_NUL_SNIFF_BYTES);
    if (probeLen > 0 && buf.subarray(0, probeLen).includes(0)) {
      failSandbox('INVALID_ACTION', `Refusing binary file containing NUL bytes: ${requestedPath}`);
    }

    return { content: buf.toString('utf8'), mode: fst.mode & 0o777 };
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

function atomicWriteNoFollow(targetPath: string, content: string, mode = 0o644): number {
  const dir = posix.dirname(targetPath);
  fs.mkdirSync(dir, { recursive: true });

  // Refuse to write through an existing symlink at the target
  try {
    const st = fs.lstatSync(targetPath);
    if (st.isSymbolicLink()) {
      failSandbox('POLICY_BLOCK', `Refusing to write through symlink: ${targetPath}`);
    }
    if (st.isDirectory()) {
      failSandbox('INVALID_ACTION', `Cannot overwrite directory with file write: ${targetPath}`);
    }
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
  }

  const tmpName = `.dsh-tmp-${process.pid}-${randomBytes(6).toString('hex')}`;
  const tmpPath = posix.join(dir, tmpName);
  const data = Buffer.from(content, 'utf8');
  const flags =
    fs.constants.O_WRONLY |
    fs.constants.O_CREAT |
    fs.constants.O_EXCL |
    (fs.constants.O_NOFOLLOW || 0);
  let fd: number | undefined;
  try {
    fd = fs.openSync(tmpPath, flags, mode);
    fs.writeSync(fd, data, 0, data.length);
    if (process.platform !== 'win32' && mode !== 0o644) {
      try {
        fs.fchmodSync(fd, mode);
      } catch {
        // ignore chmod failures on restricted filesystems
      }
    }
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(tmpPath, targetPath);
    return data.length;
  } catch (err) {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch {
        /* ignore */
      }
    }
    fs.rmSync(tmpPath, { force: true });
    throw err;
  }
}

function globFragmentToRegExpSource(fragment: string): string {
  let out = '';
  let i = 0;
  while (i < fragment.length) {
    const ch = fragment[i]!;
    if ((i === 0 || fragment[i - 1] === '/') && fragment.startsWith('**/', i)) {
      out += '(?:.+/)?';
      i += 3;
      continue;
    }
    if (fragment.startsWith('/**', i) && i + 3 === fragment.length) {
      out += '(?:/.*)?';
      i += 3;
      continue;
    }
    if (fragment.startsWith('**', i)) {
      out += '.*';
      i += 2;
      continue;
    }
    if (ch === '*') {
      out += '[^/]*';
      i += 1;
      continue;
    }
    if (ch === '?') {
      out += '[^/]';
      i += 1;
      continue;
    }
    if (ch === '{') {
      let depth = 1;
      let j = i + 1;
      const alts: string[] = [];
      let altStart = j;
      while (j < fragment.length && depth > 0) {
        const cur = fragment[j]!;
        if (cur === '{') {
          depth += 1;
        } else if (cur === '}') {
          depth -= 1;
          if (depth === 0) {
            alts.push(fragment.slice(altStart, j));
            break;
          }
        } else if (cur === ',' && depth === 1) {
          alts.push(fragment.slice(altStart, j));
          altStart = j + 1;
        }
        j += 1;
      }
      if (depth === 0) {
        out += `(?:${alts.map((alt) => globFragmentToRegExpSource(alt)).join('|')})`;
        i = j + 1;
        continue;
      }
      out += '\\{';
      i += 1;
      continue;
    }
    out += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    i += 1;
  }
  return out;
}

export function globToRegExp(pattern: string): RegExp {
  let normalized = toPosixPath(pattern);
  while (normalized.startsWith('./')) {
    normalized = normalized.slice(2);
  }
  if (normalized.startsWith('/')) {
    normalized = normalized.slice(1);
  }
  return new RegExp(`^${globFragmentToRegExpSource(normalized)}$`);
}

export class ConfinedFsService {
  stat(params: { binding: SessionBinding; path: string; maskEnvSecrets?: boolean }): {
    exists: boolean;
    kind: 'file' | 'dir' | 'symlink' | 'other' | 'missing';
    size: number;
    mtimeMs: number;
    maskedEnv: boolean;
  } {
    const res = resolveConfinedFsPath(params.binding, params.path, false, { allowDanglingSymlink: true });
    const st = lstatOrNull(res.realPath);
    if (!st) {
      return { exists: false, kind: 'missing', size: 0, mtimeMs: 0, maskedEnv: false };
    }
    const maskedEnv = !res.insideShare && isMaskedEnvRead(
      res.rootReal,
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
      res.rootReal,
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

    const { content: raw } = readUtf8RegularFile(res.realPath, params.path, MAX_READ_FILE_BYTES);
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
    const existing = lstatOrNull(res.realPath);
    const mode = existing && !existing.isSymbolicLink() && existing.isFile() ? (existing.mode & 0o777) : 0o644;
    const bytesWritten = atomicWriteNoFollow(res.realPath, params.content, mode);
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
    const { content, mode } = readUtf8RegularFile(res.realPath, params.path, MAX_READ_FILE_BYTES);
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
    atomicWriteNoFollow(res.realPath, updated, mode);
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

  async grep(params: {
    binding: SessionBinding;
    query: string;
    cwd?: string;
    regex?: boolean;
    maxMatches?: number;
    maskEnvSecrets?: boolean;
  }): Promise<{ matches: GrepMatch[]; truncated: boolean }> {
    const base = resolveConfinedFsPath(params.binding, params.cwd ?? params.binding.cwd, true);
    const cap = Math.min(500, Math.max(1, params.maxMatches ?? 100));
    const maskEnv = params.maskEnvSecrets !== false;

    let jsMatcher: RegExp | null = null;
    if (params.regex) {
      try {
        jsMatcher = new RegExp(params.query);
      } catch (err) {
        failSandbox(
          'INVALID_ACTION',
          `Invalid regex pattern in grep: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }

    // Prefer non-blocking ripgrep (`rg --json`) inside distro if available
    const rgArgs = ['--no-config', '--no-follow', '--json', '--max-count=50', '--max-columns=1000'];
    if (!params.regex) rgArgs.push('--fixed-strings');
    rgArgs.push('--', params.query, base.realPath);

    const rgOutcome = await new Promise<{
      spawned: boolean;
      status: number | null;
      stdout: string;
      stderr: string;
      truncatedOutput: boolean;
    }>((resolve) => {
      const child = spawn('rg', rgArgs, { stdio: ['ignore', 'pipe', 'pipe'], shell: false });
      const outChunks: Buffer[] = [];
      const errChunks: Buffer[] = [];
      let outBytes = 0;
      let errBytes = 0;
      let truncatedOutput = false;
      let settled = false;

      const timer = setTimeout(() => {
        truncatedOutput = true;
        try {
          child.kill('SIGKILL');
        } catch {
          // ignore
        }
      }, 15_000);
      timer.unref();

      child.stdout?.on('data', (chunk: Buffer) => {
        if (outBytes < MAX_RG_STDOUT_BYTES) {
          const take = Math.min(chunk.length, MAX_RG_STDOUT_BYTES - outBytes);
          outChunks.push(chunk.subarray(0, take));
          outBytes += take;
          if (take < chunk.length) {
            truncatedOutput = true;
            try {
              child.kill('SIGKILL');
            } catch {
              // ignore
            }
          }
        }
      });
      child.stderr?.on('data', (chunk: Buffer) => {
        if (errBytes < 16 * 1024) {
          errChunks.push(chunk.subarray(0, 16 * 1024 - errBytes));
          errBytes += chunk.length;
        }
      });

      child.once('error', () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve({ spawned: false, status: null, stdout: '', stderr: '', truncatedOutput: false });
      });

      child.once('close', (code) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve({
          spawned: true,
          status: code,
          stdout: Buffer.concat(outChunks).toString('utf8'),
          stderr: Buffer.concat(errChunks).toString('utf8'),
          truncatedOutput,
        });
      });
    });

    if (rgOutcome.spawned) {
      if (rgOutcome.status === 2) {
        failSandbox(
          'INVALID_ACTION',
          `Invalid grep query (${rgOutcome.stderr.trim() || 'exit 2'})`,
        );
      }
      if (rgOutcome.status === 0 || rgOutcome.status === 1 || rgOutcome.truncatedOutput) {
        const matches: GrepMatch[] = [];
        let truncated = rgOutcome.truncatedOutput;
        const lines = rgOutcome.stdout.split('\n').filter(Boolean);
        for (const line of lines) {
          let parsed: {
            type?: string;
            data?: {
              path?: { text?: string };
              line_number?: number;
              lines?: { text?: string };
            };
          };
          try {
            parsed = JSON.parse(line) as typeof parsed;
          } catch {
            continue;
          }
          if (parsed.type !== 'match' || !parsed.data) continue;
          const rawFile = parsed.data.path?.text;
          if (!rawFile) continue;
          const rawPosix = toPosixPath(rawFile);
          const candidatePath = isAbsolutePosixOrWin(rawPosix)
            ? rawPosix
            : posix.join(base.realPath, rawPosix);
          let realFile: string;
          try {
            realFile = toPosixPath(fs.realpathSync(candidatePath));
          } catch {
            continue;
          }
          if (!isPathInside(base.rootReal, realFile)) {
            continue;
          }
          if (!base.insideShare && isMaskedEnvRead(base.rootReal, realFile, maskEnv)) {
            continue;
          }
          if (matches.length >= cap) {
            truncated = true;
            break;
          }
          const rawLineText = parsed.data.lines?.text ?? '';
          const text = rawLineText.replace(/\r?\n$/, '');
          matches.push({
            file: posix.relative(base.realPath, realFile),
            line: typeof parsed.data.line_number === 'number' ? parsed.data.line_number : 0,
            text,
          });
        }
        return { matches, truncated };
      }
    }

    // Pure JS fallback when `rg` is not installed
    const matches: GrepMatch[] = [];
    let truncated = false;
    const { matches: files } = this.glob({
      binding: params.binding,
      pattern: '**',
      cwd: params.cwd ?? params.binding.cwd,
      maxResults: 1000,
    });
    for (const rel of files) {
      if (truncated) break;
      const full = posix.join(base.realPath, rel);
      if (!base.insideShare && isMaskedEnvRead(base.rootReal, full, maskEnv)) continue;
      let content: string;
      try {
        content = readUtf8RegularFile(full, rel, 2 * 1024 * 1024).content;
      } catch {
        continue;
      }
      const lines = content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const text = lines[i]!;
        const hit = jsMatcher ? jsMatcher.test(text) : text.includes(params.query);
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
    const res = resolveConfinedFsPath(params.binding, params.path, true, { allowDanglingSymlink: true });
    assertWriteAllowed(params.binding, res, params.path);
    if (res.realPath === res.rootReal) {
      failSandbox('POLICY_BLOCK', 'Cannot delete workspaceRoot itself');
    }
    const st = fs.lstatSync(res.realPath);
    if (st.isDirectory()) {
      failSandbox('INVALID_ACTION', `Refusing non-recursive delete of directory: ${params.path}`);
    }
    fs.unlinkSync(res.realPath);
    return { deleted: true };
  }

  move(params: { binding: SessionBinding; from: string; to: string }): { moved: true } {
    const src = resolveConfinedFsPath(params.binding, params.from, true, { allowDanglingSymlink: true });
    const dst = resolveConfinedFsPath(params.binding, params.to, false, { allowDanglingSymlink: false });
    assertWriteAllowed(params.binding, src, params.from);
    assertWriteAllowed(params.binding, dst, params.to);
    if (src.realPath === src.rootReal) {
      failSandbox('POLICY_BLOCK', 'Cannot move workspaceRoot itself');
    }
    fs.mkdirSync(posix.dirname(dst.realPath), { recursive: true });
    fs.renameSync(src.realPath, dst.realPath);
    return { moved: true };
  }
}
