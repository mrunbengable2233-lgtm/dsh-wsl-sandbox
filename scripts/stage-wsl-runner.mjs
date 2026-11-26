#!/usr/bin/env node
/**
 * Stages the built `dist/` runner bundle and `packages/bootstrap/provision-wsl.sh`
 * directly into native WSL ext4 (`$HOME/.local/share/dsh-wsl-sandbox/runner/`) via
 * a pure-JS POSIX ustar tar stream piped to `wsl.exe -d <Distro> --cd ~ -- sh -c ...`.
 *
 * Why this exists:
 * 1. Works with ZERO `/mnt/c` dependency (works even when `[automount] enabled = false`).
 * 2. Works seamlessly with WSL Manager imported/moved VHDX instances that disappear from
 *    Windows Explorer's left "Linux" sidebar.
 * 3. Holds ZERO Windows NTFS file handles on the host plugin directory (prevents undeletable
 *    folder locks when disabling or uninstalling the plugin).
 * 4. Avoids Windows PowerShell 5.1 binary pipeline corruption (`tar | wsl` breaks in PS 5.1).
 * 5. Requires only POSIX `sh` + `tar` inside WSL (works before Node.js is installed in WSL).
 */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '..');

function writeOctal(buf, offset, length, value) {
  const oct = value.toString(8).padStart(length - 1, '0');
  buf.write(oct.slice(-(length - 1)) + '\0', offset, length, 'ascii');
}

export function createTarHeader(relPath, size, mode, typeFlag = '0') {
  const cleanPath = relPath.replace(/\\/g, '/').replace(/^\/+/, '');
  let name = cleanPath;
  let prefix = '';
  if (Buffer.byteLength(cleanPath, 'utf8') > 100) {
    const idx = cleanPath.lastIndexOf('/');
    if (idx === -1 || idx > 155 || cleanPath.length - idx - 1 > 100) {
      throw new Error(`Path too long for POSIX ustar tar header: ${cleanPath}`);
    }
    prefix = cleanPath.slice(0, idx);
    name = cleanPath.slice(idx + 1);
  }

  const header = Buffer.alloc(512, 0);
  header.write(name, 0, 100, 'utf8');
  writeOctal(header, 100, 8, mode);
  writeOctal(header, 108, 8, 0); // uid
  writeOctal(header, 116, 8, 0); // gid
  writeOctal(header, 124, 12, size);
  writeOctal(header, 136, 12, Math.floor(Date.now() / 1000));
  header.fill(0x20, 148, 156); // checksum placeholder spaces
  header.write(typeFlag, 156, 1, 'ascii');
  header.write('ustar\0', 257, 6, 'ascii');
  header.write('00', 263, 2, 'ascii');
  if (prefix) {
    header.write(prefix, 345, 155, 'utf8');
  }

  let checksum = 0;
  for (let i = 0; i < 512; i++) checksum += header[i];
  const chkStr = checksum.toString(8).padStart(6, '0') + '\0 ';
  header.write(chkStr, 148, 8, 'ascii');
  return header;
}

export function buildTarBuffer(entries) {
  const chunks = [];
  for (const entry of entries) {
    const data = Buffer.isBuffer(entry.content) ? entry.content : Buffer.from(entry.content, 'utf8');
    const mode = entry.mode ?? 0o644;
    chunks.push(createTarHeader(entry.path, data.length, mode, '0'));
    if (data.length > 0) {
      chunks.push(data);
      const rem = data.length % 512;
      if (rem !== 0) {
        chunks.push(Buffer.alloc(512 - rem, 0));
      }
    }
  }
  // Two 512-byte zero blocks mark end-of-archive
  chunks.push(Buffer.alloc(1024, 0));
  return Buffer.concat(chunks);
}

function collectFiles(repoRoot) {
  const entries = [];
  const walkDir = (absDir) => {
    for (const ent of fs.readdirSync(absDir, { withFileTypes: true })) {
      if (ent.name === '.compiled-tests') continue;
      const full = path.join(absDir, ent.name);
      if (ent.isDirectory()) {
        walkDir(full);
      } else if (ent.isFile()) {
        const rel = path.relative(repoRoot, full).replace(/\\/g, '/');
        const content = fs.readFileSync(full);
        const isExec = rel.endsWith('.sh') || content.subarray(0, 2).toString('ascii') === '#!';
        entries.push({ path: rel, content, mode: isExec ? 0o755 : 0o644 });
      }
    }
  };

  const distDir = path.join(repoRoot, 'dist');
  if (!fs.existsSync(distDir)) {
    throw new Error(`dist/ not found under ${repoRoot}. Run 'node scripts/build.mjs' first.`);
  }
  walkDir(distDir);

  for (const extraRel of ['package.json', 'packages/bootstrap/provision-wsl.sh']) {
    const abs = path.join(repoRoot, extraRel);
    if (fs.existsSync(abs)) {
      let content = fs.readFileSync(abs);
      if (extraRel.endsWith('.sh')) {
        // Normalize CRLF -> LF in case repo was cloned on Windows with core.autocrlf=true
        content = Buffer.from(content.toString('utf8').replace(/\r\n/g, '\n'), 'utf8');
      }
      entries.push({
        path: extraRel,
        content,
        mode: extraRel.endsWith('.sh') ? 0o755 : 0o644,
      });
    }
  }
  return entries;
}

export function stageRunnerIntoWsl(options) {
  const distro = options.distro;
  const repoRoot = options.repoRoot ?? ROOT;
  const targetSubdir = options.targetSubdir ?? '.local/share/dsh-wsl-sandbox/runner';
  if (!distro || !distro.trim()) {
    throw new Error('Missing --distro <name>');
  }

  const entries = collectFiles(repoRoot);
  const tarBuf = buildTarBuffer(entries);
  const shCmd = [
    'set -eu',
    'umask 077',
    `TARGET="$HOME/${targetSubdir}"`,
    'mkdir -p "$HOME/.local/share/dsh-wsl-sandbox"',
    'chmod 700 "$HOME/.local/share/dsh-wsl-sandbox"',
    'rm -rf "$TARGET"',
    'mkdir -p "$TARGET"',
    'chmod 700 "$TARGET"',
    'tar -xf - -C "$TARGET"',
    'if [ -f "$TARGET/packages/bootstrap/provision-wsl.sh" ]; then chmod 700 "$TARGET/packages/bootstrap/provision-wsl.sh"; fi',
    'printf "%s\\n" "$TARGET"',
  ].join(' && ');

  const res = spawnSync('wsl.exe', ['-d', distro, '--cd', '~', '--', 'sh', '-c', shCmd], {
    input: tarBuf,
    maxBuffer: 16 * 1024 * 1024,
    timeout: 60_000,
    windowsHide: true,
  });

  if (res.error) {
    throw res.error;
  }
  if (res.status !== 0) {
    const errOut = Buffer.isBuffer(res.stderr) ? res.stderr.toString('utf8') : String(res.stderr ?? '');
    throw new Error(`Failed to stage runner into WSL distro '${distro}' (exit ${res.status}): ${errOut.trim()}`);
  }
  const stagedRoot = (Buffer.isBuffer(res.stdout) ? res.stdout.toString('utf8') : String(res.stdout ?? '')).trim().split(/\r?\n/).pop() || '';
  return {
    distro,
    fileCount: entries.length,
    tarBytes: tarBuf.length,
    stagedRoot,
    runnerPath: `${stagedRoot}/dist/packages/wsl-runner/src/main.js`,
    doctorPath: `${stagedRoot}/dist/packages/bootstrap/src/doctor.js`,
    provisionScriptPath: `${stagedRoot}/packages/bootstrap/provision-wsl.sh`,
  };
}

const isDirectRun = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(import.meta.filename);
if (isDirectRun) {
  const args = process.argv.slice(2);
  const dIdx = args.indexOf('--distro');
  const distro = dIdx !== -1 ? args[dIdx + 1] : '';
  const asJson = args.includes('--json');
  const result = stageRunnerIntoWsl({ distro });
  if (asJson) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else {
    process.stdout.write(`${result.runnerPath}\n`);
  }
}
