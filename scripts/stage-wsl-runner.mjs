#!/usr/bin/env node
/**
 * 通过纯 Node.js POSIX ustar 归档流与 `wsl.exe -d <Distro> --cd ~ -- sh -c ...`，
 * 将已编译的 `dist/` Runner 与 `packages/bootstrap/provision-wsl.sh` 直接部署进
 * WSL 原生 `ext4`（`$HOME/.local/share/dsh-wsl-sandbox/runner/`）。
 *
 * 设计原因：
 * 1. 零 `/mnt/c` 依赖（即使在 `[automount] enabled = false` 下也可正常部署）。
 * 2. 兼容经 WSL Manager 导入/迁移磁盘后从 Windows 资源管理器左侧栏消失的实例。
 * 3. 不在宿主机插件目录留下任何 Windows NTFS 打开句柄锁，卸载/禁用插件绝不卡死文件夹。
 * 4. 规避 Windows PowerShell 5.1 管道二进制损毁问题，且 WSL 侧仅需基础 `sh` + `tar`（无需预装 Node）。
 */
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

function resolveDefaultRepoRoot() {
  let cur = path.resolve(import.meta.dirname);
  for (let i = 0; i < 6; i++) {
    const pkgPath = path.join(cur, 'package.json');
    if (fs.existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
        if (pkg && pkg.name === 'dsh-wsl-sandbox') {
          return cur;
        }
      } catch {
        // continue walking up
      }
    }
    const parent = path.dirname(cur);
    if (parent === cur) break;
    cur = parent;
  }
  return path.resolve(import.meta.dirname, '..');
}

const ROOT = resolveDefaultRepoRoot();
const VALID_LINUX_USERNAME_RE = /^[a-z_][a-z0-9_.-]{0,31}$/;

function isValidDistro(value) {
  if (typeof value !== 'string') return false;
  if (value.length === 0 || value.length > 128) return false;
  if (value.trim() !== value) return false;
  if (value === '.' || value === '..') return false;
  return !/[\x00-\x1f\x7f/\\:*?"<>|]/.test(value);
}

function validateTargetSubdir(rawSubdir) {
  const subdir = (rawSubdir ?? '.local/share/dsh-wsl-sandbox/runner').replace(/\\/g, '/').replace(/\/+$/, '');
  if (!subdir || subdir.startsWith('/') || subdir.includes('\0') || /[\r\n]/.test(subdir)) {
    throw new Error(`Invalid targetSubdir: ${String(rawSubdir)}`);
  }
  const parts = subdir.split('/');
  if (parts.some((p) => p === '' || p === '.' || p === '..')) {
    throw new Error(`Unsafe targetSubdir path traversal: ${subdir}`);
  }
  return subdir;
}

function writeOctal(buf, offset, length, value) {
  const oct = value.toString(8).padStart(length - 1, '0');
  buf.write(oct.slice(-(length - 1)) + '\0', offset, length, 'ascii');
}

export function createTarHeader(relPath, size, mode, typeFlag = '0') {
  const cleanPath = relPath.replace(/\\/g, '/').replace(/^\/+/, '').replace(/\/+/g, '/');
  let name = cleanPath;
  let prefix = '';

  if (Buffer.byteLength(cleanPath, 'utf8') > 100) {
    let splitIdx = -1;
    for (let i = cleanPath.indexOf('/'); i !== -1; i = cleanPath.indexOf('/', i + 1)) {
      const candPrefix = cleanPath.slice(0, i);
      const candName = cleanPath.slice(i + 1);
      if (
        candPrefix.length > 0 &&
        candName.length > 0 &&
        Buffer.byteLength(candPrefix, 'utf8') <= 155 &&
        Buffer.byteLength(candName, 'utf8') <= 100
      ) {
        splitIdx = i;
      }
    }
    if (splitIdx === -1) {
      throw new Error(`Path too long for POSIX ustar tar header: ${cleanPath}`);
    }
    prefix = cleanPath.slice(0, splitIdx);
    name = cleanPath.slice(splitIdx + 1);
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

  let pkgVersion = '0.0.0';
  const pkgAbs = path.join(repoRoot, 'package.json');
  if (fs.existsSync(pkgAbs)) {
    const rawPkg = fs.readFileSync(pkgAbs);
    try {
      const parsed = JSON.parse(rawPkg.toString('utf8'));
      if (typeof parsed.version === 'string' && parsed.version.trim()) {
        pkgVersion = parsed.version.trim();
      }
    } catch {
      // ignore invalid package.json
    }
    entries.push({ path: 'package.json', content: rawPkg, mode: 0o644 });
  }

  const provRel = 'packages/bootstrap/provision-wsl.sh';
  const provAbs = path.join(repoRoot, provRel);
  if (fs.existsSync(provAbs)) {
    const lfText = fs.readFileSync(provAbs, 'utf8').replace(/\r\n/g, '\n').replace(/\r/g, '');
    entries.push({ path: provRel, content: Buffer.from(lfText, 'utf8'), mode: 0o755 });
  }

  entries.push({
    path: '.staged-version',
    content: Buffer.from(`${pkgVersion}\n`, 'utf8'),
    mode: 0o644,
  });

  return { entries, version: pkgVersion };
}

function buildStageInvocation(options) {
  const distro = options?.distro;
  const username = options?.username;
  const repoRoot = options?.repoRoot ?? ROOT;
  const targetSubdir = validateTargetSubdir(options?.targetSubdir);
  const wslExecutable = options?.wslExecutable ?? 'wsl.exe';
  const dryRun = Boolean(options?.dryRun);

  if (!isValidDistro(distro)) {
    throw new Error(`Missing or invalid --distro: ${String(distro ?? '')}`);
  }
  if (username !== undefined && username !== '' && !VALID_LINUX_USERNAME_RE.test(username)) {
    throw new Error(`Invalid WSL Linux username: ${username}`);
  }

  const { entries, version } = collectFiles(repoRoot);
  const tarBuf = buildTarBuffer(entries);

  const shCmd = [
    'cd "$HOME" 2>/dev/null || true',
    'set -eu',
    'umask 077',
    'SUBDIR="$1"',
    'TARGET="$HOME/$SUBDIR"',
    'PARENT="$(dirname "$TARGET")"',
    'mkdir -p "$PARENT"',
    'chmod 700 "$PARENT" 2>/dev/null || true',
    'TMP_DIR="$TARGET.tmp.$$"',
    'OLD_DIR="$TARGET.old.$$"',
    'rm -rf "$TMP_DIR" "$OLD_DIR"',
    'mkdir -p "$TMP_DIR"',
    'chmod 700 "$TMP_DIR"',
    'tar -xf - -C "$TMP_DIR"',
    'PROV="$TMP_DIR/packages/bootstrap/provision-wsl.sh"',
    'if [ -f "$PROV" ]; then tr -d "\\r" < "$PROV" > "$PROV.lf" && mv "$PROV.lf" "$PROV" && chmod 700 "$PROV"; fi',
    'if [ -d "$TARGET" ]; then mv "$TARGET" "$OLD_DIR"; fi',
    'if ! mv "$TMP_DIR" "$TARGET"; then if [ -d "$OLD_DIR" ] && [ ! -e "$TARGET" ]; then mv "$OLD_DIR" "$TARGET" || true; fi; rm -rf "$TMP_DIR" || true; exit 1; fi',
    'if [ -d "$OLD_DIR" ]; then chmod -R u+w "$OLD_DIR" 2>/dev/null || true; rm -rf "$OLD_DIR"; fi',
    'printf "%s\\n" "$TARGET"',
  ].join(' && ');

  const args = ['-d', distro, '--cd', '~'];
  if (username) {
    args.push('-u', username);
  }
  args.push('--', 'sh', '-c', shCmd, 'stage-wsl', targetSubdir);

  return {
    distro,
    username,
    version,
    targetSubdir,
    wslExecutable,
    dryRun,
    entries,
    tarBuf,
    args,
  };
}

function formatResult(plan, stagedRoot) {
  return {
    distro: plan.distro,
    ...(plan.username ? { username: plan.username } : {}),
    version: plan.version,
    fileCount: plan.entries.length,
    tarBytes: plan.tarBuf.length,
    stagedRoot,
    runnerPath: `${stagedRoot}/dist/packages/wsl-runner/src/main.js`,
    doctorPath: `${stagedRoot}/dist/packages/bootstrap/src/doctor.js`,
    provisionScriptPath: `${stagedRoot}/packages/bootstrap/provision-wsl.sh`,
    ...(plan.dryRun ? { dryRun: true, wslExecutable: plan.wslExecutable, args: plan.args } : {}),
  };
}

function assertAllowedHostWslSpawn(wslExecutable) {
  if (
    process.env.DSH_WSL_NO_HOST_SPAWN === '1' &&
    /^(?:wsl|wsl\.exe)$/i.test(path.basename(String(wslExecutable ?? 'wsl.exe')))
  ) {
    throw new Error('Spawning host wsl.exe is disabled under DSH_WSL_NO_HOST_SPAWN=1');
  }
}

export function stageRunnerIntoWsl(options) {
  const plan = buildStageInvocation(options);
  if (plan.dryRun) {
    return formatResult(plan, `$HOME/${plan.targetSubdir}`);
  }
  assertAllowedHostWslSpawn(plan.wslExecutable);

  const res = spawnSync(plan.wslExecutable, plan.args, {
    input: plan.tarBuf,
    maxBuffer: 16 * 1024 * 1024,
    timeout: 60_000,
    windowsHide: true,
  });

  if (res.error) {
    throw res.error;
  }
  if (res.status !== 0) {
    const errOut = Buffer.isBuffer(res.stderr) ? res.stderr.toString('utf8') : String(res.stderr ?? '');
    throw new Error(`Failed to stage runner into WSL distro '${plan.distro}' (exit ${res.status}): ${errOut.trim()}`);
  }
  const stagedRoot = (Buffer.isBuffer(res.stdout) ? res.stdout.toString('utf8') : String(res.stdout ?? ''))
    .trim()
    .split(/\r?\n/)
    .pop() || '';
  return formatResult(plan, stagedRoot);
}

export async function stageRunnerIntoWslAsync(options) {
  const plan = buildStageInvocation(options);
  if (plan.dryRun) {
    return formatResult(plan, `$HOME/${plan.targetSubdir}`);
  }
  assertAllowedHostWslSpawn(plan.wslExecutable);

  return new Promise((resolve, reject) => {
    const child = spawn(plan.wslExecutable, plan.args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      shell: false,
      windowsHide: true,
    });

    const stdoutChunks = [];
    const stderrChunks = [];
    let settled = false;

    const finishErr = (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    };

    const timer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch { /* ignore */ }
      finishErr(new Error(`Timed out staging runner into WSL distro '${plan.distro}'`));
    }, 60_000);
    timer.unref();

    child.stdin.on('error', () => {});
    child.stdout.on('data', (c) => stdoutChunks.push(c));
    child.stderr.on('data', (c) => stderrChunks.push(c));
    child.once('error', finishErr);

    child.once('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (code !== 0) {
        const errOut = Buffer.concat(stderrChunks).toString('utf8').trim();
        reject(new Error(`Failed to stage runner into WSL distro '${plan.distro}' (exit ${code}): ${errOut}`));
        return;
      }
      const stagedRoot = Buffer.concat(stdoutChunks).toString('utf8').trim().split(/\r?\n/).pop() || '';
      resolve(formatResult(plan, stagedRoot));
    });

    child.stdin.end(plan.tarBuf);
  });
}

const isDirectRun = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(import.meta.filename);
if (isDirectRun) {
  const args = process.argv.slice(2);
  const readFlag = (name) => {
    const idx = args.indexOf(name);
    return idx !== -1 ? args[idx + 1] : undefined;
  };
  const distro = readFlag('--distro') ?? '';
  const username = readFlag('--username');
  const targetSubdir = readFlag('--target-subdir');
  const dryRun = args.includes('--dry-run');
  const asJson = args.includes('--json');
  const result = stageRunnerIntoWsl({ distro, username, targetSubdir, dryRun });
  if (asJson) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else {
    process.stdout.write(`${result.runnerPath}\n`);
  }
}
