import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import {
  buildBwrapArgs,
  compileSeccompBpf,
  DANGEROUS_DIRECTORIES,
  DANGEROUS_FILES,
  DEFAULT_RLIMITS,
  evaluateBashCommand,
  isPrivateOrLoopbackIp,
  isProtectedWorkspaceWrite,
  RotatingNdjsonSink,
  SandboxError,
  sanitizeSandboxEnv,
  type SessionBinding,
  StructuredLogger,
  UdsAllowlistProxy,
} from '../../packages/core/src/index.ts';
import { ConfinedFsService, globToRegExp } from '../../packages/wsl-runner/src/fs-service.ts';
import { IS_WINDOWS } from '../test-env.ts';

function makeBinding(workspaceRoot: string, overrides?: Partial<SessionBinding>): SessionBinding {
  return {
    sessionId: 'stage2-sess',
    backend: 'wsl',
    wslVersion: 2,
    distribution: 'Ubuntu-26.04',
    uid: process.getuid ? process.getuid() : 1000,
    username: 'dev',
    arch: process.arch === 'arm64' ? 'aarch64' : 'x86_64',
    workspaceRoot,
    cwd: workspaceRoot,
    profile: 'workspace-write',
    revision: 'rev-stage2',
    generation: 1,
    runnerId: 'runner-stage2',
    sandboxReady: true,
    enforcement: 'full',
    supportsDisableUserns: true,
    probedSockets: [],
    authorizedShares: [],
    authorizedDevices: [],
    ...overrides,
  };
}

function tryCreateSymlink(target: string, linkPath: string, type: 'file' | 'dir' = 'file'): boolean {
  try {
    fs.symlinkSync(target, linkPath, type);
    return true;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (IS_WINDOWS && (code === 'EPERM' || code === 'EACCES')) {
      return false;
    }
    throw err;
  }
}

describe('Stage 2 ConfinedFsService & globToRegExp hardening', () => {
  it('globToRegExp handles **/, /**, brace groups, escaped brackets, and leading ./', () => {
    const tsDeep = globToRegExp('**/*.ts');
    assert.equal(tsDeep.test('index.ts'), true);
    assert.equal(tsDeep.test('src/app/index.ts'), true);
    assert.equal(tsDeep.test('src/app/index.tsx'), false);

    const braceGlob = globToRegExp('./src/**/*.{ts,mts}');
    assert.equal(braceGlob.test('src/main.ts'), true);
    assert.equal(braceGlob.test('src/nested/util.mts'), true);
    assert.equal(braceGlob.test('src/nested/util.js'), false);

    const midDouble = globToRegExp('a/**/b/**');
    assert.equal(midDouble.test('a/b'), true);
    assert.equal(midDouble.test('a/b/c'), true);
    assert.equal(midDouble.test('a/x/y/b/c/d'), true);
    assert.equal(midDouble.test('a/x/c'), false);

    const brackets = globToRegExp('app/[id]/page.tsx');
    assert.equal(brackets.test('app/[id]/page.tsx'), true);
    assert.equal(brackets.test('app/i/page.tsx'), false);
  });

  it('rejects binary NUL bytes, directory read/non-recursive delete, colon filenames in grep, and invalid regex', async () => {
    const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-stage2-fs-'));
    try {
      const binding = makeBinding(ws);
      const svc = new ConfinedFsService();

      fs.mkdirSync(path.join(ws, 'sub'), { recursive: true });
      fs.writeFileSync(path.join(ws, 'bin.dat'), Buffer.from([0x41, 0x00, 0x42, 0x43]));
      fs.writeFileSync(path.join(ws, 'sub', 'plain.txt'), 'needle_value\n');
      if (!IS_WINDOWS) {
        fs.writeFileSync(path.join(ws, 'sub', 'foo:bar.ts'), 'const tag = "colon_needle";\n');
      }

      assert.throws(
        () => svc.read({ binding, path: 'sub' }),
        (err: unknown) => err instanceof SandboxError && err.code === 'INVALID_ACTION',
      );
      assert.throws(
        () => svc.read({ binding, path: 'bin.dat' }),
        (err: unknown) => err instanceof SandboxError && err.code === 'INVALID_ACTION',
      );
      assert.throws(
        () => svc.edit({ binding, path: 'bin.dat', oldText: 'A', newText: 'B' }),
        (err: unknown) => err instanceof SandboxError && err.code === 'INVALID_ACTION',
      );
      assert.throws(
        () => svc.delete({ binding, path: 'sub' }),
        (err: unknown) => err instanceof SandboxError && err.code === 'INVALID_ACTION',
      );

      await assert.rejects(
        () => svc.grep({ binding, query: '[unclosed', regex: true }),
        (err: unknown) => err instanceof SandboxError && err.code === 'INVALID_ACTION',
      );

      const g1 = await svc.grep({ binding, query: 'needle_value' });
      assert.equal(g1.matches.length, 1);
      assert.equal(g1.matches[0]?.file, 'sub/plain.txt');

      if (!IS_WINDOWS) {
        const gColon = await svc.grep({ binding, query: 'colon_needle' });
        assert.equal(gColon.matches.length, 1);
        assert.equal(gColon.matches[0]?.file, 'sub/foo:bar.ts');
      }
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
    }
  });

  it('runs grep pure-JS fallback cleanly inside authorized /shares/<alias> without POLICY_BLOCK', async () => {
    const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-stage2-share-ws-'));
    const shareDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-stage2-share-ro-'));
    const origPath = process.env.PATH;
    try {
      fs.writeFileSync(path.join(shareDir, 'note.txt'), 'share_fallback_needle\n', 'utf8');
      const binding = makeBinding(ws, {
        authorizedShares: [
          {
            id: 'sh-docs',
            alias: 'docs',
            sourceLinuxPath: shareDir.replace(/\\/g, '/'),
            mode: 'ro',
          },
        ],
      });
      const svc = new ConfinedFsService();
      // Force `spawn('rg', ...)` ENOENT so the pure-JS grep fallback path executes
      process.env.PATH = '';
      const res = await svc.grep({ binding, query: 'share_fallback_needle', cwd: '/shares/docs' });
      assert.equal(res.matches.length, 1);
      assert.equal(res.matches[0]?.file, 'note.txt');
      assert.equal(res.matches[0]?.line, 1);
      assert.equal(res.matches[0]?.text, 'share_fallback_needle');
    } finally {
      if (origPath === undefined) {
        delete process.env.PATH;
      } else {
        process.env.PATH = origPath;
      }
      fs.rmSync(ws, { recursive: true, force: true });
      fs.rmSync(shareDir, { recursive: true, force: true });
    }
  });

  it('handles dangling symlinks safely across stat, read, write, edit, delete, and move', (t) => {
    const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-stage2-dangling-'));
    try {
      const linkPath = path.join(ws, 'broken.link');
      if (!tryCreateSymlink(path.join(ws, 'does-not-exist'), linkPath, 'file')) {
        t.skip('Windows file symlinks require Developer Mode or SeCreateSymbolicLinkPrivilege');
        return;
      }

      const binding = makeBinding(ws);
      const svc = new ConfinedFsService();

      const st = svc.stat({ binding, path: 'broken.link' });
      assert.equal(st.exists, true);
      assert.equal(st.kind, 'symlink');

      assert.throws(
        () => svc.read({ binding, path: 'broken.link' }),
        (err: unknown) => err instanceof SandboxError && err.code === 'POLICY_BLOCK',
      );
      assert.throws(
        () => svc.write({ binding, path: 'broken.link', content: 'x' }),
        (err: unknown) => err instanceof SandboxError && err.code === 'POLICY_BLOCK',
      );
      assert.throws(
        () => svc.edit({ binding, path: 'broken.link', oldText: 'a', newText: 'b' }),
        (err: unknown) => err instanceof SandboxError && err.code === 'POLICY_BLOCK',
      );

      const mv = svc.move({ binding, from: 'broken.link', to: 'moved.link' });
      assert.equal(mv.moved, true);
      assert.equal(svc.stat({ binding, path: 'broken.link' }).exists, false);
      assert.equal(svc.stat({ binding, path: 'moved.link' }).kind, 'symlink');

      const del = svc.delete({ binding, path: 'moved.link' });
      assert.equal(del.deleted, true);
      assert.equal(svc.stat({ binding, path: 'moved.link' }).exists, false);
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
    }
  });

  it('preserves POSIX executable bit on write/edit and rejects FIFOs non-blocking', { skip: IS_WINDOWS ? 'Requires POSIX chmod bits & mkfifo' : false }, () => {
    const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-stage2-posix-'));
    try {
      const binding = makeBinding(ws);
      const svc = new ConfinedFsService();

      const scriptPath = path.join(ws, 'run.sh');
      fs.writeFileSync(scriptPath, '#!/bin/sh\necho old\n', { mode: 0o755 });
      fs.chmodSync(scriptPath, 0o755);

      svc.edit({ binding, path: 'run.sh', oldText: 'echo old', newText: 'echo new' });
      assert.equal(fs.statSync(scriptPath).mode & 0o777, 0o755);

      svc.write({ binding, path: 'run.sh', content: '#!/bin/sh\necho rewritten\n' });
      assert.equal(fs.statSync(scriptPath).mode & 0o777, 0o755);

      const fifoPath = path.join(ws, 'pipe.fifo');
      const mk = spawnSync('mkfifo', [fifoPath], { encoding: 'utf8' });
      if (mk.status === 0) {
        assert.throws(
          () => svc.read({ binding, path: 'pipe.fifo' }),
          (err: unknown) => err instanceof SandboxError && err.code === 'INVALID_ACTION',
        );
      }
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
    }
  });
});

describe('Stage 2 UDS SSRF IPv6/NAT64 canonicalization & policy preservation', () => {
  it('blocks mapped/compat/NAT64/zone/benchmark/CGNAT IPs while allowing public IPs', () => {
    const blocked = [
      '[::ffff:7f00:1]',
      '[0:0:0:0:0:0:0:1]',
      '[64:ff9b::127.0.0.1]',
      '64:ff9b::a9fe:a9fe',
      'fe80::1%eth0',
      'fc00::1',
      '198.18.0.1',
      '100.64.0.1',
      '224.0.0.1',
      '::ffff:169.254.169.254',
    ];
    for (const ip of blocked) {
      assert.equal(isPrivateOrLoopbackIp(ip), true, `Expected blocked private/loopback IP: ${ip}`);
    }

    const allowed = ['1.1.1.1', '8.8.8.8', '93.184.216.34', '2606:4700:4700::1111'];
    for (const ip of allowed) {
      assert.equal(isPrivateOrLoopbackIp(ip), false, `Expected public IP allowed: ${ip}`);
    }
  });

  it('preserves constructor allowedDomains across updatePolicy calls', () => {
    const proxy = new UdsAllowlistProxy({
      socketPath: path.join(os.tmpdir(), 'unused-stage2.sock'),
      allowedDomains: ['base.example.org'],
      customAllowedDomains: ['first.example.org'],
    });
    assert.equal(proxy.getAllowlistSnapshot().includes('base.example.org'), true);
    assert.equal(proxy.getAllowlistSnapshot().includes('first.example.org'), true);

    proxy.updatePolicy({ customAllowedDomains: ['second.example.org'] });
    assert.equal(proxy.getAllowlistSnapshot().includes('base.example.org'), true);
    assert.equal(proxy.getAllowlistSnapshot().includes('first.example.org'), false);
    assert.equal(proxy.getAllowlistSnapshot().includes('second.example.org'), true);
  });
});

describe('Stage 2 seccomp-bpf & bwrap-builder hardening', () => {
  it('emits valid 8-bit cBPF jump offsets, inline KILL on arch mismatch, ioctl/clone3 filters, and newly blocked syscalls', () => {
    for (const arch of ['x86_64', 'aarch64'] as const) {
      for (const blockNetworkSockets of [true, false]) {
        for (const blockUsernsClone of [true, false]) {
          const buf = compileSeccompBpf({ arch, blockNetworkSockets, blockUsernsClone });
          assert.equal(buf.length % 8, 0);
          const count = buf.length / 8;

          // Instruction 0: LD OFF_ARCH(4), Instr 1: JEQ arch -> arch_ok(jt=1), Instr 2: RET SECCOMP_RET_KILL_PROCESS
          const op0 = buf.readUInt16LE(0);
          const k0 = buf.readUInt32LE(4);
          assert.equal(op0, 0x20);
          assert.equal(k0, 4);
          const retKillOp = buf.readUInt16LE(2 * 8);
          const retKillVal = buf.readUInt32LE(2 * 8 + 4);
          assert.equal(retKillOp, 0x06);
          assert.equal(retKillVal, 0x80000000);

          const constantsSeen = new Set<number>();
          for (let idx = 0; idx < count; idx++) {
            const off = idx * 8;
            const op = buf.readUInt16LE(off);
            const jt = buf.readUInt8(off + 2);
            const jf = buf.readUInt8(off + 3);
            const k = buf.readUInt32LE(off + 4);
            constantsSeen.add(k);
            assert.ok(jt <= 255 && jf <= 255);
            if (op === 0x05) {
              assert.ok(idx + 1 + k < count, `JA out of bounds at ${idx}`);
            } else if (op === 0x15 || op === 0x35) {
              assert.ok(idx + 1 + jt < count, `jt out of bounds at ${idx}`);
              assert.ok(idx + 1 + jf < count, `jf out of bounds at ${idx}`);
            }
          }

          // TIOCSTI & TIOCLINUX + newly blocked syscalls must always be encoded
          assert.equal(constantsSeen.has(0x5412), true);
          assert.equal(constantsSeen.has(0x541c), true);
          assert.equal(constantsSeen.has(431), true); // fsconfig
          assert.equal(constantsSeen.has(433), true); // fspick
          assert.equal(constantsSeen.has(442), true); // mount_setattr
          assert.equal(constantsSeen.has(443), true); // quotactl_fd
          assert.equal(constantsSeen.has(arch === 'x86_64' ? 298 : 241), true); // perf_event_open
          assert.equal(constantsSeen.has(arch === 'x86_64' ? 323 : 282), true); // userfaultfd
          assert.equal(constantsSeen.has(arch === 'x86_64' ? 163 : 89), true); // acct
          assert.equal(constantsSeen.has(arch === 'x86_64' ? 179 : 60), true); // quotactl

          if (blockUsernsClone) {
            assert.equal(constantsSeen.has(0x7e020000), true); // CLONE_NEW* mask
            assert.equal(constantsSeen.has(0x00050000 | 38), true); // SECCOMP_RET_ERRNO | ENOSYS
          }
        }
      }
    }
  });

  it('builds bwrap args for NixOS /run/current-system, symlinked home credentials, /etc/resolv.conf, .git file, broken Checklist B symlink, and read-only workspace', () => {
    assert.deepEqual(DEFAULT_RLIMITS, {
      nproc: 4096,
      nofile: 8192,
      fsizeBytes: 8 * 1024 * 1024 * 1024,
    });

    assert.equal(DANGEROUS_FILES.includes('.envrc'), true);
    assert.equal(DANGEROUS_FILES.includes('.ignore'), true);
    assert.equal(DANGEROUS_FILES.includes('.rgignore'), true);
    assert.equal(DANGEROUS_DIRECTORIES.includes('.claude/settings.json'), true);
    assert.equal(DANGEROUS_DIRECTORIES.includes('.claude/settings.local.json'), true);
    assert.equal(DANGEROUS_DIRECTORIES.includes('.cursor/mcp.json'), true);
    assert.equal(isProtectedWorkspaceWrite('/ws', '/ws/.claude/settings.json').blocked, true);

    const stubLstat = (p: string) => {
      if (p === '/sys') return 'dir';
      if (p === '/bin' || p === '/usr' || p === '/etc') return 'dir';
      if (p === '/run/current-system') return 'symlink';
      if (p === '/etc/resolv.conf') return 'symlink';
      if (p === '/home/dev/.ssh' || p === '/home/dev/.npmrc') return 'symlink';
      if (p === '/ws') return 'dir';
      if (p === '/ws/.git') return 'file';
      if (p === '/ws/.git/worktrees/wt1') return 'dir';
      if (p === '/ws/.bashrc') return 'symlink'; // broken symlink in Checklist B
      return null;
    };
    const stubStat = (p: string) => {
      if (p === '/home/dev/.ssh' || p === '/real/ssh') return 'dir';
      if (p === '/home/dev/.npmrc' || p === '/tmp-outside/npmrc') return 'file';
      if (p === '/run/systemd/resolve/stub-resolv.conf') return 'file';
      return stubLstat(p) === 'symlink' ? null : stubLstat(p);
    };
    const stubExists = (p: string) => {
      if (p === '/ws/.bashrc') return false; // broken!
      if (p === '/run/systemd/resolve/stub-resolv.conf') return true;
      if (p === '/home/dev/.ssh' || p === '/home/dev/.npmrc') return true;
      return stubLstat(p) !== null;
    };
    const stubRealpath = (p: string) => {
      if (p === '/etc/resolv.conf') return '/run/systemd/resolve/stub-resolv.conf';
      if (p === '/home/dev/.ssh') return '/real/ssh';
      if (p === '/home/dev/.npmrc') return '/tmp-outside/npmrc';
      return p;
    };

    const allowProxyBuild = buildBwrapArgs({
      argv: ['/bin/bash', '-c', 'true'],
      cwd: '/ws',
      workspaceRoot: '/ws',
      mode: 'workspace-write',
      networkMode: 'allowlist-proxy',
      supportsDisableUserns: true,
      env: {},
      homeDir: '/home/dev',
      preScannedEnvFiles: [],
      rootEntries: [
        { name: 'bin', kind: 'dir' },
        { name: 'usr', kind: 'dir' },
        { name: 'etc', kind: 'dir' },
      ],
      lstatKind: stubLstat,
      statKind: stubStat,
      existsSync: stubExists,
      realpathSync: stubRealpath,
      readFileSync: (p) => (p === '/ws/.git' ? 'gitdir: /ws/.git/worktrees/wt1\n' : ''),
      emptyMaskFilePath: '/tmp/empty-mask',
      usePrlimit: false,
    });

    const joined = allowProxyBuild.bwrapArgs.join(' ');
    assert.ok(joined.includes('--ro-bind /run/current-system /run/current-system'));
    assert.ok(joined.includes('--ro-bind /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf'));
    assert.ok(joined.includes('--tmpfs /real/ssh --remount-ro /real/ssh'));
    assert.ok(joined.includes('--ro-bind /tmp/empty-mask /tmp-outside/npmrc'));
    assert.equal(allowProxyBuild.maskedConfigPaths.includes('/home/dev/.ssh'), true);
    assert.equal(allowProxyBuild.maskedConfigPaths.includes('/home/dev/.npmrc'), true);
    assert.ok(joined.includes('--ro-bind /ws/.git /ws/.git'));
    assert.ok(joined.includes('--ro-bind /ws/.git/worktrees/wt1 /ws/.git/worktrees/wt1'));
    // Broken Checklist B symlink must be masked read-only WITHOUT being added to createdPlaceholders!
    assert.ok(joined.includes('--ro-bind /tmp/empty-mask /ws/.bashrc'));
    assert.equal(allowProxyBuild.createdPlaceholders.includes('/ws/.bashrc'), false);

    // Verify /run/current-system & /etc/resolv.conf come AFTER --tmpfs /run and --tmpfs /mnt
    const tmpfsMntIdx = allowProxyBuild.bwrapArgs.lastIndexOf('/mnt');
    const resolvIdx = allowProxyBuild.bwrapArgs.indexOf('/etc/resolv.conf');
    assert.ok(resolvIdx > tmpfsMntIdx, '/etc/resolv.conf bind must come after --tmpfs /mnt');

    // Verify offline mode masks /etc/resolv.conf empty and read-only mode binds workspace read-only
    const roOffline = buildBwrapArgs({
      argv: ['/bin/bash', '-c', 'true'],
      cwd: '/ws',
      workspaceRoot: '/ws',
      mode: 'read-only',
      networkMode: 'offline',
      supportsDisableUserns: true,
      env: {},
      homeDir: '/home/dev',
      preScannedEnvFiles: [],
      rootEntries: [
        { name: 'bin', kind: 'dir' },
        { name: 'usr', kind: 'dir' },
        { name: 'etc', kind: 'dir' },
      ],
      lstatKind: stubLstat,
      statKind: stubStat,
      existsSync: stubExists,
      realpathSync: stubRealpath,
      emptyMaskFilePath: '/tmp/empty-mask',
      usePrlimit: false,
    });
    const roJoined = roOffline.bwrapArgs.join(' ');
    assert.ok(roJoined.includes('--ro-bind /tmp/empty-mask /etc/resolv.conf'));
    assert.ok(roJoined.includes('--ro-bind /ws /ws'));
  });
});

describe('Stage 2 env-sanitizer, logger, and here-string bash guard hardening', () => {
  it('preserves benign git/ml token vars, strips linker/npm/case-variant vars, removes ALL_PROXY, and prepends pnpm/cargo bins', () => {
    const out = sanitizeSandboxEnv({
      baseEnv: {
        PATH: '/usr/bin:/bin',
      },
      extraEnv: {
        GIT_AUTHOR_NAME: 'Alice',
        GIT_AUTHOR_EMAIL: 'alice@example.com',
        GIT_COMMITTER_NAME: 'Bob',
        MAX_TOKENS: '4096',
        TOKENIZERS_PARALLELISM: 'false',
        GLIBC_TUNABLES: 'glibc.malloc.check=1',
        NPM_CONFIG_SCRIPT_SHELL: '/tmp/evil',
        ld_preload: '/tmp/evil.so',
        ALL_PROXY: 'socks5://evil:1080',
        all_proxy: 'socks5://evil:1080',
      },
      proxyUrl: 'http://127.0.0.1:41234',
      cacheRootDir: '/tmp/cache-ws',
      homeDir: '/home/dev',
    });

    assert.equal(out.GIT_AUTHOR_NAME, 'Alice');
    assert.equal(out.GIT_AUTHOR_EMAIL, 'alice@example.com');
    assert.equal(out.GIT_COMMITTER_NAME, 'Bob');
    assert.equal(out.MAX_TOKENS, '4096');
    assert.equal(out.TOKENIZERS_PARALLELISM, 'false');
    assert.equal(out.GLIBC_TUNABLES, undefined);
    assert.equal(out.NPM_CONFIG_SCRIPT_SHELL, undefined);
    assert.equal(out.ld_preload, undefined);
    assert.equal(out.ALL_PROXY, undefined);
    assert.equal(out.all_proxy, undefined);
    assert.ok(out.PATH.startsWith('/tmp/cache-ws/pnpm:/tmp/cache-ws/cargo/bin:'));
  });

  it('redacts secrets before truncating, handles throwing getters, keeps distinct sessions in dedupe, retains pending lines on EBUSY, and handles >64KiB single lines in readRecent', () => {
    const logger = new StructuredLogger({ source: 'host', level: 'info', dedupeWindowMs: 5000 });
    const log = logger.child('test');
    const longPrefix = 'A'.repeat(2030);
    const mockGoogleKey = ['AIza', 'SyMockUnitTestOnly00000000000000000'].join('');
    const mockGitlabPat = ['glpat', 'MockUnitTestOnly0000'].join('-');
    const mockBasicAuth = Buffer.from(['mockuser', 'mockpass'].join(':'), 'utf8').toString('base64');
    log.info('redact.order', `${longPrefix} ${mockGoogleKey} ${mockGitlabPat} Basic ${mockBasicAuth}`, {
      circular: (() => {
        const o: Record<string, unknown> = { ok: 1 };
        o.self = o;
        return o;
      })(),
      throwing: {
        get boom(): string {
          throw new Error('getter boom');
        },
      },
    });
    const entry = logger.query({ search: 'redact.order' })[0]!;
    assert.match(entry.message, /\.\.\.\[truncated \d+ chars\]$/);
    assert.equal(entry.message.includes('SyMockUnitTestOnly'), false);
    assert.equal(entry.message.includes('MockUnitTestOnly0000'), false);
    assert.equal(entry.message.includes(mockBasicAuth), false);

    // Distinct sessionIds must NOT suppress one another inside dedupeWindowMs
    log.info('same.event', 'repeated message', undefined, { sessionId: 's1' });
    log.info('same.event', 'repeated message', undefined, { sessionId: 's2' });
    assert.equal(logger.query({ search: 'same.event' }).length, 2);

    // Single line larger than 64 KiB tail preload window must return [] cleanly
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-stage2-log-'));
    try {
      const logFile = path.join(dir, 'bigline.ndjson');
      fs.writeFileSync(logFile, 'X'.repeat(80 * 1024) + '\n', 'utf8');
      const sink = new RotatingNdjsonSink({ logDir: dir, fileName: 'bigline.ndjson', flushIntervalMs: 0 });
      assert.deepEqual(sink.readRecent(), []);

      // Transient EBUSY should preserve pending lines for retry
      const retrySink = new RotatingNdjsonSink({ logDir: dir, fileName: 'retry.ndjson', flushIntervalMs: 0 });
      const origOpen = fs.openSync;
      let shouldFail = true;
      (fs as unknown as { openSync: typeof fs.openSync }).openSync = ((...args: Parameters<typeof fs.openSync>) => {
        if (shouldFail) {
          shouldFail = false;
          throw Object.assign(new Error('resource busy'), { code: 'EBUSY' });
        }
        return origOpen(...args);
      }) as typeof fs.openSync;
      try {
        retrySink.append({
          seq: 1,
          timestamp: new Date().toISOString(),
          level: 'info',
          source: 'host',
          component: 'test',
          event: 'retry.test',
          message: 'survives ebusy',
        });
        assert.equal(fs.existsSync(path.join(dir, 'retry.ndjson')), false);
        retrySink.flushSync();
        assert.match(fs.readFileSync(path.join(dir, 'retry.ndjson'), 'utf8'), /survives ebusy/);
      } finally {
        (fs as unknown as { openSync: typeof fs.openSync }).openSync = origOpen;
      }
      sink.dispose();
      retrySink.dispose();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('denies here-string sudo execution piped to bash in evaluateBashCommand', () => {
    const verdict = evaluateBashCommand('cat <<< "sudo id" | bash', { workspaceRoot: '/ws' });
    assert.equal(verdict.decision, 'deny');
  });
});

describe('Stage 2 stage-wsl-runner.mjs & build.mjs hardening', () => {
  it('handles UTF-8 deep paths in createTarHeader and embeds .staged-version with LF provision script on dryRun', async () => {
    const { createTarHeader, stageRunnerIntoWsl } = await import('../../scripts/stage-wsl-runner.mjs');
    const prefix = 'packages/' + '测试目录/'.repeat(5) + 'sub';
    const leaf = '文件-'.repeat(10) + 'index.js';
    const rel = `${prefix}/${leaf}`;
    const hdr = createTarHeader(rel, 12, 0o644);
    assert.equal(hdr.length, 512);
    const hdrName = hdr.subarray(0, 100).toString('utf8').replace(/\0.*$/, '');
    const hdrPrefix = hdr.subarray(345, 500).toString('utf8').replace(/\0.*$/, '');
    assert.ok(Buffer.byteLength(hdrName, 'utf8') <= 100);
    assert.ok(Buffer.byteLength(hdrPrefix, 'utf8') <= 155);
    assert.equal(`${hdrPrefix}/${hdrName}`, rel);

    const dry = stageRunnerIntoWsl({
      distro: 'Ubuntu-26.04',
      username: 'dev',
      dryRun: true,
    });
    assert.equal(dry.dryRun, true);
    assert.ok(dry.args.includes('-u'));
    assert.ok(dry.args.includes('dev'));
    assert.ok(dry.version.length > 0);
  });

  it('rewrites static, dynamic, and side-effect ESM .ts imports while leaving prose strings untouched', async () => {
    const { rewriteTsSpecifiers } = await import('../../scripts/build.mjs');
    const srcTest = path.resolve('tests/unit/example.test.ts');
    const outTest = path.resolve('.cache/compiled-tests/unit/example.compiled.mjs');
    const input = [
      `import './side-effect.ts';`,
      `import {\n  foo,\n} from '../../packages/core/src/index.ts';`,
      `const mod = await import('../test-env.ts');`,
      `const msg = "Mention './fake.ts' or from './bar.ts' in prose only";`,
      `// import './commented.ts'`,
    ].join('\n');

    const rewritten = rewriteTsSpecifiers(input, srcTest, outTest, true);
    assert.match(rewritten, /import '\.\/side-effect\.mjs';/);
    assert.match(rewritten, /from '\.\.\/\.\.\/\.\.\/dist\/packages\/core\/src\/index\.js';/);
    assert.match(rewritten, /import\('\.\.\/test-env\.mjs'\)/);
    assert.ok(rewritten.includes(`const msg = "Mention './fake.ts' or from './bar.ts' in prose only";`));
    assert.ok(rewritten.includes(`// import './commented.ts'`));
  });

  it('keeps template brace balance across regex literals like /\\//g before subsequent await import()', async () => {
    const { rewriteTsSpecifiers } = await import('../../scripts/build.mjs');
    const srcPkg = path.resolve('packages/dsh-plugin/src/web-api.ts');
    const outPkg = path.resolve('dist/packages/dsh-plugin/src/web-api.js');
    const input = [
      'function fmt(distro, linuxFull) {',
      '  return `\\\\\\\\wsl.localhost\\\\${distro}${linuxFull.replace(/\\//g, \'\\\\\')}`;',
      '}',
      'async function checkDoctor() {',
      '  const { runDoctor } = await import(\'../../bootstrap/src/doctor.ts\');',
      '  return runDoctor();',
      '}',
    ].join('\n');

    const rewritten = rewriteTsSpecifiers(input, srcPkg, outPkg, false);
    assert.ok(rewritten.includes(`replace(/\\//g, '\\\\')`));
    assert.ok(rewritten.includes(`await import('../../bootstrap/src/doctor.js');`));
    assert.equal(rewritten.includes(`doctor.ts`), false);
  });
});
