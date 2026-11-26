import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import {
  buildDefaultSandboxPath,
  buildHostNodeChildEnv,
  buildWslNodeSpawnArgs,
  parseRunnerWireLog,
  RotatingNdjsonSink,
  resolveSharedHostNodeRuntime,
  SandboxError,
  type SessionBinding,
  sanitizeSandboxEnv,
  StructuredLogger,
  validateWslNodeExecutable,
} from '../../packages/core/src/index.ts';
import { apply as applyWslSandbox } from '../../packages/dsh-plugin/src/index.ts';
import { removeAgentsMdWslSection, upsertAgentsMdWslSection } from '../../packages/dsh-plugin/src/prompt-injector.ts';
import { ConfinedFsService } from '../../packages/wsl-runner/src/fs-service.ts';
import {
  resolveEphemeralRamTmpRoot,
  sweepOrphanedRunnerTempDirs,
  writeDeduplicatedReadOnlyBackup,
} from '../../packages/wsl-runner/src/hygiene.ts';
import {
  assertPrivateFileMode,
  BUILT_RUNNER_PATH,
  BWRAP_SKIP_REASON,
  IS_LINUX,
  POSIX_BASH_SKIP_REASON,
  PROVISION_SH_PATH,
} from '../test-env.ts';

describe('StructuredLogger & RotatingNdjsonSink — SSD write coalescing, deduplication, redaction & rotation', () => {
  it('redacts inline tokens, URL basic-auth, and secret keys recursively before RAM or disk persistence', () => {
    const logger = new StructuredLogger({ source: 'host', level: 'debug', dedupeWindowMs: 0 });
    const log = logger.child('security');

    log.info(
      'auth.test',
      'Connecting with Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 and DEEPSEEK_API_KEY=sk-1234567890abcdef1234 to https://admin:supersecret@proxy.example.com:8080',
      {
        apiKey: 'sk-99999999999999999999',
        nested: {
          githubToken: 'ghp_1234567890abcdefghijklmnopqrstuv',
          Authorization: 'Bearer secret-token-value',
          safeField: 'kept-intact',
        },
      },
    );

    const entries = logger.query({ limit: 10 });
    assert.equal(entries.length, 1);
    const e = entries[0]!;
    assert.doesNotMatch(e.message, /eyJhbGci/);
    assert.doesNotMatch(e.message, /sk-1234567890/);
    assert.doesNotMatch(e.message, /supersecret/);
    assert.match(e.message, /Bearer \[REDACTED\]/);
    assert.match(e.message, /DEEPSEEK_API_KEY=\[REDACTED\]/);
    assert.match(e.message, /https:\/\/\[REDACTED\]@proxy\.example\.com:8080/);

    const dataJson = JSON.stringify(e.data);
    assert.doesNotMatch(dataJson, /sk-99999999/);
    assert.doesNotMatch(dataJson, /ghp_1234567890/);
    assert.doesNotMatch(dataJson, /secret-token-value/);
    assert.match(dataJson, /kept-intact/);
  });

  it('coalesces burst writes into a SINGLE disk flush (protecting SSD TBW) and holds ZERO open FDs at idle', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-log-coalesce-'));
    const logDir = path.join(tmpDir, 'logs');
    const sink = new RotatingNdjsonSink({
      logDir,
      fileName: 'host.ndjson',
      flushIntervalMs: 5_000, // 5s batch window
      flushThresholdBytes: 64 * 1024,
    });
    const logger = new StructuredLogger({
      source: 'host',
      level: 'debug',
      fileSink: sink,
      preloadFromDisk: false,
      dedupeWindowMs: 0,
    });

    try {
      // Emit 40 distinct log entries rapidly -> must buffer in RAM with ZERO disk writes before flush!
      for (let i = 0; i < 40; i++) {
        logger.log('info', {
          component: 'tools',
          event: `step.${i}`,
          message: `Buffered entry #${i}`,
        });
      }
      assert.equal(sink.getDiskFlushCount(), 0, 'Must NOT hammer disk on every single log call');
      assert.equal(logger.query({ limit: 100 }).length, 40, 'In-memory query works immediately with 0 disk reads');

      // Explicit flush writes all 40 lines in ONE single writeSync syscall!
      logger.flushSync();
      assert.equal(sink.getDiskFlushCount(), 1, '40 log lines must coalesce into exactly 1 disk write');

      const logFile = sink.getFilePath();
      assertPrivateFileMode(logDir, 0o700);
      assertPrivateFileMode(logFile, 0o600);

      // Verify 64 KiB tail preload reads back cleanly on a fresh logger instance
      const reloaded = new StructuredLogger({
        source: 'host',
        level: 'info',
        fileSink: new RotatingNdjsonSink({ logDir, fileName: 'host.ndjson', flushIntervalMs: 5_000 }),
        preloadFromDisk: true,
      });
      assert.equal(reloaded.query({ limit: 100 }).length, 40);
      reloaded.dispose();
      logger.dispose();

      // Verify ZERO lingering NTFS/POSIX file locks: renaming & deleting the log directory succeeds immediately!
      const renamedDir = path.join(tmpDir, 'logs-renamed');
      fs.renameSync(logDir, renamedDir);
      fs.rmSync(renamedDir, { recursive: true, force: true });
      assert.equal(fs.existsSync(renamedDir), false);
    } finally {
      sink.dispose();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('folds duplicate log storms within dedupeWindowMs and rotates bounded NDJSON files cleanly', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-log-rotate-'));
    const sink = new RotatingNdjsonSink({
      logDir: tmpDir,
      fileName: 'app.ndjson',
      maxBytes: 12 * 1024, // 12 KiB small cap to exercise rotation
      maxFiles: 2,
      flushIntervalMs: 0,
    });
    const logger = new StructuredLogger({
      source: 'host',
      level: 'info',
      fileSink: sink,
      preloadFromDisk: false,
      dedupeWindowMs: 3_000,
      maxDiskEntriesPer10s: 500,
    });

    try {
      // 25 identical proxy denials in a tight loop -> folded into 1 entry + 1 summary!
      for (let i = 0; i < 25; i++) {
        logger.log('warn', {
          component: 'proxy',
          event: 'proxy.blocked',
          message: 'Blocked outbound connection to evil.invalid:443',
        });
      }
      logger.log('info', {
        component: 'proxy',
        event: 'proxy.AfterBurst',
        message: 'Next distinct event triggers coalesced summary',
      });

      const entries = logger.query({ limit: 20 });
      assert.equal(entries.length, 3);
      assert.equal(entries[1]!.event, 'proxy.blocked.coalesced');
      assert.equal((entries[1]!.data as { suppressedDuplicates: number }).suppressedDuplicates, 24);

      // Push enough distinct entries to trigger rotation (.1, .2, and prune .3)
      for (let i = 0; i < 160; i++) {
        logger.log('info', {
          component: 'rot',
          event: `rot.${i}`,
          message: `Payload-${i}-${'x'.repeat(180)}`,
        });
      }
      assert.equal(fs.existsSync(path.join(tmpDir, 'app.ndjson')), true);
      assert.equal(fs.existsSync(path.join(tmpDir, 'app.ndjson.1')), true);
      assert.equal(fs.existsSync(path.join(tmpDir, 'app.ndjson.3')), false, 'Oldest file beyond maxFiles=2 must be pruned');
    } finally {
      logger.dispose();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});

describe('Shared Node.js Runtime & User Toolchain Sandbox PATH', () => {
  it('shares DSH process.execPath carrier, strips host NODE_OPTIONS, and blocks Windows /mnt/*.exe in WSL Node config', () => {
    const hostRt = resolveSharedHostNodeRuntime();
    assert.equal(hostRt.executable, process.execPath);
    assert.equal(hostRt.nodeVersion, process.version);
    assert.equal(hostRt.sharedWithHostProcess, true);

    const childEnv = buildHostNodeChildEnv({
      PATH: '/usr/bin',
      NODE_OPTIONS: '--inspect=9229',
      TSX_TSCONFIG_PATH: '/tmp/tsconfig.json',
    });
    assert.equal(childEnv.NODE_OPTIONS, undefined);
    assert.equal(childEnv.TSX_TSCONFIG_PATH, undefined);

    assert.equal(validateWslNodeExecutable('auto'), 'auto');
    assert.equal(validateWslNodeExecutable('/home/dev/.local/share/mise/shims/node'), '/home/dev/.local/share/mise/shims/node');
    for (const bad of ['/mnt/c/Program Files/nodejs/node.exe', 'node.exe', 'C:\\Program Files\\nodejs\\node.exe']) {
      assert.throws(() => validateWslNodeExecutable(bad), SandboxError, `Expected reject for Windows Node: ${bad}`);
    }

    const wslArgs = buildWslNodeSpawnArgs({
      distro: 'Ubuntu-26.04',
      username: 'dev',
      scriptPath: '/home/dev/.local/share/dsh-wsl-sandbox/runner/dist/packages/wsl-runner/src/main.js',
      leaseMs: 180_000,
      logLevel: 'info',
    });
    assert.deepEqual(wslArgs.slice(0, 6), ['-d', 'Ubuntu-26.04', '--cd', '~', '-u', 'dev']);
    assert.ok(wslArgs.includes('dsh-wsl-node'));
    assert.equal(parseRunnerWireLog('[DSH_RUNNER_LOG]{"level":"info","message":"ok"}')?.message, 'ok');
  });

  it('includes shared DSH/mise/uv/cargo/bun user binary dirs and RUSTUP_HOME inside sanitizeSandboxEnv', () => {
    const p = buildDefaultSandboxPath('/home/alice');
    assert.match(p, /\/home\/alice\/\.dsh\/runtime\/bin/);
    assert.match(p, /\/home\/alice\/\.local\/share\/mise\/shims/);
    assert.match(p, /\/home\/alice\/\.local\/bin/);
    assert.match(p, /\/home\/alice\/\.cargo\/bin/);
    assert.match(p, /\/home\/alice\/\.bun\/bin/);
    assert.doesNotMatch(p, /\/mnt\//);

    const env = sanitizeSandboxEnv({ homeDir: '/home/alice' });
    assert.equal(env.RUSTUP_HOME, '/home/alice/.rustup');
    assert.ok(env.PATH.includes('/home/alice/.local/share/mise/shims'));
  });

  it('forwards [DSH_RUNNER_LOG] entries from wsl-runner into Host /wsl-sandbox/api/logs & /logs/export', { skip: BWRAP_SKIP_REASON }, async () => {
    const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-log-e2e-'));
    const routes = new Map<string, (req: Record<string, unknown>, res: Record<string, unknown>) => Promise<void>>();
    const tools = new Map<string, { execute: (input: Record<string, unknown>) => Promise<unknown> }>();

    const handle = applyWslSandbox(
      {
        tools: {
          register: (t) => {
            tools.set(t.name, t);
            return () => tools.delete(t.name);
          },
        },
        http: {
          route: (m, p, h) => {
            routes.set(`${m} ${p}`, h as never);
            return () => routes.delete(`${m} ${p}`);
          },
        },
      },
      {
        persistConfig: false,
        persistLogs: false,
        allowLinuxDevMode: true,
        initialConfig: {
          transportMode: 'local-linux',
          distro: 'linux-devbox',
          workspaceRoot: ws,
          runnerPath: BUILT_RUNNER_PATH,
          networkMode: 'offline',
          logLevel: 'info',
        },
      },
    );

    try {
      await tools.get('wsl_bash')!.execute({ command: 'echo LOG_BRIDGE_OK' });
      // Allow stderr readline tick to ingest forwarded runner logs
      await new Promise((r) => setTimeout(r, 60));

      let jsonRes: Record<string, unknown> = {};
      await routes.get('GET /wsl-sandbox/api/logs')!(
        { method: 'GET', path: '/wsl-sandbox/api/logs', params: {}, query: { source: 'all' }, headers: {} },
        {
          status() { return this; },
          header() { return this; },
          json(p: Record<string, unknown>) { jsonRes = p; },
          html() {},
          text() {},
        },
      );

      const entries = (jsonRes.entries ?? []) as Array<{ source: string; event: string }>;
      assert.ok(entries.some((e) => e.source === 'host' && e.event === 'plugin.loaded'));
      assert.ok(entries.some((e) => e.source === 'wsl-runner' && e.event === 'proc.exec'));

      let exported = '';
      await routes.get('GET /wsl-sandbox/api/logs/export')!(
        { method: 'GET', path: '/wsl-sandbox/api/logs/export', params: {}, query: {}, headers: {} },
        {
          status() { return this; },
          header() { return this; },
          json() {},
          html() {},
          text(t: string) { exported = t; },
        },
      );
      assert.match(exported, /"event":"proc\.exec"/);
    } finally {
      await handle.dispose();
      fs.rmSync(ws, { recursive: true, force: true });
    }
  });

  it('evaluates AI dangerous-command red-team batch seed with 0 false-negative bypasses and 0 false positives', async () => {
    const { runDangerousCommandMatrix } = await import('../../scripts/run-dangerous-cmd-matrix.mjs');
    const seedPath = path.resolve(import.meta.dirname, '..', '..', '..', 'tests', 'fixtures', 'dangerous-commands-seed.json');
    const fallbackSeedPath = path.resolve(import.meta.dirname, '..', 'fixtures', 'dangerous-commands-seed.json');
    const resolvedSeed = fs.existsSync(fallbackSeedPath) ? fallbackSeedPath : seedPath;
    const cases = JSON.parse(fs.readFileSync(resolvedSeed, 'utf8')) as Array<Record<string, unknown>>;
    const report = runDangerousCommandMatrix(cases);
    assert.equal(report.total >= 30, true);
    assert.equal(report.falseNegatives, 0);
    assert.equal(report.falsePositives, 0);
    assert.equal(report.failed, 0);
  });
});

describe('Lifecycle Hygiene, Crash Recovery & Reversible Uninstallation (Issue #1 & #2)', () => {
  it('reversibly removes dsh-wsl-sandbox AGENTS.md block and deletes empty plugin-created scaffold files', () => {
    const tmpProj = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-agentsmd-test-'));
    try {
      // Case 1: Created from scratch -> deleted completely on remove
      const created = upsertAgentsMdWslSection(tmpProj, { distro: 'Ubuntu-26.04', workspaceRoot: '~/workspace' });
      assert.equal(created.action, 'created');
      assert.equal(fs.existsSync(created.filePath), true);

      const removedEmpty = removeAgentsMdWslSection(tmpProj);
      assert.equal(removedEmpty.action, 'deleted-empty-file');
      assert.equal(fs.existsSync(created.filePath), false);

      // Case 2: Appended to user-authored AGENTS.md (and supports legacy `:begin` marker too) -> preserves user text
      fs.writeFileSync(
        created.filePath,
        '# Team Conventions\n\nKeep commits atomic.\n\n<!-- dsh-wsl-sandbox:begin -->\nOld block\n<!-- dsh-wsl-sandbox:end -->\n\n## Footer\nStay safe.\n',
        'utf8',
      );
      const stripped = removeAgentsMdWslSection(tmpProj);
      assert.equal(stripped.action, 'removed-section');
      const remaining = fs.readFileSync(created.filePath, 'utf8');
      assert.doesNotMatch(remaining, /dsh-wsl-sandbox/);
      assert.match(remaining, /Keep commits atomic\./);
      assert.match(remaining, /Stay safe\./);
    } finally {
      fs.rmSync(tmpProj, { recursive: true, force: true });
    }
  });

  it('deduplicates unchanged backup snapshots by SHA-256 and caps rolling .bak files at 5 without 0400 EACCES errors', () => {
    const bkDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-bk-dedupe-'));
    try {
      // 6 repeated calls with identical content -> ONLY 1 file (`wsl.conf.orig`), ZERO `.bak` accumulation!
      for (let i = 0; i < 6; i++) {
        writeDeduplicatedReadOnlyBackup({
          backupDir: bkDir,
          origFileName: 'wsl.conf.orig',
          rollingPrefix: 'wsl.conf',
          rollingExt: 'bak',
          timestamp: `20261126-00000${i}`,
          content: '[boot]\nsystemd=true\n',
          maxRolling: 5,
        });
      }
      assert.deepEqual(fs.readdirSync(bkDir).sort(), ['wsl.conf.orig']);
      assertPrivateFileMode(path.join(bkDir, 'wsl.conf.orig'), 0o400);

      // 8 distinct content revisions -> `.orig` stays untouched + rolling `.bak` capped at exactly 5
      for (let i = 1; i <= 8; i++) {
        writeDeduplicatedReadOnlyBackup({
          backupDir: bkDir,
          origFileName: 'wsl.conf.orig',
          rollingPrefix: 'wsl.conf',
          rollingExt: 'bak',
          timestamp: `20261126-01000${i}`,
          content: `[boot]\nrevision=${i}\n`,
          maxRolling: 5,
        });
      }
      const files = fs.readdirSync(bkDir).sort();
      assert.equal(files.length, 6); // 1 .orig + 5 rolling .bak
      assert.equal(files.includes('wsl.conf.orig'), true);
      assert.equal(fs.readFileSync(path.join(bkDir, 'wsl.conf.orig'), 'utf8'), '[boot]\nsystemd=true\n');
    } finally {
      for (const f of fs.readdirSync(bkDir)) {
        try { fs.chmodSync(path.join(bkDir, f), 0o600); } catch { /* ignore */ }
      }
      fs.rmSync(bkDir, { recursive: true, force: true });
    }
  });

  it('sweeps SIGKILL-orphaned 0444 runner/proxy temp dirs via owner.pid while preserving live runner dirs and preferring RAM tmpfs', () => {
    if (IS_LINUX) {
      const ramRoot = resolveEphemeralRamTmpRoot();
      assert.ok(
        ramRoot === '/dev/shm' || ramRoot.startsWith('/run/user/') || ramRoot === os.tmpdir(),
        `Unexpected ramRoot: ${ramRoot}`,
      );
    }

    const fakeTmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-sweep-lab-'));
    try {
      const crashedRunner = path.join(fakeTmp, 'dsh-wsl-runner-dead1');
      const crashedProxy = path.join(fakeTmp, 'dsh-wsl-proxy-dead2');
      const liveRunner = path.join(fakeTmp, 'dsh-wsl-runner-live');

      for (const d of [crashedRunner, crashedProxy, liveRunner]) {
        fs.mkdirSync(d, { recursive: true, mode: 0o700 });
        fs.writeFileSync(path.join(d, 'empty-mask'), '', { mode: 0o444 });
      }
      fs.writeFileSync(path.join(crashedRunner, 'owner.pid'), '99999991\n');
      fs.writeFileSync(path.join(crashedProxy, 'owner.pid'), '99999992\n');
      fs.writeFileSync(path.join(liveRunner, 'owner.pid'), `${process.pid}\n`);

      const swept = sweepOrphanedRunnerTempDirs({ tmpRoot: fakeTmp });
      assert.equal(swept.sweptDirs.length, 2);
      assert.equal(fs.existsSync(crashedRunner), false);
      assert.equal(fs.existsSync(crashedProxy), false);
      assert.equal(fs.existsSync(liveRunner), true);
    } finally {
      for (const ent of fs.readdirSync(fakeTmp)) {
        const sub = path.join(fakeTmp, ent, 'empty-mask');
        if (fs.existsSync(sub)) {
          try { fs.chmodSync(sub, 0o600); } catch { /* ignore */ }
        }
      }
      fs.rmSync(fakeTmp, { recursive: true, force: true });
    }
  });

  it('enforces Checklist B (.git/hooks, .bashrc, .dsh) protection inside rw /shares/<alias> in ConfinedFsService', () => {
    const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-fs-ws-'));
    const rwShare = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-fs-rwshare-'));
    fs.mkdirSync(path.join(rwShare, '.git', 'hooks'), { recursive: true });
    try {
      const svc = new ConfinedFsService();
      const binding: SessionBinding = {
        sessionId: 'sess-fs-share',
        uid: 1000,
        username: 'dev',
        distro: 'Ubuntu-26.04',
        workspaceRoot: ws,
        cwd: ws,
        profile: 'workspace-write',
        revision: 'rev-1',
        generation: 1,
        runnerId: 'r-1',
        authorizedShares: [{ id: 'sh-1', alias: 'extrepo', sourceLinuxPath: rwShare, mode: 'rw', oneShot: false }],
        authorizedDevices: [],
      };

      // Normal file write in rw share is allowed
      const okWrite = svc.write({ binding, path: '/shares/extrepo/README.md', content: 'hello\n' });
      assert.equal(okWrite.bytesWritten, 6);

      // Checklist B protected targets inside rw share MUST be blocked just like workspaceRoot!
      for (const bad of ['/shares/extrepo/.git/hooks/pre-commit', '/shares/extrepo/.bashrc', '/shares/extrepo/.dsh/config.json']) {
        assert.throws(() => svc.write({ binding, path: bad, content: 'pwned\n' }), SandboxError, `Expected Checklist B block for ${bad}`);
      }
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
      fs.rmSync(rwShare, { recursive: true, force: true });
    }
  });

  it('cleanly reverses all WSL artifacts in provision-wsl.sh --uninstall --purge-toolchains and has zero curl|sudo NodeSource commands', { skip: POSIX_BASH_SKIP_REASON }, () => {
    const provContent = fs.readFileSync(PROVISION_SH_PATH, 'utf8');
    assert.doesNotMatch(provContent, /nodesource\.com\/setup_/);

    const fakeHome = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-uninstall-home-'));
    try {
      // Populate all WSL-side artifacts including 0400 backups, shell RC hooks, cache, runner, delta path, and empty ~/workspace
      const cfgRoot = path.join(fakeHome, '.config', 'dsh-wsl-sandbox');
      const bkDir = path.join(cfgRoot, 'backups');
      const cacheDir = path.join(fakeHome, '.cache', 'dsh-wsl-sandbox', 'deadbeef1234');
      const runnerDir = path.join(fakeHome, '.local', 'share', 'dsh-wsl-sandbox', 'runner');
      const deltaTool = path.join(fakeHome, '.local', 'bin', 'fake-delta-tool');
      const emptyWs = path.join(fakeHome, 'workspace');

      fs.mkdirSync(bkDir, { recursive: true, mode: 0o700 });
      fs.mkdirSync(cacheDir, { recursive: true, mode: 0o700 });
      fs.mkdirSync(runnerDir, { recursive: true, mode: 0o700 });
      fs.mkdirSync(path.dirname(deltaTool), { recursive: true, mode: 0o700 });
      fs.mkdirSync(emptyWs, { recursive: true, mode: 0o755 });

      fs.writeFileSync(path.join(bkDir, 'wsl.conf.orig'), '[boot]\n', { mode: 0o400 });
      fs.chmodSync(path.join(bkDir, 'wsl.conf.orig'), 0o400);
      fs.writeFileSync(path.join(cacheDir, 'pkg.tgz'), 'cached');
      fs.writeFileSync(path.join(runnerDir, 'main.js'), '// runner');
      fs.writeFileSync(deltaTool, '#!/bin/sh\n', { mode: 0o755 });
      fs.writeFileSync(path.join(fakeHome, '.dsh-wsl-env.sh'), 'export DSH_WSL_PROFILE="standard"\n', { mode: 0o600 });
      fs.writeFileSync(
        path.join(fakeHome, '.bashrc'),
        '# User bashrc\nalias ll="ls -la"\n[ -f "$HOME/.dsh-wsl-env.sh" ] && . "$HOME/.dsh-wsl-env.sh"\n',
      );
      fs.writeFileSync(
        path.join(cfgRoot, 'provision-manifest.json'),
        JSON.stringify({ deltaEntries: [`path:${deltaTool}`] }, null, 2),
        { mode: 0o600 },
      );

      const res = spawnSync(
        'bash',
        [PROVISION_SH_PATH, '--uninstall', '--purge-toolchains', '--skip-restore'],
        {
          encoding: 'utf8',
          env: { ...process.env, HOME: fakeHome },
        },
      );
      assert.equal(res.status, 0, res.stderr || res.stdout);

      assert.equal(fs.existsSync(cfgRoot), false, '~/.config/dsh-wsl-sandbox (including 0400 backups) must be removed');
      assert.equal(fs.existsSync(path.join(fakeHome, '.cache', 'dsh-wsl-sandbox')), false, '~/.cache/dsh-wsl-sandbox must be removed');
      assert.equal(fs.existsSync(path.join(fakeHome, '.local', 'share', 'dsh-wsl-sandbox')), false, '~/.local/share/dsh-wsl-sandbox must be removed');
      assert.equal(fs.existsSync(path.join(fakeHome, '.dsh-wsl-env.sh')), false, '~/.dsh-wsl-env.sh must be removed');
      assert.equal(fs.existsSync(deltaTool), false, 'Delta toolchain path from provision-manifest.json must be removed');
      assert.equal(fs.existsSync(emptyWs), false, 'Empty default ~/workspace must be removed');

      const bashrcAfter = fs.readFileSync(path.join(fakeHome, '.bashrc'), 'utf8');
      assert.doesNotMatch(bashrcAfter, /\.dsh-wsl-env\.sh/);
      assert.match(bashrcAfter, /alias ll="ls -la"/);

      // Verify non-empty ~/workspace with user code is NEVER deleted!
      fs.mkdirSync(emptyWs, { recursive: true });
      fs.writeFileSync(path.join(emptyWs, 'my-code.ts'), 'export const x = 1;\n');
      const res2 = spawnSync('bash', [PROVISION_SH_PATH, '--uninstall', '--skip-restore'], {
        encoding: 'utf8',
        env: { ...process.env, HOME: fakeHome },
      });
      assert.equal(res2.status, 0);
      assert.equal(fs.existsSync(path.join(emptyWs, 'my-code.ts')), true, 'Non-empty user ~/workspace must be preserved!');
    } finally {
      fs.rmSync(fakeHome, { recursive: true, force: true });
    }
  });
});


