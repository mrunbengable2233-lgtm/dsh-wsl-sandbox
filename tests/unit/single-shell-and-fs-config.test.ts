import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { spawnSync } from 'node:child_process';
import {
  ApprovalController,
  buildBwrapArgs,
  deobfuscatePowerShell,
  evaluateBashCommand,
  evaluatePwshCommand,
  SandboxError,
  type SessionBinding,
} from '../../packages/core/src/index.ts';
import { ConfigStore, validateBackupDirPath } from '../../packages/dsh-plugin/src/config-store.ts';
import {
  isInsideLxssBasePath,
  mergeWslDistrosWithLxss,
  parseWslListVerbose,
} from '../../packages/dsh-plugin/src/wsl-discovery.ts';
import { ConfinedFsService } from '../../packages/wsl-runner/src/fs-service.ts';
import { ConfinedProcManager } from '../../packages/wsl-runner/src/proc-manager.ts';
import { ConfinedTerminalManager } from '../../packages/wsl-runner/src/pty-manager.ts';
import {
  assertPrivateFileMode,
  BWRAP_SKIP_REASON,
  IS_WINDOWS,
  POSIX_BASH_SKIP_REASON,
  POSIX_TAR_SKIP_REASON,
  PROVISION_SH_PATH,
  UDS_SKIP_REASON,
} from '../test-env.ts';

function makeBinding(workspaceRoot: string, overrides?: Partial<SessionBinding>): SessionBinding {
  return {
    sessionId: 'unit-sess',
    backend: 'wsl',
    wslVersion: 2,
    distribution: 'Ubuntu-26.04',
    uid: process.getuid ? process.getuid() : 1000,
    username: 'dev',
    arch: process.arch === 'arm64' ? 'aarch64' : 'x86_64',
    cwd: workspaceRoot,
    workspaceRoot,
    profile: 'workspace-write',
    revision: 'rev-1',
    generation: 1,
    runnerId: 'runner-unit',
    sandboxReady: true,
    enforcement: 'full',
    supportsDisableUserns: true,
    probedSockets: [],
    authorizedShares: [],
    authorizedDevices: [],
    ...overrides,
  };
}

describe('Single-Shell Purity & Pre-Execution Shell Dialect Guard (DeepSeek V4.1 Flash Quirks)', () => {
  it('blocks all 8 mixed-shell / CMD-in-PowerShell / hang / UNC escape specimens at L0', () => {
    const blockedSpecimens = [
      // 1. Outer Move-Item + nested cmd /c rd + mkdir + mklink + xcopy
      'Move-Item -Path .\\src -Destination .\\src_bak -Force; cmd.exe /c "rd /s /q .\\src & mkdir .\\src & mklink /J .\\src C:\\Users\\Public\\shared && xcopy .\\src_bak\\* .\\src\\ /E /H /Y"',
      // 2. Reverse UNC \\wsl.localhost\ escape bypassing bwrap read-only .git/hooks
      'New-Item -ItemType Directory -Force .\\tmp_stage; Set-Content \\\\wsl.localhost\\Ubuntu-24.04\\home\\dev\\workspace\\.git\\hooks\\pre-commit "evil"',
      'Copy-Item .\\evil \\\\wsl$\\Ubuntu-24.04\\home\\dev\\workspace\\.bashrc',
      // 3. PowerShell --% stop-parsing + cmd /v:on delayed variable expansion
      'pwsh.exe -NoProfile --% cmd.exe /v:on /c "set d=rd & !d! /s /q C:\\Projects\\build"',
      // 4. Bare CMD slash-flags (/s /q, /f /q, /y) passed to PowerShell aliases (parsed as C:\s, C:\q!)
      'mkdir build_out; move .\\dist\\* build_out\\; rmdir /s /q .\\dist',
      'del /f /q .\\build\\*.tmp',
      'move /y a.bin b.bin',
      // 5. CMD 2>nul redirection inside PowerShell (creates undeletable DOS reserved `nul` file)
      'Remove-Item .\\temp -Recurse -Force 2>nul',
      'Get-ChildItem >nul',
      // 6. Mixing pwsh.exe (PS 7) and powershell.exe (WinPS 5.1) causing >> quote hang & CP936 mojibake
      'pwsh.exe -Command "Move-Item .\\a .\\b; powershell.exe -Command \\"Get-Date\\""',
      'Move-Item .\\a .\\b; powershell.exe -Command "Get-ChildItem"',
      // 7. Interactive hang flags (cmd /k, -NoExit, -Command -, Read-Host, pause)
      'powershell.exe -NoExit -Command "Get-Process"',
      'pwsh.exe -Command -',
      'Read-Host "Press Enter"',
      'pause',
      // 8. WinPS 5.1 invoked with PS 7 && chain or CMD %VAR% syntax
      'powershell.exe -Command "Get-Location && Get-ChildItem"',
      'Get-ChildItem %USERPROFILE%\\Desktop',
      // 9. Positional pwsh.exe -> cmd without -c & caret obfuscation
      'pwsh.exe cmd /r "mkdir foo && move a b"',
      'c^m^d.exe /c "m^k^d^i^r foo"',
      '"mkdir a && move b c" | cmd.exe',
    ];

    for (const specimen of blockedSpecimens) {
      const verdict = evaluatePwshCommand(specimen);
      assert.equal(
        verdict.decision,
        'deny',
        `Expected L0 deny for specimen:\n  ${specimen}\nGot: ${verdict.decision} (${verdict.reasons.join('; ')})`,
      );
      assert.equal(verdict.code, 'POLICY_BLOCK');
    }
  });

  it('strips both PowerShell backticks and unquoted CMD carets during deobfuscation', () => {
    assert.equal(deobfuscatePowerShell('c^m^d /c m^o^v^e'), 'cmd /c move');
    assert.equal(deobfuscatePowerShell('i`e`x "test"'), 'iex "test"');
  });

  it('blocks Windows PowerShell/CMD syntax or .exe interop accidentally used inside POSIX wsl_bash', () => {
    const ctx = { workspaceRoot: '/home/dev/workspace' };
    const badInBash = [
      'Get-ChildItem -Recurse',
      'Move-Item ./a ./b',
      'Remove-Item -Recurse -Force ./dist',
      'rd /s /q ./dist',
      'del /f /q ./out',
      'echo $env:USERPROFILE',
      'ls %USERPROFILE%',
      'cmd.exe /c dir',
      'pwsh.exe -c Get-Date',
      'powershell.exe Get-Date',
    ];
    for (const cmd of badInBash) {
      const res = evaluateBashCommand(cmd, ctx);
      assert.equal(res.decision, 'deny', `Expected wsl_bash L0 deny for: ${cmd}`);
    }
  });
});

describe('bwrap-builder — mount precedence, Checklist B placeholders, shares, devices & UDS socket', () => {
  it('builds complete sandbox argv with --remount-ro /, Checklist B locks, .env masking, shares, and device binds', { skip: UDS_SKIP_REASON }, async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-bwrap-unit-'));
    const shareDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-share-unit-'));
    const sockDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-sock-unit-'));
    const sockPath = path.join(sockDir, 'proxy.sock');
    const server = net.createServer();
    await new Promise<void>((resolve) => server.listen(sockPath, resolve));

    try {
      fs.writeFileSync(path.join(tmp, '.env'), 'SECRET=123\n');
      fs.writeFileSync(path.join(tmp, '.env.example'), 'SECRET=example\n');
      fs.mkdirSync(path.join(tmp, '.git'), { recursive: true });

      const binding = makeBinding(tmp, {
        authorizedShares: [{ id: 's1', alias: 'extdocs', sourceLinuxPath: shareDir, mode: 'ro' }],
      });

      const plan = buildBwrapArgs({
        argv: ['/bin/bash', '-lc', 'echo ok'],
        cwd: tmp,
        workspaceRoot: tmp,
        mode: 'workspace-write',
        networkMode: 'allowlist-proxy',
        supportsDisableUserns: true,
        env: { PATH: '/usr/bin:/bin' },
        shares: binding.authorizedShares,
        proxySocketHostPath: sockPath,
        maskEnvSecrets: true,
        emptyMaskFilePath: '/dev/null',
      });

      assert.ok(plan.bwrapArgs.includes('--remount-ro'));
      assert.ok(plan.bwrapArgs.includes('--disable-userns'));
      assert.ok(plan.bwrapArgs.includes('--unshare-net'));
      assert.ok(plan.bwrapArgs.includes('/shares/extdocs'));
      assert.ok(plan.maskedEnvFiles.some((f) => f.endsWith('/.env')));
      assert.ok(!plan.maskedEnvFiles.some((f) => f.endsWith('/.env.example')));
      assert.ok(plan.createdPlaceholders.some((p) => p.endsWith('/.git/hooks')));

      // Fail closed if proxy socket does not exist
      assert.throws(
        () =>
          buildBwrapArgs({
            argv: ['/bin/true'],
            cwd: tmp,
            workspaceRoot: tmp,
            mode: 'workspace-write',
            networkMode: 'allowlist-proxy',
            supportsDisableUserns: true,
            env: {},
            proxySocketHostPath: path.join(sockDir, 'missing.sock'),
          }),
        (err: unknown) => err instanceof SandboxError,
      );
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      fs.rmSync(tmp, { recursive: true, force: true });
      fs.rmSync(shareDir, { recursive: true, force: true });
      fs.rmSync(sockDir, { recursive: true, force: true });
    }
  });
});

describe('ConfinedFsService & ConfinedTerminalManager — line slicing, .env masking, Checklist B & EXIT trap', () => {
  it('slices wsl_read by 1-based line offset and line limit accurately and masks .env*', () => {
    const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-fs-unit-'));
    try {
      const binding = makeBinding(ws);
      const svc = new ConfinedFsService();

      svc.write({
        binding,
        path: 'src/lines.txt',
        content: 'line-1\nline-2\nline-3\nline-4\nline-5\n',
      });

      const page = svc.read({ binding, path: 'src/lines.txt', offset: 2, limit: 2 });
      assert.equal(page.content, 'line-2\nline-3');
      assert.equal(page.startLine, 2);
      assert.equal(page.endLine, 3);
      assert.equal(page.totalLines, 5);
      assert.equal(page.truncated, true);
      assert.equal(page.maskedEnv, false);

      // Masked .env vs readable .env.example
      fs.writeFileSync(path.join(ws, '.env.local'), 'API_KEY=xyz\n');
      fs.writeFileSync(path.join(ws, '.env.example'), 'API_KEY=placeholder\n');

      const envMasked = svc.read({ binding, path: '.env.local', maskEnvSecrets: true });
      assert.equal(envMasked.maskedEnv, true);
      assert.equal(envMasked.content, '');

      const envUnmasked = svc.read({ binding, path: '.env.local', maskEnvSecrets: false });
      assert.equal(envUnmasked.maskedEnv, false);
      assert.match(envUnmasked.content, /API_KEY=xyz/);

      const envExample = svc.read({ binding, path: '.env.example', maskEnvSecrets: true });
      assert.equal(envExample.maskedEnv, false);
      assert.match(envExample.content, /API_KEY=placeholder/);

      // Checklist B blocks writing .git/hooks or .bashrc
      fs.mkdirSync(path.join(ws, '.git', 'hooks'), { recursive: true });
      assert.throws(
        () => svc.write({ binding, path: '.git/hooks/pre-commit', content: '#!/bin/sh\n' }),
        (err: unknown) => err instanceof SandboxError && err.code === 'POLICY_BLOCK',
      );
      assert.throws(
        () => svc.write({ binding, path: '.bashrc', content: 'alias ls=evil\n' }),
        (err: unknown) => err instanceof SandboxError && err.code === 'POLICY_BLOCK',
      );

      // Read-only mode blocks write/edit/delete
      const roBinding = makeBinding(ws, { profile: 'read-only' });
      assert.throws(
        () => svc.write({ binding: roBinding, path: 'src/new.txt', content: 'hi' }),
        (err: unknown) => err instanceof SandboxError && err.code === 'POLICY_BLOCK',
      );
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
    }
  });

  it('preserves working directory in ConfinedTerminalManager even when command calls exit 0', { skip: BWRAP_SKIP_REASON }, async () => {
    const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-term-unit-'));
    try {
      fs.mkdirSync(path.join(ws, 'packages', 'sub'), { recursive: true });
      const binding = makeBinding(ws);
      const procMgr = new ConfinedProcManager();
      const termMgr = new ConfinedTerminalManager(procMgr);

      const r1 = await termMgr.exec({
        binding,
        terminalId: 't1',
        command: 'cd packages/sub && echo "entered" && exit 0',
        cwd: ws,
        mode: 'workspace-write',
        networkMode: 'offline',
      });
      assert.equal(r1.exitCode, 0);
      assert.equal(r1.cwd, path.posix.join(ws, 'packages/sub'));

      const r2 = await termMgr.exec({
        binding,
        terminalId: 't1',
        command: 'pwd -P',
        cwd: ws,
        mode: 'workspace-write',
        networkMode: 'offline',
      });
      assert.equal(r2.stdout.text.trim(), path.posix.join(ws, 'packages/sub'));
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
    }
  });
});

describe('ConfigStore & ApprovalController — persistence, TTL timeout, and deny-with-guidance', () => {
  it('writes 0600 config atomically, recovers from corrupt file, and validates profile/network/transport fields', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-cfg-unit-'));
    const cfgPath = path.join(dir, 'config.json');
    try {
      fs.writeFileSync(cfgPath, '{not-valid-json', 'utf8');
      const store = new ConfigStore({
        filePath: cfgPath,
        initial: { workspaceRoot: '/home/dev/ws', distro: 'Ubuntu-26.04', environmentProfile: 'core' },
      });
      assert.equal(store.get().distro, 'Ubuntu-26.04');
      assert.equal(store.get().environmentProfile, 'core');

      assertPrivateFileMode(cfgPath, 0o600);

      const updated = store.updateBasic({
        transportMode: 'local-linux',
        environmentProfile: 'universal',
        upstreamProxy: 'socks5://127.0.0.1:10808',
      });
      assert.equal(updated.transportMode, 'local-linux');
      assert.equal(updated.environmentProfile, 'universal');
      assert.equal(updated.upstreamProxy, 'socks5://127.0.0.1:10808');

      assert.throws(
        () => store.updateAdvancedNetwork({ localLabCidrs: ['999.999.1.1/24'] }),
        (err: unknown) => err instanceof SandboxError && err.code === 'POLICY_BLOCK',
      );
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('enforces REVIEW_TIMEOUT when human reviewer does not respond before ttlMs', async () => {
    const binding = makeBinding('/home/dev/ws');
    const ctrl = new ApprovalController({
      ttlMs: 40,
      reviewer: ({ signal }) =>
        new Promise((_resolve, reject) => {
          signal.addEventListener('abort', () => reject(new Error('timed out')), { once: true });
        }),
    });
    ctrl.bind(binding);

    await assert.rejects(
      () =>
        ctrl.authorize({
          kind: 'dangerous-command',
          summary: 'rm test',
          command: 'rm -rf ./tmp',
          reasons: ['test'],
          touchesPhysicalDevice: false,
        }),
      (err: unknown) => err instanceof SandboxError && err.code === 'REVIEW_TIMEOUT',
    );
  });

  it('auto-converts Windows folder paths for single-directory /shares mounting while blocking whole drives, system roots & config dirs', async () => {
    const { normalizeSharePathInput, validateShareEntry } = await import('../../packages/core/src/index.ts');

    assert.equal(normalizeSharePathInput('D:\\Datasets\\Project\\'), '/mnt/d/Datasets/Project');
    assert.equal(
      normalizeSharePathInput('"C:\\Users\\Alice\\Downloads\\spec-v2"'),
      '/mnt/c/Users/Alice/Downloads/spec-v2',
    );

    const validated = validateShareEntry({
      id: '',
      alias: '',
      sourceLinuxPath: 'D:\\Datasets\\Project-Docs',
      mode: 'ro',
    });
    assert.equal(validated.alias, 'Project-Docs');
    assert.equal(validated.sourceLinuxPath, '/mnt/d/Datasets/Project-Docs');
    assert.match(validated.id, /^sh-/);

    for (const forbidden of [
      'C:\\',
      'D:',
      'D:\\',
      '/mnt/c',
      '/mnt/d/',
      'C:\\Windows\\System32',
      'C:\\Program Files\\Vendor',
      'C:\\Users\\Alice',
      'C:\\Users\\Alice\\.dsh',
      'C:\\Users\\Alice\\.ssh',
      'C:\\Users\\Alice\\AppData\\Local\\Packages\\Canonical',
      '\\\\wsl.localhost\\Ubuntu-26.04\\home\\dev',
    ]) {
      assert.throws(
        () => validateShareEntry({ id: 'sh-bad', alias: 'bad', sourceLinuxPath: forbidden, mode: 'ro' }),
        (err: unknown) => err instanceof SandboxError && err.code === 'POLICY_BLOCK',
        `Expected POLICY_BLOCK for forbidden share input: ${forbidden}`,
      );
    }
  });

  it('supports arbitrary custom backupDir with 0700 dir + 0400 read-only files, blocks sensitive config dirs, and confines open-explorer', async () => {
    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-custom-bk-'));
    const customBkDir = path.join(tmpRoot, 'my-wsl-backups');
    const cfgFile = path.join(tmpRoot, 'config.json');
    try {
      // Reject sensitive/live config folders as backupDir
      for (const badDir of [
        os.homedir(),
        path.join(os.homedir(), '.dsh'),
        path.join(os.homedir(), '.dsh', 'dsh-wsl-sandbox'),
        path.join(os.homedir(), '.ssh'),
        path.join(os.homedir(), '.config', 'dsh-wsl-sandbox'),
      ]) {
        assert.throws(
          () => validateBackupDirPath(badDir),
          (err: unknown) => err instanceof SandboxError && err.code === 'POLICY_BLOCK',
          `Expected POLICY_BLOCK for backupDir: ${badDir}`,
        );
      }

      const { ApprovalBridge } = await import('../../packages/dsh-plugin/src/approval-bridge.ts');
      const { WslSandboxSessionManager } = await import('../../packages/dsh-plugin/src/tools.ts');
      const { registerWslSandboxWebApi } = await import('../../packages/dsh-plugin/src/web-api.ts');

      const store = new ConfigStore({
        filePath: cfgFile,
        initial: { workspaceRoot: '/home/dev/ws', distro: 'Ubuntu-26.04' },
      });
      const routes = new Map<string, (req: Record<string, unknown>, res: Record<string, unknown>) => Promise<void>>();
      const mockCtx = {
        http: {
          route: (m: string, p: string, h: (req: Record<string, unknown>, res: Record<string, unknown>) => Promise<void>) => {
            routes.set(`${m} ${p}`, h);
            return () => {};
          },
        },
      };
      const bridge = new ApprovalBridge({ configStore: store });
      const mgr = new WslSandboxSessionManager({ configStore: store, approvalBridge: bridge });
      registerWslSandboxWebApi(mockCtx as never, { configStore: store, sessionManager: mgr, approvalBridge: bridge });

      const invoke = async (method: string, route: string, body?: unknown, query: Record<string, string> = {}) => {
        let status = 200;
        let payload: unknown;
        const res = {
          status(c: number) { status = c; return res; },
          header() { return res; },
          json(p: unknown) { payload = p; },
          html() {},
          text() {},
        };
        const handler = routes.get(`${method} ${route}`);
        assert.ok(handler, `Missing route ${method} ${route}`);
        await handler({ method, path: route, params: {}, query, body, headers: {} }, res);
        return { status, payload: payload as Record<string, unknown> };
      };

      // 1. Backup to arbitrary custom backupDir -> verify 0700 dir and 0400 read-only snapshot files!
      const bkRes = await invoke('POST', '/wsl-sandbox/api/wsl-config/backup', { backupDir: customBkDir });
      assert.equal(bkRes.status, 200);
      assert.equal(bkRes.payload.backupDir, customBkDir);
      assert.equal(store.get().backupDir, customBkDir);
      assertPrivateFileMode(customBkDir, 0o700, 'Backup directory must be owner-only 0700');

      const savedFiles = bkRes.payload.savedFiles as string[];
      assert.ok(savedFiles.length >= 1, 'Expected at least 1 saved backup file');
      for (const f of savedFiles) {
        assertPrivateFileMode(f, 0o400, `Backup file ${f} must be read-only 0400`);
      }

      // 2. List backup items and verify explorerPath is populated
      const listRes = await invoke('GET', '/wsl-sandbox/api/wsl-config/backups');
      assert.equal(listRes.status, 200);
      const items = listRes.payload.items as Array<{ name: string; explorerPath: string }>;
      assert.ok(items.length >= 1, 'Expected at least 1 backup item');

      // 3. Highlight individual backup item in Explorer -> allowed (`explorerArgs: ['/select,<file>']`)
      const openItem = await invoke('POST', '/wsl-sandbox/api/wsl-config/open-explorer', {
        targetPath: items[0]!.explorerPath,
        selectFile: true,
      });
      assert.equal(openItem.status, 200);
      assert.deepEqual(openItem.payload.explorerArgs, [`/select,${items[0]!.explorerPath}`]);

      // 4. Reject escaping backupDir or launching .exe via open-explorer
      const escapeAttempt = await invoke('POST', '/wsl-sandbox/api/wsl-config/open-explorer', {
        targetPath: path.join(tmpRoot, 'outside.orig'),
        selectFile: true,
      });
      assert.equal(escapeAttempt.status, 403);

      fs.writeFileSync(path.join(customBkDir, 'evil.exe'), 'MZ');
      const exeAttempt = await invoke('POST', '/wsl-sandbox/api/wsl-config/open-explorer', {
        targetPath: path.join(customBkDir, 'evil.exe'),
        selectFile: true,
      });
      assert.equal(exeAttempt.status, 403);

      await mgr.dispose();
    } finally {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  });
});

describe('Bootstrap provisioning profiles, WSL Manager discovery & native ext4 tar staging', () => {
  it('enforces genuine core/standard/universal profile differentiation, shared Node / Node 24 LTS, and single-distro --terminate in provision-wsl.sh', { skip: POSIX_BASH_SKIP_REASON }, () => {
    const runDry = (extraArgs: string[]) =>
      spawnSync('bash', [PROVISION_SH_PATH, ...extraArgs, '--dry-run'], { encoding: 'utf8' });

    const coreRes = runDry(['--profile', 'core']);
    assert.equal(coreRes.status, 0, coreRes.stderr);
    assert.match(coreRes.stdout, /bubblewrap/);
    assert.match(coreRes.stdout, /unzip/);
    assert.match(coreRes.stdout, /Core profile stops at shared Node \/ Node\.js 24 LTS/);
    assert.match(coreRes.stdout, /Core profile stops at system python3/);
    assert.match(coreRes.stdout, /\[step:go\]\[profile=core\] Skipped/);
    assert.match(coreRes.stdout, /\[step:rust\]\[profile=core\] Skipped/);
    assert.match(coreRes.stdout, /\[step:extra\]\[profile=core\] Skipped/);
    assert.doesNotMatch(coreRes.stdout, /uv tool install/);
    assert.doesNotMatch(coreRes.stdout, /openjdk-21/);

    const stdRes = runDry(['--profile', 'standard', '--mirror', 'cn']);
    assert.equal(stdRes.status, 0, stdRes.stderr);
    assert.match(stdRes.stdout, /ccache protobuf-compiler/);
    assert.match(stdRes.stdout, /Ensure prebuilt mise binary/);
    assert.match(stdRes.stdout, /pnpm yarn typescript eslint prettier/);
    assert.match(stdRes.stdout, /uv tool install pytest/);
    assert.match(stdRes.stdout, /golang\.google\.cn\/dl/);
    assert.match(stdRes.stdout, /golangci-lint/);
    assert.match(stdRes.stdout, /rustup \(--profile minimal --component rustfmt,clippy\)/);
    assert.match(stdRes.stdout, /\[step:extra\]\[profile=standard\] Skipped/);
    assert.doesNotMatch(stdRes.stdout, /bazelisk/);
    assert.doesNotMatch(stdRes.stdout, /openjdk-21/);

    const uniRes = runDry(['--profile', 'universal']);
    assert.equal(uniRes.status, 0, uniRes.stderr);
    assert.match(uniRes.stdout, /clang clang-format clang-tidy/);
    assert.match(uniRes.stdout, /bazelisk/);
    assert.match(uniRes.stdout, /mise install node@22 node@24 && mise use -g node@24/);
    assert.match(uniRes.stdout, /uv tool install poetry/);
    assert.match(uniRes.stdout, /openjdk-21-jdk-headless maven gradle ruby php-cli composer/);

    // Individual spec steps `--step node`, `--step go`, and `--step rust` must all work standalone
    assert.equal(runDry(['--profile', 'standard', '--step', 'node']).status, 0);
    assert.equal(runDry(['--profile', 'standard', '--step', 'go']).status, 0);
    assert.equal(runDry(['--profile', 'standard', '--step', 'rust']).status, 0);

    // Unsafe --backup-dir targeting live config folders must fail with exit 2
    const badBk = runDry(['--backup-configs', '--backup-dir', path.join(os.homedir(), '.dsh')]);
    assert.notEqual(badBk.status, 0);

    // --disable-automount must recommend single-distro --terminate, NEVER global --shutdown
    const autoOff = runDry(['--disable-automount']);
    assert.equal(autoOff.status, 0);
    assert.match(autoOff.stdout, /wsl\.exe --terminate/);
    assert.doesNotMatch(autoOff.stdout, /Run 'wsl\.exe --shutdown'/);
  });

  it('parses UTF-16LE wsl.exe -l -v with Ubuntu-26.04, Debian, and WSL Manager moved VHDX instances', () => {
    const sampleText = [
      '  NAME                   STATE           VERSION',
      '* Ubuntu-26.04           Running         2',
      '  MyMovedLabDistro       Stopped         2',
      '  Debian                 Stopped         2',
      '  LegacyWsl1             Stopped         1',
      '  docker-desktop         Running         2',
      '  docker-desktop-data    Stopped         2',
    ].join('\r\n');
    const utf16Bom = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(sampleText, 'utf16le')]);

    const lxss = new Map([
      [
        'mymovedlabdistro',
        {
          DistributionName: 'MyMovedLabDistro',
          BasePath: 'E:\\WSL\\Imported\\MyMovedLabDistro',
          Version: 2,
          DefaultUid: 1000,
        },
      ],
      [
        'ubuntu-26.04',
        {
          DistributionName: 'Ubuntu-26.04',
          BasePath: 'C:\\Users\\Alice\\AppData\\Local\\Packages\\CanonicalGroupLimited.Ubuntu26.04\\LocalState',
          Version: 2,
          DefaultUid: 1000,
        },
      ],
      [
        'hiddenexplorerdistro',
        {
          DistributionName: 'HiddenExplorerDistro',
          BasePath: 'D:\\WSL-VHDX\\HiddenExplorerDistro',
          Version: 2,
          DefaultUid: 1000,
        },
      ],
    ]);

    const parsed = mergeWslDistrosWithLxss(parseWslListVerbose(utf16Bom), lxss);
    const ubuntu = parsed.find((d) => d.name === 'Ubuntu-26.04');
    const moved = parsed.find((d) => d.name === 'MyMovedLabDistro');
    const hidden = parsed.find((d) => d.name === 'HiddenExplorerDistro');
    const docker = parsed.find((d) => d.name === 'docker-desktop');
    const legacy = parsed.find((d) => d.name === 'LegacyWsl1');

    assert.equal(ubuntu?.isDefault, true);
    assert.equal(ubuntu?.wslVersion, 2);
    assert.equal(ubuntu?.isCustomDiskLocation, false);

    assert.equal(moved?.wslVersion, 2);
    assert.equal(moved?.isCustomDiskLocation, true);
    assert.equal(moved?.basePath, 'E:\\WSL\\Imported\\MyMovedLabDistro');
    assert.equal(moved?.supported, true);

    assert.equal(hidden?.isCustomDiskLocation, true);
    assert.equal(hidden?.supported, true);

    assert.equal(docker?.isInternalContainer, true);
    assert.equal(docker?.supported, false);
    assert.equal(legacy?.wslVersion, 1);
    assert.equal(legacy?.supported, false);

    // Guard against placing backupDir inside a moved WSL Manager VHDX BasePath!
    assert.equal(isInsideLxssBasePath('E:\\WSL\\Imported\\MyMovedLabDistro\\backups', parsed), 'MyMovedLabDistro');
    assert.equal(isInsideLxssBasePath('D:\\SafeBackups\\WSL', parsed), null);
  });

  it('builds a valid POSIX ustar tar archive in stage-wsl-runner.mjs that extracts cleanly via real tar', { skip: POSIX_TAR_SKIP_REASON }, async () => {
    const { buildTarBuffer } = await import('../../scripts/stage-wsl-runner.mjs');
    const tarBuf = buildTarBuffer([
      { path: 'dist/packages/wsl-runner/src/main.js', content: 'console.log("ok");\n', mode: 0o644 },
      { path: 'packages/bootstrap/provision-wsl.sh', content: '#!/usr/bin/env bash\necho hi\n', mode: 0o755 },
    ]);
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-tar-unit-'));
    try {
      const res = spawnSync('tar', ['-xf', '-', '-C', outDir], { input: tarBuf, encoding: 'utf8' });
      assert.equal(res.status, 0, res.stderr);
      const extractedJs = path.join(outDir, 'dist/packages/wsl-runner/src/main.js');
      const extractedSh = path.join(outDir, 'packages/bootstrap/provision-wsl.sh');
      assert.equal(fs.readFileSync(extractedJs, 'utf8'), 'console.log("ok");\n');
      assert.equal(fs.readFileSync(extractedSh, 'utf8'), '#!/usr/bin/env bash\necho hi\n');
      if (!IS_WINDOWS) {
        assert.notEqual(fs.statSync(extractedSh).mode & 0o111, 0, 'Executable bit must be preserved');
      }
    } finally {
      fs.rmSync(outDir, { recursive: true, force: true });
    }
  });

  it('masks sensitive $HOME config and credential dirs read-only inside buildBwrapArgs', { skip: IS_WINDOWS ? 'bwrap POSIX path builder runs inside Linux/WSL runner' : false }, () => {
    const fakeHome = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-home-mask-'));
    const ws = path.join(fakeHome, 'workspace');
    try {
      fs.mkdirSync(ws, { recursive: true });
      fs.mkdirSync(path.join(fakeHome, '.dsh'), { recursive: true });
      fs.mkdirSync(path.join(fakeHome, '.config', 'dsh-wsl-sandbox'), { recursive: true });
      fs.mkdirSync(path.join(fakeHome, '.ssh'), { recursive: true });
      fs.writeFileSync(path.join(fakeHome, '.git-credentials'), 'https://user:secret@example.com\n');

      const plan = buildBwrapArgs({
        argv: ['/bin/true'],
        cwd: ws,
        workspaceRoot: ws,
        homeDir: fakeHome,
        mode: 'workspace-write',
        networkMode: 'offline',
        supportsDisableUserns: true,
        env: { HOME: fakeHome, PATH: '/usr/bin:/bin' },
        emptyMaskFilePath: '/dev/null',
      });

      assert.ok(plan.maskedConfigPaths.includes(path.join(fakeHome, '.dsh')));
      assert.ok(plan.maskedConfigPaths.includes(path.join(fakeHome, '.config', 'dsh-wsl-sandbox')));
      assert.ok(plan.maskedConfigPaths.includes(path.join(fakeHome, '.ssh')));
      assert.ok(plan.maskedConfigPaths.includes(path.join(fakeHome, '.git-credentials')));

      // Verify both --tmpfs AND --remount-ro are emitted for ~/.dsh so AI has ZERO read or write access
      const dshTmpfsIdx = plan.bwrapArgs.indexOf(path.join(fakeHome, '.dsh'));
      assert.ok(dshTmpfsIdx > 0 && plan.bwrapArgs[dshTmpfsIdx - 1] === '--tmpfs');
      assert.equal(plan.bwrapArgs[dshTmpfsIdx + 1], '--remount-ro');
      assert.equal(plan.bwrapArgs[dshTmpfsIdx + 2], path.join(fakeHome, '.dsh'));
    } finally {
      fs.rmSync(fakeHome, { recursive: true, force: true });
    }
  });
});
