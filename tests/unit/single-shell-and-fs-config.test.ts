import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import {
  ApprovalController,
  buildBwrapArgs,
  deobfuscatePowerShell,
  evaluateBashCommand,
  evaluatePwshCommand,
  SandboxError,
  type SessionBinding,
} from '../../packages/core/src/index.ts';
import { ConfigStore } from '../../packages/dsh-plugin/src/config-store.ts';
import { ConfinedFsService } from '../../packages/wsl-runner/src/fs-service.ts';
import { ConfinedProcManager } from '../../packages/wsl-runner/src/proc-manager.ts';
import { ConfinedTerminalManager } from '../../packages/wsl-runner/src/pty-manager.ts';

function makeBinding(workspaceRoot: string, overrides?: Partial<SessionBinding>): SessionBinding {
  return {
    sessionId: 'unit-sess',
    distribution: 'Ubuntu-24.04',
    uid: process.getuid ? process.getuid() : 1000,
    gid: process.getgid ? process.getgid() : 1000,
    username: 'dev',
    arch: process.arch === 'arm64' ? 'aarch64' : 'x86_64',
    cwd: workspaceRoot,
    workspaceRoot,
    profile: 'workspace-write',
    revision: 'rev-1',
    generation: 1,
    verifiedAt: new Date().toISOString(),
    runnerId: 'runner-unit',
    bwrapPath: '/usr/bin/bwrap',
    bwrapSupportsDisableUserns: true,
    seccompEnforced: true,
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
  it('builds complete sandbox argv with --remount-ro /, Checklist B locks, .env masking, shares, and device binds', async () => {
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

  it('preserves working directory in ConfinedTerminalManager even when command calls exit 0', async () => {
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
  it('writes 0600 config atomically, recovers from corrupt file, and validates network/transport fields', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-cfg-unit-'));
    const cfgPath = path.join(dir, 'config.json');
    try {
      fs.writeFileSync(cfgPath, '{not-valid-json', 'utf8');
      const store = new ConfigStore({
        filePath: cfgPath,
        initial: { workspaceRoot: '/home/dev/ws', distro: 'Ubuntu-24.04' },
      });
      assert.equal(store.get().distro, 'Ubuntu-24.04');

      const st = fs.statSync(cfgPath);
      assert.equal(st.mode & 0o777, 0o600);

      const updated = store.updateBasic({
        transportMode: 'local-linux',
        upstreamProxy: 'socks5://127.0.0.1:10808',
      });
      assert.equal(updated.transportMode, 'local-linux');
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

  it('auto-converts Windows folder paths for single-directory /shares mounting while blocking whole drives & Windows system roots', async () => {
    const { normalizeSharePathInput, validateShareEntry } = await import('../../packages/core/src/index.ts');

    assert.equal(normalizeSharePathInput('D:\\Datasets\\ESP32\\'), '/mnt/d/Datasets/ESP32');
    assert.equal(
      normalizeSharePathInput('"C:\\Users\\Alice\\Downloads\\spec-v2"'),
      '/mnt/c/Users/Alice/Downloads/spec-v2',
    );

    const validated = validateShareEntry({
      id: '',
      alias: '',
      sourceLinuxPath: 'D:\\Datasets\\ESP32-Docs',
      mode: 'ro',
    });
    assert.equal(validated.alias, 'ESP32-Docs');
    assert.equal(validated.sourceLinuxPath, '/mnt/d/Datasets/ESP32-Docs');
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
      '\\\\wsl.localhost\\Ubuntu-24.04\\home\\dev',
    ]) {
      assert.throws(
        () => validateShareEntry({ id: 'sh-bad', alias: 'bad', sourceLinuxPath: forbidden, mode: 'ro' }),
        (err: unknown) => err instanceof SandboxError && err.code === 'POLICY_BLOCK',
        `Expected POLICY_BLOCK for forbidden share input: ${forbidden}`,
      );
    }
  });

  it('supports arbitrary custom backupDir, lists backup items, and confines open-explorer strictly to non-executable backup files', async () => {
    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-custom-bk-'));
    const customBkDir = path.join(tmpRoot, 'my-wsl-backups');
    const cfgFile = path.join(tmpRoot, 'config.json');
    try {
      const { ApprovalBridge } = await import('../../packages/dsh-plugin/src/approval-bridge.ts');
      const { WslSandboxSessionManager } = await import('../../packages/dsh-plugin/src/tools.ts');
      const { registerWslSandboxWebApi } = await import('../../packages/dsh-plugin/src/web-api.ts');
      const typeMod = await import('../../packages/dsh-plugin/src/cordis-types.ts');
      void typeMod;

      const store = new ConfigStore({
        filePath: cfgFile,
        initial: { workspaceRoot: '/home/dev/ws', distro: 'Ubuntu-24.04' },
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

      // 1. Backup to arbitrary custom backupDir
      const bkRes = await invoke('POST', '/wsl-sandbox/api/wsl-config/backup', { backupDir: customBkDir });
      assert.equal(bkRes.status, 200);
      assert.equal(bkRes.payload.backupDir, customBkDir);
      assert.equal(store.get().backupDir, customBkDir);

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
