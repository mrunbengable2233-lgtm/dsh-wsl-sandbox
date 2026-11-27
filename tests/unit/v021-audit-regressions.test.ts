import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { after, describe, it } from 'node:test';
import {
  buildDefaultSandboxPath,
  disposeSystemPwshParser,
  evaluatePwshCommand,
  type ProbeResponse,
  parsePs1FileWithSystemParser,
  SandboxError,
  type SessionBinding,
  WSL_SHARED_NODE_EXEC_SH,
  WSL_SYSTEM_NODE_DIRS,
} from '../../packages/core/src/index.ts';
import { ApprovalBridge } from '../../packages/dsh-plugin/src/approval-bridge.ts';
import { ConfigStore, validateFullConfig } from '../../packages/dsh-plugin/src/config-store.ts';
import type {
  DshCordisContext,
  DshHttpHandler,
  DshPreToolDecision,
  DshRealToolExecution,
  DshToolDefinition,
  DshToolGuard,
  DshWaterfallListener,
  DshWebServerRoute,
} from '../../packages/dsh-plugin/src/cordis-types.ts';
import { apply as applyWslSandbox } from '../../packages/dsh-plugin/src/index.ts';
import { buildWslRoutingPromptSection } from '../../packages/dsh-plugin/src/prompt-injector.ts';
import { evaluateBootstrapCommandGate } from '../../packages/dsh-plugin/src/pwsh-hook.ts';
import { createWslSandboxTools, WslSandboxSessionManager } from '../../packages/dsh-plugin/src/tools.ts';
import { registerWslSandboxWebApi } from '../../packages/dsh-plugin/src/web-api.ts';
import {
  discoverWslDistros,
  discoverWslDistrosAsync,
  mergeWslDistrosWithLxss,
  parseRegQueryLxssOutput,
  parseWslListVerbose,
  parseWslVersionOutput,
} from '../../packages/dsh-plugin/src/wsl-discovery.ts';
import { WslTransport } from '../../packages/dsh-plugin/src/wsl-transport.ts';
import { stageRunnerIntoWsl, stageRunnerIntoWslAsync } from '../../scripts/stage-wsl-runner.mjs';
import { BUILT_RUNNER_PATH, IS_WINDOWS, REPO_ROOT } from '../test-env.ts';

function makeBinding(overrides?: Partial<SessionBinding>): SessionBinding {
  return {
    sessionId: 'sess-v021-unit',
    backend: 'wsl',
    wslVersion: 2,
    distribution: 'AI workspace',
    uid: 1000,
    username: 'alice',
    arch: process.arch === 'arm64' ? 'aarch64' : 'x86_64',
    workspaceRoot: '/home/alice/workspace',
    cwd: '/home/alice/workspace',
    profile: 'workspace-write',
    revision: 'rev-1',
    generation: 1,
    runnerId: 'runner-v021',
    sandboxReady: true,
    enforcement: 'full',
    supportsDisableUserns: true,
    probedSockets: [],
    authorizedShares: [],
    authorizedDevices: [],
    ...overrides,
  };
}

describe('v0.2.1 Audit Regressions — 100% Hermetic Host & Plugin Guarantees', () => {
  after(async () => {
    await disposeSystemPwshParser();
  });

  it('enforces DSH_WSL_NO_HOST_SPAWN=1 across discovery, WslTransport, stage-wsl-runner, and open-explorer', async () => {
    const prev = process.env.DSH_WSL_NO_HOST_SPAWN;
    process.env.DSH_WSL_NO_HOST_SPAWN = '1';
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-nospawn-'));
    const bkDir = path.join(tmpDir, 'backups');
    try {
      const syncDisc = discoverWslDistros();
      assert.deepEqual(syncDisc.distros, []);

      const asyncDisc = await discoverWslDistrosAsync();
      assert.deepEqual(asyncDisc.distros, []);

      const transport = new WslTransport({
        mode: 'wsl',
        distro: 'AI workspace',
        runnerPath: '/home/alice/.local/share/dsh-wsl-sandbox/runner/dist/packages/wsl-runner/src/main.js',
      });
      await assert.rejects(
        () => transport.ensureStarted(),
        (err: unknown) =>
          err instanceof SandboxError &&
          err.code === 'BACKEND_UNAVAILABLE' &&
          /DSH_WSL_NO_HOST_SPAWN=1/.test(err.message),
      );
      await transport.dispose();

      assert.throws(
        () => stageRunnerIntoWsl({ distro: 'Ubuntu-26.04', repoRoot: REPO_ROOT }),
        /DSH_WSL_NO_HOST_SPAWN=1/,
      );
      await assert.rejects(
        () => stageRunnerIntoWslAsync({ distro: 'Ubuntu-26.04', repoRoot: REPO_ROOT }),
        /DSH_WSL_NO_HOST_SPAWN=1/,
      );

      // Verify open-explorer returns launched=false under DSH_WSL_NO_HOST_SPAWN=1
      const store = new ConfigStore({
        filePath: path.join(tmpDir, 'config.json'),
        initial: {
          transportMode: 'wsl',
          distro: 'AI workspace',
          workspaceRoot: '/home/alice/workspace',
          runnerPath: '/home/alice/.local/share/dsh-wsl-sandbox/runner/dist/packages/wsl-runner/src/main.js',
          backupDir: bkDir,
        },
      });
      const bridge = new ApprovalBridge({ configStore: store });
      const mgr = new WslSandboxSessionManager({ configStore: store, approvalBridge: bridge });
      const routes = new Map<string, DshHttpHandler>();
      registerWslSandboxWebApi(
        {
          http: {
            route: (m, p, h) => {
              routes.set(`${m} ${p}`, h);
              return () => {};
            },
          },
        },
        { configStore: store, sessionManager: mgr, approvalBridge: bridge },
      );
      fs.mkdirSync(bkDir, { recursive: true });
      let status = 0;
      let jsonBody: Record<string, unknown> = {};
      await routes.get('POST /wsl-sandbox/api/wsl-config/open-explorer')!(
        {
          method: 'POST',
          path: '/wsl-sandbox/api/wsl-config/open-explorer',
          params: {},
          query: {},
          body: { targetPath: bkDir },
          headers: {},
        },
        {
          status(c) { status = c; return this; },
          header() { return this; },
          json(p) { jsonBody = p as Record<string, unknown>; },
          html() {},
          text() {},
        },
      );
      assert.equal(status, 200);
      assert.equal(jsonBody.launched, false);
      await mgr.dispose();
    } finally {
      if (prev === undefined) delete process.env.DSH_WSL_NO_HOST_SPAWN;
      else process.env.DSH_WSL_NO_HOST_SPAWN = prev;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('ConfigStore.loadOrInit preserves persisted config over initial defaults and validates DIY distro & runnerPath', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-cfg-prio-'));
    const cfgPath = path.join(tmpDir, 'config.json');
    try {
      fs.writeFileSync(
        cfgPath,
        JSON.stringify(
          {
            revision: 'rev-7',
            enabled: true,
            transportMode: 'wsl',
            distro: 'AI workspace',
            username: 'alice',
            workspaceRoot: '/home/alice/workspace',
            runnerPath: '/home/alice/.local/share/dsh-wsl-sandbox/runner/dist/packages/wsl-runner/src/main.js',
            environmentProfile: 'universal',
            sandboxMode: 'workspace-write',
            approvalPolicyMode: 'balanced',
            networkMode: 'allowlist-proxy',
            upstreamProxy: '',
            mirrorCn: false,
            cacheMode: 'workspace-persistent',
            logLevel: 'info',
            approvalTimeoutMs: 60_000,
            enablePwshGuard: true,
            enablePromptInjection: true,
            unmaskedEnvWorkspaces: [],
            backupDir: path.join(tmpDir, 'backups'),
            advanced: {
              shares: [],
              deviceNodes: [],
              localLabCidrs: [],
              localLabPorts: [],
              customAllowedDomains: [],
            },
          },
          null,
          2,
        ),
        'utf8',
      );

      const store = new ConfigStore({
        filePath: cfgPath,
        persistToDisk: true,
        initial: {
          distro: 'Ubuntu-26.04',
          environmentProfile: 'core',
          workspaceRoot: '/home/dev/workspace',
        },
      });

      assert.equal(store.get().distro, 'AI workspace');
      assert.equal(store.get().environmentProfile, 'universal');
      assert.equal(store.get().username, 'alice');

      // Validate DIY distro names and runnerPath rules
      const validWsl = validateFullConfig({
        ...store.get(),
        distro: 'Ubuntu (Lab 24.04)',
      });
      assert.equal(validWsl.distro, 'Ubuntu (Lab 24.04)');

      for (const badRunner of [
        '/mnt/c/Users/alice/runner/main.js',
        '/home/alice/runner.exe',
        'dist/packages/wsl-runner/src/main.js',
        '/home/alice/bad\npath.js',
      ]) {
        assert.throws(
          () => validateFullConfig({ ...store.get(), transportMode: 'wsl', runnerPath: badRunner }),
          SandboxError,
          `Expected runnerPath rejection in wsl mode: ${badRunner}`,
        );
      }

      // local-linux mode on Windows permits host BUILT_RUNNER_PATH
      const localLinuxValid = validateFullConfig({
        ...store.get(),
        transportMode: 'local-linux',
        runnerPath: BUILT_RUNNER_PATH,
      });
      assert.equal(localLinuxValid.runnerPath, BUILT_RUNNER_PATH);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('apply honors enableHostPwshGuard, function-style ctx.logger, non-duplicate routes, and preserves WSL session rules during host pwsh L3', async () => {
    const prev = process.env.DSH_WSL_NO_HOST_SPAWN;
    process.env.DSH_WSL_NO_HOST_SPAWN = '1';
    try {
      // 1. enableHostPwshGuard: false + function-style ctx.logger
      let loggerScope = '';
      const infoMsgs: string[] = [];
      const guardsDisabled: DshToolGuard[] = [];
      const hDisabled = applyWslSandbox(
        {
          logger: (scope) => {
            loggerScope = scope;
            return {
              info: (msg) => infoMsgs.push(msg),
              warn: () => {},
              error: () => {},
            };
          },
          tools: {
            register: () => () => {},
            guard: (fn) => {
              guardsDisabled.push(fn);
              return () => {};
            },
          },
        },
        {
          persistConfig: false,
          persistLogs: false,
          enableHostPwshGuard: false,
        },
      );
      assert.equal(loggerScope, 'dsh-wsl-sandbox');
      assert.equal(infoMsgs.length, 1);
      assert.equal(hDisabled.configStore.get().enablePwshGuard, false);
      assert.equal(
        guardsDisabled[0]!({ name: 'pwsh', arguments: { command: 'Format-Volume -DriveLetter C' } }),
        undefined,
        'Monotonic guard must pass through when enableHostPwshGuard=false',
      );
      await hDisabled.dispose();

      // 2. enableHostPwshGuard: true + Cordis ctx with BOTH http & webServer + host pwsh L3 preserving WSL session rules
      const routeKeys = new Set<string>();
      const webRoutes: DshWebServerRoute[] = [];
      const preExecListeners: Array<DshWaterfallListener<DshRealToolExecution, DshPreToolDecision>> = [];
      const guardsEnabled: DshToolGuard[] = [];

      const cordisCtx: DshCordisContext = {
        tools: {
          register: () => () => {},
          guard: (fn) => {
            guardsEnabled.push(fn);
            return () => {};
          },
        },
        http: {
          route: (m, p) => {
            const k = `${m} ${p}`;
            assert.equal(routeKeys.has(k), false, `Duplicate http.route detected: ${k}`);
            routeKeys.add(k);
            return () => routeKeys.delete(k);
          },
        },
        webServer: {
          register: (r) => {
            webRoutes.push(r);
            return () => {};
          },
        },
        inject: (_deps, cb) => {
          cb(cordisCtx);
        },
        waterfall: (event, listener) => {
          if (event === 'tools/pre-execute') {
            preExecListeners.push(listener as DshWaterfallListener<DshRealToolExecution, DshPreToolDecision>);
          }
          return () => {};
        },
        effect: () => {},
      };

      const hEnabled = applyWslSandbox(cordisCtx, {
        persistConfig: false,
        persistLogs: false,
        enableHostPwshGuard: true,
        initialConfig: {
          transportMode: 'wsl',
          distro: 'AI workspace',
          approvalPolicyMode: 'strict',
        },
      });
      assert.equal(hEnabled.configStore.get().enablePwshGuard, true);
      assert.ok(routeKeys.size > 0);
      assert.equal(webRoutes.length, 2);

      // Seed an active WSL binding + cached WSL session rule on ApprovalBridge
      const wslBinding = makeBinding({ revision: hEnabled.configStore.get().revision });
      hEnabled.approvalBridge.setBinding(wslBinding);
      const cachedTicketPromise = hEnabled.approvalBridge.requestApproval(
        wslBinding,
        {
          kind: 'dangerous-command',
          summary: 'Cacheable test command',
          command: 'npm test -- --runInBand',
          reasons: ['test'],
          touchesPhysicalDevice: false,
          suggestedPrefix: ['npm', 'test'],
        },
        { requireIndependentFallback: false },
      );
      while (hEnabled.approvalBridge.listPending().length === 0) {
        await new Promise((r) => setTimeout(r, 10));
      }
      const firstPending = hEnabled.approvalBridge.listPending()[0]!;
      hEnabled.approvalBridge.decidePending(firstPending.requestId, 'allow-session-rule');
      (await cachedTicketPromise).consume();
      assert.deepEqual(hEnabled.approvalBridge.getSessionRules(), [['npm', 'test']]);

      // Run host pwsh L3 through pre-execute listener (must NOT spawn wsl.exe and must NOT wipe WSL session rules!)
      const hostPwshPromise = preExecListeners[0]!(
        {
          name: 'pwsh',
          arguments: { command: 'reg add HKCU\\Software\\Test /v Foo /d Bar' },
          callId: 'host-pwsh-l3',
        },
        async () => ({ kind: 'allow' }),
      );
      while (hEnabled.approvalBridge.listPending().length === 0) {
        await new Promise((r) => setTimeout(r, 10));
      }
      const hostPending = hEnabled.approvalBridge.listPending()[0]!;
      assert.equal(hostPending.kind, 'host-pwsh-command');
      hEnabled.approvalBridge.decidePending(hostPending.requestId, 'allow-once');
      const hostDecision = await hostPwshPromise;
      assert.deepEqual(hostDecision, { kind: 'allow' });
      assert.deepEqual(
        hEnabled.approvalBridge.getSessionRules(),
        [['npm', 'test']],
        'Host pwsh L3 approval must NOT wipe active WSL session rules',
      );
      await hEnabled.dispose();
    } finally {
      if (prev === undefined) delete process.env.DSH_WSL_NO_HOST_SPAWN;
      else process.env.DSH_WSL_NO_HOST_SPAWN = prev;
    }
  });

  it('parses English and Chinese wsl.exe -l -v with spaced DIY distro names and reg.exe Lxss output', () => {
    const enOut = [
      '  NAME                   STATE           VERSION',
      '* AI workspace           Running         2',
      '  docker-desktop         Running         2',
    ].join('\r\n');
    const zhOut = [
      '  名称                   状态            版本',
      '* AI workspace           正在运行        2',
      '  docker-desktop         已停止          2',
    ].join('\r\n');

    const regSample = [
      'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss',
      '    DefaultDistribution    REG_SZ    {11111111-1111-1111-1111-111111111111}',
      '',
      'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss\\{11111111-1111-1111-1111-111111111111}',
      '    State    REG_DWORD    0x1',
      '    DistributionName    REG_SZ    AI workspace',
      '    Version    REG_DWORD    0x2',
      '    BasePath    REG_SZ    \\\\?\\D:\\WSL\\AI workspace',
      '    DefaultUid    REG_DWORD    0x3e8',
    ].join('\r\n');

    const lxss = parseRegQueryLxssOutput(regSample);
    const entry = lxss.get('ai workspace');
    assert.ok(entry);
    assert.equal(entry.DistributionName, 'AI workspace');
    assert.equal(entry.BasePath, 'D:\\WSL\\AI workspace');
    assert.equal(entry.Version, 2);
    assert.equal(entry.DefaultUid, 1000);

    for (const raw of [enOut, zhOut]) {
      const utf16Bom = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(raw, 'utf16le')]);
      const parsed = mergeWslDistrosWithLxss(parseWslListVerbose(utf16Bom), lxss);
      const ai = parsed.find((d) => d.name === 'AI workspace');
      const docker = parsed.find((d) => d.name === 'docker-desktop');
      assert.ok(ai);
      assert.equal(ai.isDefault, true);
      assert.equal(ai.wslVersion, 2);
      assert.equal(ai.supported, true);
      assert.equal(ai.isCustomDiskLocation, true);
      assert.equal(ai.basePath, 'D:\\WSL\\AI workspace');
      assert.equal(ai.registeredDefaultUid, 1000);
      assert.ok(docker);
      assert.equal(docker.isInternalContainer, true);
      assert.equal(docker.supported, false);
    }
  });

  it('WslSandboxSessionManager supports single-flight bind, placeholder auto-discovery, auto-staging, non-disruptive updates, and stateful terminal CWD', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-mgr-mock-'));
    try {
      // 1. Placeholder Ubuntu-26.04 -> auto-discovers 'AI workspace', probes 'alice', stages runner, single-flight probe
      const store = new ConfigStore({
        filePath: path.join(tmpDir, 'cfg1.json'),
        initial: {
          transportMode: 'wsl',
          distro: 'Ubuntu-26.04',
          workspaceRoot: '/home/dev/workspace',
          runnerPath: '/home/dev/.local/share/dsh-wsl-sandbox/runner/dist/packages/wsl-runner/src/main.js',
        },
      });
      const bridge = new ApprovalBridge({ configStore: store });

      let stageCalls = 0;
      let probeRpcCalls = 0;
      let invalidateRpcCalls = 0;
      let disposeCalls = 0;
      const termExecCalls: Array<Record<string, unknown>> = [];
      const termResetCalls: Array<Record<string, unknown>> = [];

      const mgr = new WslSandboxSessionManager({
        configStore: store,
        approvalBridge: bridge,
        sessionId: 'sess-sf-1',
        discoverDistros: async () => ({
          platform: 'win32',
          recommendedDistro: 'AI workspace',
          distros: [
            {
              name: 'AI workspace',
              state: 'Running',
              wslVersion: 2,
              isDefault: true,
              isInternalContainer: false,
              supported: true,
            },
          ],
          wslSettingsSharedPaths: {
            windowsGlobalConfig: '%USERPROFILE%\\.wslconfig',
            distroConfig: '/etc/wsl.conf',
            lxssRegistryKey: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss',
          },
        }),
        probeDistroUser: async (distro) => ({
          distro,
          uid: 1000,
          username: 'alice',
          homeDir: '/var/home/alice',
        }),
        checkStagedVersion: async () => null,
        stageRunner: async ({ distro, username }) => {
          stageCalls += 1;
          assert.equal(distro, 'AI workspace');
          assert.equal(username, 'alice');
          return {
            runnerPath: '/var/home/alice/.local/share/dsh-wsl-sandbox/runner/dist/packages/wsl-runner/src/main.js',
            version: '0.3.0',
          };
        },
        transportFactory: (cfg) => ({
          isRunning: () => true,
          getRunnerNodeInfo: () => ({ nodeVersion: 'v24.0.0', nodeExecPath: '/usr/bin/node' }),
          setRunnerLogLevel: async () => {},
          invalidate: async () => {
            invalidateRpcCalls += 1;
            return 0;
          },
          dispose: async () => {
            disposeCalls += 1;
          },
          call: async <T = unknown>(method: string, params: Record<string, unknown>): Promise<T> => {
            if (method === 'probe') {
              probeRpcCalls += 1;
              await new Promise((r) => setTimeout(r, 20));
              const resp: ProbeResponse = {
                sessionId: String(params.sessionId),
                backend: 'wsl',
                wslVersion: 2,
                distribution: cfg.distro,
                uid: 1000,
                username: 'alice',
                arch: 'x86_64',
                workspaceRoot: cfg.workspaceRoot,
                cwd: cfg.workspaceRoot,
                profile: cfg.sandboxMode,
                revision: String(params.revision ?? cfg.revision),
                runnerId: 'mock-runner-1',
                sandboxReady: true,
                enforcement: 'full',
                supportsDisableUserns: true,
                homeDir: '/var/home/alice',
              };
              return resp as T;
            }
            if (method === 'proxy.configure') {
              return { enabled: true } as T;
            }
            if (method === 'term.exec') {
              termExecCalls.push(params);
              const cmd = String(params.command ?? '');
              const nextCwd = cmd.includes('cd packages')
                ? '/var/home/alice/workspace/packages'
                : String(params.cwd);
              return {
                exitCode: 0,
                signal: null,
                timedOut: false,
                aborted: false,
                timeoutMs: 5000,
                stdout: { text: 'ok', truncated: false, totalBytes: 2 },
                stderr: { text: '', truncated: false, totalBytes: 0 },
                sandbox: { mode: 'workspace-write', denied: false, enforcement: 'full', runnerFailed: false, denialMatches: [] },
                terminalId: String(params.terminalId),
                cwd: nextCwd,
              } as T;
            }
            if (method === 'term.reset') {
              termResetCalls.push(params);
              return { reset: true } as T;
            }
            return {} as T;
          },
        }),
      });

      // Single-flight concurrent ensureBound() calls
      const [b1, b2, b3] = await Promise.all([mgr.ensureBound(), mgr.ensureBound(), mgr.ensureBound()]);
      assert.equal(b1, b2);
      assert.equal(b2, b3);
      assert.equal(b1.distribution, 'AI workspace');
      assert.equal(b1.workspaceRoot, '/var/home/alice/workspace');
      assert.equal(stageCalls, 1);
      assert.equal(probeRpcCalls, 1);

      // computeCacheDir honors probedHomeDir
      const cacheDir = mgr.computeCacheDir(b1, store.get());
      assert.ok(cacheDir?.startsWith('/var/home/alice/.cache/dsh-wsl-sandbox/'));

      // Non-disruptive updates do NOT bump generation, wipe session rules, or dispose/invalidate transport
      const genBefore = mgr.getGeneration();
      store.updateBasic({
        logLevel: 'debug',
        backupDir: path.join(tmpDir, 'custom-bk'),
        approvalTimeoutMs: 90_000,
        enablePromptInjection: false,
      });
      await new Promise((r) => setTimeout(r, 20));
      assert.equal(mgr.getGeneration(), genBefore);
      assert.equal(invalidateRpcCalls, 0);
      assert.equal(disposeCalls, 0);

      // Stateful wsl_terminal CWD tracking + term.reset sessionId
      const tools = createWslSandboxTools(mgr, store, bridge);
      const wslTerminal = tools.find((t) => t.name === 'wsl_terminal')!;
      await wslTerminal.execute({ terminalId: 't1', command: 'cd packages && pwd' });
      assert.equal(probeRpcCalls, 1);
      assert.equal(mgr.getGeneration(), genBefore);
      assert.equal(termExecCalls[0]?.explicitCwd, false);
      assert.equal(termExecCalls[0]?.cwd, '/var/home/alice/workspace');

      await wslTerminal.execute({ terminalId: 't1', command: 'ls -la' });
      assert.equal(termExecCalls[1]?.explicitCwd, false);
      assert.equal(termExecCalls[1]?.cwd, '/var/home/alice/workspace/packages');

      await wslTerminal.execute({ terminalId: 't1', reset: true, command: 'pwd' });
      assert.deepEqual(termResetCalls[0], { terminalId: 't1', sessionId: 'sess-sf-1' });
      assert.equal(termExecCalls[2]?.cwd, '/var/home/alice/workspace');

      await mgr.dispose();

      // 2. Explicit user-chosen distro MUST NEVER silently switch to recommendedDistro
      const storeCustom = new ConfigStore({
        filePath: path.join(tmpDir, 'cfg2.json'),
        initial: {
          transportMode: 'wsl',
          distro: 'MyExplicitCustomDistro',
          workspaceRoot: '/home/dev/workspace',
          runnerPath: '/home/dev/.local/share/dsh-wsl-sandbox/runner/dist/packages/wsl-runner/src/main.js',
        },
      });
      const bridgeCustom = new ApprovalBridge({ configStore: storeCustom });
      let seenProbeDistro = '';
      const mgrCustom = new WslSandboxSessionManager({
        configStore: storeCustom,
        approvalBridge: bridgeCustom,
        discoverDistros: async () => ({
          platform: 'win32',
          recommendedDistro: 'OtherDistro',
          distros: [
            {
              name: 'OtherDistro',
              state: 'Running',
              wslVersion: 2,
              isDefault: true,
              isInternalContainer: false,
              supported: true,
            },
          ],
          wslSettingsSharedPaths: {
            windowsGlobalConfig: '%USERPROFILE%\\.wslconfig',
            distroConfig: '/etc/wsl.conf',
            lxssRegistryKey: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss',
          },
        }),
        probeDistroUser: async (distro) => {
          seenProbeDistro = distro;
          return { distro, uid: 1000, username: 'bob', homeDir: '/home/bob' };
        },
        checkStagedVersion: async () => '0.3.0',
        stageRunner: async () => ({ runnerPath: '/home/bob/main.js', version: '0.3.0' }),
        transportFactory: (cfg) => ({
          isRunning: () => true,
          getRunnerNodeInfo: () => ({}),
          setRunnerLogLevel: async () => {},
          invalidate: async () => 0,
          dispose: async () => {},
          call: async <T = unknown>(method: string, params: Record<string, unknown>): Promise<T> => {
            if (method === 'probe') {
              return {
                sessionId: String(params.sessionId),
                backend: 'wsl',
                wslVersion: 2,
                distribution: cfg.distro,
                uid: 1000,
                username: 'bob',
                arch: 'x86_64',
                workspaceRoot: cfg.workspaceRoot,
                cwd: cfg.workspaceRoot,
                profile: cfg.sandboxMode,
                revision: cfg.revision,
                runnerId: 'mock-runner-2',
                sandboxReady: true,
                enforcement: 'full',
              } as T;
            }
            return {} as T;
          },
        }),
      });
      const boundCustom = await mgrCustom.ensureBound();
      assert.equal(seenProbeDistro, 'MyExplicitCustomDistro');
      assert.equal(boundCustom.distribution, 'MyExplicitCustomDistro');
      assert.equal(storeCustom.get().distro, 'MyExplicitCustomDistro');
      await mgrCustom.dispose();
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('web-api enforces DNS rebinding & CSRF protections on webServer and routes WSL-mode /api/agents-md over fs RPCs', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-websec-'));
    const store = new ConfigStore({
      filePath: path.join(tmpDir, 'config.json'),
      persistToDisk: true,
      initial: {
        transportMode: 'wsl',
        distro: 'AI workspace',
        username: 'alice',
        workspaceRoot: '/home/alice/workspace',
        runnerPath: '/home/alice/.local/share/dsh-wsl-sandbox/runner/dist/packages/wsl-runner/src/main.js',
      },
    });
    const bridge = new ApprovalBridge({ configStore: store });
    let virtualAgentsMd: string | null = null;
    const rpcCalls: string[] = [];

    const mgr = new WslSandboxSessionManager({
      configStore: store,
      approvalBridge: bridge,
      discoverDistros: async () => ({
        platform: 'win32',
        recommendedDistro: 'AI workspace',
        distros: [],
        wslSettingsSharedPaths: {
          windowsGlobalConfig: '%USERPROFILE%\\.wslconfig',
          distroConfig: '/etc/wsl.conf',
          lxssRegistryKey: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss',
        },
      }),
      probeDistroUser: async (d) => ({ distro: d, uid: 1000, username: 'alice', homeDir: '/home/alice' }),
      checkStagedVersion: async () => '0.3.0',
      stageRunner: async () => ({
        runnerPath: '/home/alice/.local/share/dsh-wsl-sandbox/runner/dist/packages/wsl-runner/src/main.js',
        version: '0.3.0',
      }),
      transportFactory: (cfg) => ({
        isRunning: () => true,
        getRunnerNodeInfo: () => ({}),
        setRunnerLogLevel: async () => {},
        invalidate: async () => 0,
        dispose: async () => {},
        call: async <T = unknown>(method: string, params: Record<string, unknown>): Promise<T> => {
          rpcCalls.push(method);
          if (method === 'probe') {
            return {
              sessionId: String(params.sessionId),
              backend: 'wsl',
              wslVersion: 2,
              distribution: cfg.distro,
              uid: 1000,
              username: 'alice',
              arch: 'x86_64',
              workspaceRoot: cfg.workspaceRoot,
              cwd: cfg.workspaceRoot,
              profile: cfg.sandboxMode,
              revision: cfg.revision,
              runnerId: 'mock-runner-web',
              sandboxReady: true,
              enforcement: 'full',
              homeDir: '/home/alice',
            } as T;
          }
          if (method === 'fs.read') {
            assert.equal(params.maskEnvSecrets, false);
            if (virtualAgentsMd === null) {
              throw new SandboxError('NOT_FOUND', 'AGENTS.md not found');
            }
            return { content: virtualAgentsMd } as T;
          }
          if (method === 'fs.write') {
            virtualAgentsMd = String(params.content ?? '');
            return { bytesWritten: Buffer.byteLength(virtualAgentsMd, 'utf8') } as T;
          }
          if (method === 'fs.delete') {
            virtualAgentsMd = null;
            return { deleted: true } as T;
          }
          if (method === 'env.doctor') {
            throw new SandboxError('BACKEND_UNAVAILABLE', 'WSL offline for test');
          }
          return {} as T;
        },
      }),
    });

    const webRoutes: DshWebServerRoute[] = [];
    registerWslSandboxWebApi(
      {
        webServer: {
          register: (r) => {
            webRoutes.push(r);
            return () => {};
          },
        },
      },
      { configStore: store, sessionManager: mgr, approvalBridge: bridge },
    );

    const server = http.createServer(async (req, res) => {
      const urlObj = new URL(req.url ?? '/', 'http://127.0.0.1');
      const pathname = urlObj.pathname.replace(/\/+$/, '') || '/';
      const exact = webRoutes.find((r) => r.kind === 'exact' && r.path === pathname);
      if (exact) {
        await exact.handler(req, res);
        return;
      }
      const prefix = webRoutes
        .filter((r) => r.kind === 'prefix' && (pathname === r.path || pathname.startsWith(r.path + '/')))
        .sort((a, b) => b.path.length - a.path.length)[0];
      if (prefix) {
        await prefix.handler(req, res);
        return;
      }
      res.writeHead(404).end('not found');
    });

    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as { port: number }).port;
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
      // 1. DNS rebinding Host header -> 403 FORBIDDEN_HOST via raw TCP socket
      const dnsRebindRes = await new Promise<string>((resolve, reject) => {
        const sock = net.connect(port, '127.0.0.1', () => {
          sock.write('GET /wsl-sandbox/api/status HTTP/1.1\r\nHost: evil.attacker.com:8080\r\nConnection: close\r\n\r\n');
        });
        const chunks: Buffer[] = [];
        sock.on('data', (d) => chunks.push(d));
        sock.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
        sock.on('error', reject);
      });
      assert.match(dnsRebindRes, /^HTTP\/1\.1 403 /);
      assert.match(dnsRebindRes, /FORBIDDEN_HOST/);

      // 2. Cross-port loopback Origin -> 403
      const crossPort = await fetch(`${baseUrl}/wsl-sandbox/api/config`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Origin: 'http://127.0.0.1:65534',
          'X-DSH-WSL-Client': '1',
        },
        body: JSON.stringify({ logLevel: 'warn' }),
      });
      assert.equal(crossPort.status, 403);

      // 3. Browser Origin missing X-DSH-WSL-Client -> 403
      const missingClientHdr = await fetch(`${baseUrl}/wsl-sandbox/api/config`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Origin: baseUrl,
        },
        body: JSON.stringify({ logLevel: 'warn' }),
      });
      assert.equal(missingClientHdr.status, 403);

      // 4. Valid Origin + X-DSH-WSL-Client: 1 -> 200
      const validBrowser = await fetch(`${baseUrl}/wsl-sandbox/api/config`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Origin: baseUrl,
          'X-DSH-WSL-Client': '1',
        },
        body: JSON.stringify({ logLevel: 'warn' }),
      });
      assert.equal(validBrowser.status, 200);

      // 5. CLI / Origin-less request -> 200
      const cliReq = await fetch(`${baseUrl}/wsl-sandbox/api/config`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ logLevel: 'info' }),
      });
      assert.equal(cliReq.status, 200);

      // 6. WSL-mode POST & DELETE /api/agents-md over fs.read/fs.write/fs.delete RPCs (zero Windows FS side effects)
      const postAgents = await fetch(`${baseUrl}/wsl-sandbox/api/agents-md`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      assert.equal(postAgents.status, 200);
      const postJson = (await postAgents.json()) as { ok: boolean; filePath: string; action: string };
      assert.equal(postJson.ok, true);
      assert.equal(postJson.filePath, 'wsl:AI workspace:/home/alice/workspace/AGENTS.md');
      assert.equal(postJson.action, 'created');
      assert.ok(virtualAgentsMd && virtualAgentsMd.includes('<!-- dsh-wsl-sandbox:start -->'));
      assert.equal(fs.existsSync(path.join(tmpDir, 'AGENTS.md')), false);

      const manifestAfterAdd = JSON.parse(
        fs.readFileSync(path.join(tmpDir, 'install-manifest.json'), 'utf8'),
      ) as { agentsMdFiles: string[] };
      assert.ok(manifestAfterAdd.agentsMdFiles.includes('wsl:AI workspace:/home/alice/workspace/AGENTS.md'));

      const delAgents = await fetch(`${baseUrl}/wsl-sandbox/api/agents-md`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      assert.equal(delAgents.status, 200);
      const delJson = (await delAgents.json()) as { ok: boolean; action: string };
      assert.equal(delJson.action, 'deleted-empty-file');
      assert.equal(virtualAgentsMd, null);
      assert.ok(rpcCalls.includes('fs.read') && rpcCalls.includes('fs.write') && rpcCalls.includes('fs.delete'));

      if (IS_WINDOWS) {
        const docRes = await fetch(`${baseUrl}/wsl-sandbox/api/doctor`);
        assert.equal(docRes.status, 200);
        const docJson = (await docRes.json()) as { ok: boolean; report: { verdict: string; os: { platform: string } } };
        assert.equal(docJson.ok, true);
        assert.equal(docJson.report.verdict, 'blocked');
        assert.equal(docJson.report.os.platform, 'win32');
      }
    } finally {
      await mgr.dispose();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('validates all .ps1 scripts statically with UTF-8 BOM + CRLF and verifies provision-wsl.sh uses pure LF', async () => {
    const ps1Files = [
      path.join(REPO_ROOT, 'packages', 'bootstrap', 'install-dsh-plugin.ps1'),
      path.join(REPO_ROOT, 'packages', 'bootstrap', 'uninstall-dsh-plugin.ps1'),
      path.join(REPO_ROOT, 'tests', 'windows-wsl-verify', 'verify-wsl2.ps1'),
    ];

    for (const filePath of ps1Files) {
      const buf = fs.readFileSync(filePath);
      assert.equal(buf[0], 0xef, `${path.basename(filePath)} missing UTF-8 BOM byte 0`);
      assert.equal(buf[1], 0xbb, `${path.basename(filePath)} missing UTF-8 BOM byte 1`);
      assert.equal(buf[2], 0xbf, `${path.basename(filePath)} missing UTF-8 BOM byte 2`);
      const text = buf.toString('utf8');
      assert.equal(/(?<!\r)\n/.test(text), false, `${path.basename(filePath)} must use CRLF line endings`);

      if (IS_WINDOWS) {
        const parsed = await parsePs1FileWithSystemParser(filePath);
        assert.equal(parsed.ok, true, `${path.basename(filePath)} parse failed: ${JSON.stringify(parsed.errors)}`);
        assert.equal(parsed.errorCount, 0);
      }
    }

    const provBuf = fs.readFileSync(path.join(REPO_ROOT, 'packages', 'bootstrap', 'provision-wsl.sh'));
    assert.equal(provBuf.includes(0x0d), false, 'provision-wsl.sh must have 0 CR (\\r) bytes (pure LF)');
  });

  it('enforces Controlled AI Bootstrap Channel step-order gate (-DryRun preview required before install/terminate), reloadFromDisk, and web preview APIs', async () => {
    const installCmd = '& ./packages/bootstrap/install-dsh-plugin.ps1 -NonInteractive -Distro "Ubuntu-24.04" -Profile standard -Provision';
    const previewCmd = '& ./packages/bootstrap/install-dsh-plugin.ps1 -NonInteractive -Distro "Ubuntu-24.04" -Profile standard -Provision -DryRun';
    const stageCmd = 'node ./scripts/stage-wsl-runner.mjs --distro Ubuntu-24.04';
    const uninstallCmd = '& ./packages/bootstrap/uninstall-dsh-plugin.ps1 -Yes';
    const terminateCmd = 'wsl.exe --terminate Ubuntu-24.04';

    // 1. Uninstall without -DryRun is ALWAYS L0 deny (closed or open channel)
    const closedState = { active: false, phase: 'idle' as const, previewedDryRun: false, remainingMs: 0 };
    assert.equal(
      evaluateBootstrapCommandGate(uninstallCmd, evaluatePwshCommand(uninstallCmd), closedState).verdict.decision,
      'deny',
    );
    // Non-dry-run install/staging when channel is CLOSED -> L0 deny (even with backtick obfuscation!)
    assert.equal(
      evaluateBootstrapCommandGate(installCmd, evaluatePwshCommand(installCmd), closedState).verdict.decision,
      'deny',
    );
    const backtickInstall = '& ./packages/bootstrap/install`-dsh-plugin.ps1 -NonInteractive -Distro Ubuntu-24.04 -Provision';
    assert.equal(
      evaluateBootstrapCommandGate(backtickInstall, evaluatePwshCommand(backtickInstall), closedState).verdict.decision,
      'deny',
    );
    assert.equal(
      evaluateBootstrapCommandGate(stageCmd, evaluatePwshCommand(stageCmd), closedState).verdict.decision,
      'deny',
    );
    // Plain rg / git mention must NOT trigger false-positive block
    const grepCmd = 'rg install-dsh-plugin.ps1 packages/bootstrap';
    assert.equal(
      evaluateBootstrapCommandGate(grepCmd, evaluatePwshCommand(grepCmd), closedState).verdict.decision,
      'allow',
    );

    // 2. When channel is OPEN (phase 1-probe, previewedDryRun=false):
    //    - Real install / staging / wsl --install / wsl --terminate MUST still be L0 deny!
    //    - Wrong targetDistro MUST be L0 deny!
    //    - Chaining with ';' MUST be L0 deny!
    //    - -DryRun preview returns L3 ask (single-shot) with bootstrapAction='preview'!
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-bootstrap-gate-'));
    try {
      const cfgPath = path.join(tmpDir, 'config.json');
      const store = new ConfigStore({
        filePath: cfgPath,
        persistToDisk: true,
        initial: {
          enabled: false,
          transportMode: 'wsl',
          distro: 'Ubuntu-24.04',
          workspaceRoot: '/home/alice/workspace',
          runnerPath: '/home/alice/.local/share/dsh-wsl-sandbox/runner/dist/packages/wsl-runner/src/main.js',
          backupDir: path.join(tmpDir, 'backups'),
        },
      });
      const bridge = new ApprovalBridge({ configStore: store });
      let reloadedSeen = false;
      const mgr = new WslSandboxSessionManager({
        configStore: store,
        approvalBridge: bridge,
        discoverDistros: async () => ({
          platform: 'win32',
          recommendedDistro: 'Ubuntu-24.04',
          distros: [],
          wslSettingsSharedPaths: {
            windowsGlobalConfig: '%USERPROFILE%\\.wslconfig',
            distroConfig: '/etc/wsl.conf',
            lxssRegistryKey: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss',
          },
        }),
        probeDistroUser: async (distro) => ({ distro, uid: 1000, username: 'alice', homeDir: '/home/alice' }),
        checkStagedVersion: async () => '0.3.0',
        transportFactory: (cfg) => ({
          isRunning: () => true,
          getRunnerNodeInfo: () => ({ nodeVersion: 'v24.0.0', nodeExecPath: '/usr/bin/node' }),
          setRunnerLogLevel: async () => {},
          invalidate: async () => 0,
          dispose: async () => {},
          call: async <T = unknown>(method: string, params: Record<string, unknown>): Promise<T> => {
            if (method === 'probe') {
              reloadedSeen = true;
              return {
                sessionId: String(params.sessionId),
                backend: 'wsl',
                wslVersion: 2,
                distribution: cfg.distro,
                uid: 1000,
                username: 'alice',
                arch: 'x86_64',
                workspaceRoot: cfg.workspaceRoot,
                cwd: cfg.workspaceRoot,
                profile: cfg.sandboxMode,
                revision: cfg.revision,
                runnerId: 'mock-bs-runner',
                sandboxReady: true,
                enforcement: 'full',
                homeDir: '/home/alice',
              } as T;
            }
            return {} as T;
          },
        }),
      });

      const bsOpen = mgr.setBootstrapChannel({ active: true, targetDistro: 'Ubuntu-24.04' });
      assert.equal(bsOpen.active, true);
      assert.equal(bsOpen.phase, '1-probe');
      assert.equal(bsOpen.previewedDryRun, false);

      assert.equal(
        evaluateBootstrapCommandGate(installCmd, evaluatePwshCommand(installCmd), bsOpen).verdict.decision,
        'deny',
      );
      assert.equal(
        evaluateBootstrapCommandGate(stageCmd, evaluatePwshCommand(stageCmd), bsOpen).verdict.decision,
        'deny',
      );
      assert.equal(
        evaluateBootstrapCommandGate(terminateCmd, evaluatePwshCommand(terminateCmd), bsOpen).verdict.decision,
        'deny',
      );
      assert.equal(
        evaluateBootstrapCommandGate(
          '& ./packages/bootstrap/install-dsh-plugin.ps1 -Distro OtherDistro -DryRun',
          evaluatePwshCommand('& ./packages/bootstrap/install-dsh-plugin.ps1 -Distro OtherDistro -DryRun'),
          bsOpen,
        ).verdict.decision,
        'deny',
      );
      assert.equal(
        evaluateBootstrapCommandGate(`${previewCmd}; echo pwned`, evaluatePwshCommand(`${previewCmd}; echo pwned`), bsOpen)
          .verdict.decision,
        'deny',
      );

      const previewEval = evaluateBootstrapCommandGate(previewCmd, evaluatePwshCommand(previewCmd), bsOpen);
      assert.equal(previewEval.verdict.decision, 'ask');
      assert.equal(previewEval.verdict.requiresSessionRuleBlocked, true);
      assert.equal(previewEval.bootstrapAction, 'preview');

      // System prompt injection while bootstrap channel is active includes 4-step preview card constraint
      const bsPrompt = buildWslRoutingPromptSection(store.get(), bsOpen);
      assert.match(bsPrompt, /安装脚本与变更预览卡片/);
      assert.match(bsPrompt, /NAT/);

      // Complete preview -> unlocks phase 2-previewed -> real install & single-distro terminate become L3 ask (single-shot)
      const bsPreviewed = mgr.markBootstrapPreviewCompleted('Ubuntu-24.04');
      assert.equal(bsPreviewed.phase, '2-previewed');
      assert.equal(bsPreviewed.previewedDryRun, true);

      const installEval = evaluateBootstrapCommandGate(installCmd, evaluatePwshCommand(installCmd), bsPreviewed);
      assert.equal(installEval.verdict.decision, 'ask');
      assert.equal(installEval.verdict.requiresSessionRuleBlocked, true);
      assert.equal(installEval.bootstrapAction, 'install');

      const termEval = evaluateBootstrapCommandGate(terminateCmd, evaluatePwshCommand(terminateCmd), bsPreviewed);
      assert.equal(termEval.verdict.decision, 'ask');
      assert.equal(termEval.verdict.requiresSessionRuleBlocked, true);
      assert.equal(termEval.bootstrapAction, 'terminate');

      // 3. Test web-api `/wsl-sandbox/api/bootstrap-preview` & `/wsl-sandbox/api/bootstrap-session`
      const routes = new Map<string, DshHttpHandler>();
      registerWslSandboxWebApi(
        {
          http: {
            route: (m, p, h) => {
              routes.set(`${m} ${p}`, h);
              return () => {};
            },
          },
        },
        { configStore: store, sessionManager: mgr, approvalBridge: bridge },
      );
      const invoke = async (method: string, routePath: string, body?: unknown, query: Record<string, string> = {}) => {
        let stCode = 0;
        let payload: Record<string, unknown> = {};
        await routes.get(`${method} ${routePath}`)!(
          { method, path: routePath, params: {}, query, body, headers: {} },
          {
            status(c) { stCode = c; return this; },
            header() { return this; },
            json(p) { payload = p as Record<string, unknown>; },
            html() {},
            text() {},
          },
        );
        return { status: stCode, payload };
      };

      const prevRes = await invoke('GET', '/wsl-sandbox/api/bootstrap-preview', undefined, { distro: 'Ubuntu-24.04' });
      assert.equal(prevRes.status, 200);
      assert.equal(prevRes.payload.ok, true);
      const previewScripts = prevRes.payload.scripts as Array<{ relPath: string; exists: boolean; sha256: string }>;
      assert.equal(previewScripts.length, 3);
      assert.ok(previewScripts.every((s) => s.exists && /^[0-9a-f]{64}$/.test(s.sha256)));

      // 4. Simulate external installer updating config.json on disk (`enabled: true`) -> performBind calls reloadFromDisk()
      //    and auto-closes the bootstrap channel when sandboxReady === true!
      const diskCfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8')) as Record<string, unknown>;
      diskCfg.enabled = true;
      diskCfg.username = 'alice';
      fs.writeFileSync(cfgPath, JSON.stringify(diskCfg, null, 2), 'utf8');

      const bound = await mgr.ensureBound();
      assert.equal(reloadedSeen, true);
      assert.equal(bound.sandboxReady, true);
      assert.equal(store.get().enabled, true);
      assert.equal(mgr.getBootstrapChannelState().active, false);

      await mgr.dispose();
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('includes NixOS & user-local Go paths in Node discovery/sandbox PATH and parses legacy / < 2.4 WSL version output', () => {
    assert.ok(WSL_SYSTEM_NODE_DIRS.includes('/run/current-system/sw/bin'));
    assert.match(WSL_SHARED_NODE_EXEC_SH, /\/run\/current-system\/sw\/bin/);
    assert.match(WSL_SHARED_NODE_EXEC_SH, /cd "\$HOME" 2>\/dev\/null \|\| true/);

    const sandboxPath = buildDefaultSandboxPath('/home/alice');
    assert.match(sandboxPath, /\/home\/alice\/\.nix-profile\/bin/);
    assert.match(sandboxPath, /\/home\/alice\/\.local\/share\/dsh-wsl-sandbox\/toolchains\/go\/bin/);
    assert.match(sandboxPath, /\/run\/current-system\/sw\/bin/);
    assert.doesNotMatch(sandboxPath, /\/mnt\//);

    const v23 = parseWslVersionOutput('WSL version: 2.3.26.0\nKernel version: 5.15.167.4-1\n', 0);
    assert.equal(v23.wslVersion, '2.3.26.0');
    assert.equal(v23.isBelow24, true);
    assert.equal(v23.isBelow244, true);
    assert.equal(v23.isLegacyInboxWsl, false);
    assert.match(v23.warnings[0] ?? '', /NAT/);

    const v24 = parseWslVersionOutput('WSL 版本： 2.4.11.0\n内核版本： 5.15.167.4-1\n', 0);
    assert.equal(v24.wslVersion, '2.4.11.0');
    assert.equal(v24.isBelow24, false);
    assert.equal(v24.isBelow244, false);

    const legacy = parseWslVersionOutput('Invalid command line option: --version', 1);
    assert.equal(legacy.isLegacyInboxWsl, true);
    assert.equal(legacy.isBelow24, true);
  });

  it('keeps blank Windows first-run install uninitialized (enabled=false, oobeNeeded=true) until install-manifest or explicit setup', () => {
    const tmpBlank = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-oobe-blank-'));
    try {
      const cfgPath = path.join(tmpBlank, 'config.json');
      const store = new ConfigStore({
        filePath: cfgPath,
        persistToDisk: true,
        initial: {},
      });

      if (process.platform === 'win32') {
        assert.equal(store.get().enabled, false);
        assert.equal(store.get().initialized, false);
        assert.equal(store.isInitialized(), false);
        assert.equal(store.isOobeNeeded(), true);

        // 稍后配置 -> 仅关闭弹窗提醒，仍保持未初始化状态
        store.updateBasic({ oobeDismissed: true });
        assert.equal(store.isInitialized(), false);
        assert.equal(store.isOobeNeeded(), false);

        // 写入 install-manifest.json + reload -> 自动识别已初始化
        fs.writeFileSync(
          path.join(tmpBlank, 'install-manifest.json'),
          JSON.stringify({ version: '0.3.0', distro: 'Ubuntu-24.04' }),
          'utf8',
        );
        const reloaded = store.reloadFromDisk();
        assert.equal(reloaded.initialized, true);
        assert.equal(store.isInitialized(), true);
        assert.equal(store.isOobeNeeded(), false);
      } else {
        assert.equal(store.isInitialized(), true);
        assert.equal(store.isOobeNeeded(), false);
      }
    } finally {
      fs.rmSync(tmpBlank, { recursive: true, force: true });
    }
  });
});
