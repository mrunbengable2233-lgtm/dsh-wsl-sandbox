import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import vm from 'node:vm';
import {
  apply as applyWslSandbox,
  classifyHostShellTool,
  type DshCordisContext,
  type DshPreToolDecision,
  type DshRealPromptSection,
  type DshRealToolExecution,
  type DshToolDefinition,
  type DshToolGuard,
  type DshWaterfallListener,
  type DshWebServerRoute,
  type WslSandboxPluginHandle,
} from '../../packages/dsh-plugin/src/index.ts';
import { BUILT_CLIENT_PATH, BUILT_RUNNER_PATH, BWRAP_SKIP_REASON } from '../test-env.ts';

/**
 * Faithful emulation of the REAL `@deepseek-ai/dsh@0.2.2-rc.5` Cordis Host + WebServer + ClientModuleLoader,
 * testing coexistence alongside the Top 27 DSH Marketplace plugins:
 *  - `billion-context` (preset overrides)
 *  - `dshmarket` (`/dsh-market/api/*`, `settings.section` slot)
 *  - `dsh-purge-community` (`system-prompt` override, `hooksDenyBypass: true`, `/redteam/api`, `order: 5100`)
 *  - `dsh-ops` (`ops_bash`, `tools.restrict` on official `pwsh`/`read`/`glob`/`grep`)
 *  - `@linxin666/dsh-win-bash` (`win_bash` POSIX MinGit shell on Windows)
 *  - `dsh-windows-mcp` (`mcp__windows__Click` vs `mcp__windows__PowerShell`)
 *  - `cc-safety-net` (monotonic `tools.guard` + `tools/post-execute` `--no-cwd-arg` check)
 */
describe('Real @deepseek-ai/dsh@0.2.2-rc.5 & Top-27 Marketplace Plugins Coexistence (GUI + CLI)', () => {
  let workspaceRoot = '';
  let configPath = '';
  let handle: WslSandboxPluginHandle;
  let httpServer: http.Server;
  let serverOrigin = '';

  const registeredTools = new Map<string, DshToolDefinition>();
  const registeredGuards: DshToolGuard[] = [];
  const registeredPromptSections = new Map<string, DshRealPromptSection>();
  const preExecuteListeners: Array<DshWaterfallListener<DshRealToolExecution, DshPreToolDecision>> = [];
  const webRoutes: DshWebServerRoute[] = [];
  const cordisCleanups: Array<() => void> = [];

  before(async () => {
    workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-real-top20-ws-'));
    configPath = path.join(workspaceRoot, '.dsh-cfg', 'config.json');

    // Start real HTTP listener backing `ctx.webServer`
    httpServer = http.createServer(async (req, res) => {
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

    await new Promise<void>((resolve) => httpServer.listen(0, '127.0.0.1', resolve));
    const addr = httpServer.address() as { port: number };
    serverOrigin = `http://127.0.0.1:${addr.port}`;

    // Pre-mount simulated Top-20 peer routes & tools (`dshmarket`, `dsh-purge-community`, `dsh-ops`, `win_bash`, `dsh-windows-mcp`, `cc-safety-net`)
    webRoutes.push(
      { kind: 'prefix', path: '/dsh-market/api', handler: (_req, res) => res.writeHead(200).end('{"schema":"dsh-market/update-api/v1"}') },
      { kind: 'exact', path: '/redteam/api', handler: (_req, res) => res.writeHead(200).end('{"ok":true}') },
    );

    // Peer plugin `cc-safety-net` monotonic guard + downstream waterfall listener
    let downstreamWaterfallReached = 0;
    preExecuteListeners.push(async (_exec, next) => {
      downstreamWaterfallReached += 1;
      return typeof next === 'function' ? next() : { kind: 'allow' };
    });
    void downstreamWaterfallReached;

    registeredGuards.push((exec) => {
      if (exec.name === 'pwsh' && String((exec.arguments as { command?: string })?.command ?? '').includes('cc-safety-block')) {
        return { reason: 'Blocked by cc-safety-net' };
      }
      return undefined;
    });

    const realLikeCtx: DshCordisContext = {
      tools: {
        register(tool) {
          assert.ok(tool.output && typeof tool.output.render === 'function', `Tool ${tool.name} must define output.render for DSH 0.2.2`);
          assert.ok(!registeredTools.has(tool.name), `Duplicate tool name: ${tool.name}`);
          registeredTools.set(tool.name, tool);
          return () => registeredTools.delete(tool.name);
        },
        guard(fn) {
          registeredGuards.push(fn);
          return () => {
            const i = registeredGuards.indexOf(fn);
            if (i >= 0) registeredGuards.splice(i, 1);
          };
        },
      },
      systemPrompt: {
        section(sec) {
          assert.equal(sec.interpolate, false, 'Prompt section must set interpolate: false');
          assert.ok(!registeredPromptSections.has(sec.name), `Duplicate prompt section: ${sec.name}`);
          registeredPromptSections.set(sec.name, sec);
          return () => registeredPromptSections.delete(sec.name);
        },
      },
      approval: {
        // Real `@deepseek-ai/dsh-user-approval` returns string 'unavailable' when outside an interactive turn
        request: async () => 'unavailable',
      },
      webServer: {
        register(route) {
          const dup = webRoutes.find((r) => r.kind === route.kind && r.path === route.path);
          assert.equal(dup, undefined, `Duplicate webServer route: ${route.kind} ${route.path}`);
          webRoutes.push(route);
          return () => {
            const idx = webRoutes.indexOf(route);
            if (idx >= 0) webRoutes.splice(idx, 1);
          };
        },
      },
      inject(_deps, cb) {
        cb(realLikeCtx);
      },
      // 真实 Cordis 4：`on()` 注册监听并返回 disposer；若误调 `waterfall()` 注册则模拟真实派发报错！
      on(event, listener) {
        if (event === 'tools/pre-execute') {
          const typed = listener as unknown as DshWaterfallListener<DshRealToolExecution, DshPreToolDecision>;
          preExecuteListeners.push(typed);
          return () => {
            const idx = preExecuteListeners.indexOf(typed);
            if (idx >= 0) preExecuteListeners.splice(idx, 1);
          };
        }
        return () => {};
      },
      waterfall(event) {
        if (event === 'tools/pre-execute') {
          throw new TypeError('next is not a function');
        }
        return Promise.resolve({ kind: 'allow' }) as never;
      },
      // Real Cordis `ctx.effect(setup)` invokes `setup()` immediately on mount and stores the returned disposer!
      effect(setupFn) {
        const ret = (setupFn as () => (() => void) | void)();
        if (typeof ret === 'function') {
          cordisCleanups.push(ret);
        }
      },
    };

    handle = applyWslSandbox(realLikeCtx, {
      configPath,
      persistConfig: true,
      allowLinuxDevMode: true,
      initialConfig: {
        transportMode: 'local-linux',
        distro: 'MyMovedUbuntu26',
        environmentProfile: 'core',
        workspaceRoot: process.platform === 'win32' ? '/home/dev/workspace' : workspaceRoot,
        runnerPath: BUILT_RUNNER_PATH,
      },
    });
  });

  after(async () => {
    for (const fn of cordisCleanups.splice(0)) {
      fn();
    }
    await handle?.dispose();
    await new Promise<void>((resolve) => httpServer?.close(() => resolve()));
    if (workspaceRoot && fs.existsSync(workspaceRoot)) {
      fs.rmSync(workspaceRoot, { recursive: true, force: true });
    }
  });

  async function runRealPreExecuteAndGuards(name: string, args: Record<string, unknown>): Promise<{ allowed: boolean; reason?: string }> {
    const exec: DshRealToolExecution = {
      name,
      arguments: args,
      callId: 'call-1',
      signal: new AbortController().signal,
    };

    const runWf = async (idx: number): Promise<DshPreToolDecision> => {
      if (idx >= preExecuteListeners.length) return { kind: 'allow' };
      return preExecuteListeners[idx]!(exec, () => runWf(idx + 1));
    };

    const pre = await runWf(0);
    if (pre.kind === 'deny') {
      return { allowed: false, reason: pre.reason };
    }

    // Monotonic guards run AFTER every `tools/pre-execute` listener (cannot be overridden by hooksDenyBypass!)
    for (const g of registeredGuards) {
      const denial = g(exec);
      if (denial) {
        return {
          allowed: false,
          reason: typeof denial === 'string' ? denial : denial.reason,
        };
      }
    }
    return { allowed: true };
  }

  it('mounts cleanly with real Cordis ctx.effect(() => () => ...) without prematurely disposing tools or routes', () => {
    assert.equal(registeredTools.size, 7);
    assert.ok(registeredPromptSections.has('dsh-wsl-sandbox-routing'));
    const sec = registeredPromptSections.get('dsh-wsl-sandbox-routing')!;
    const rendered = typeof sec.text === 'function' ? sec.text() : sec.text;
    assert.match(rendered, /NEVER wrap or transpile `cmd`/);
    // Verify cc-safety-net `--no-cwd-arg` compatibility note is present
    assert.match(registeredTools.get('wsl_bash')!.description, /--no-cwd-arg/);
    assert.match(registeredTools.get('wsl_terminal')!.description, /--no-cwd-arg/);
    // Read-only tools opt into DSH parallel group execution
    assert.equal(registeredTools.get('wsl_read')!.isConcurrencySafe?.({}), true);
    assert.equal(registeredTools.get('wsl_bash')!.isConcurrencySafe, undefined);
  });

  it('coexists cleanly with win_bash, ops_bash, dsh-windows-mcp, dsh-remote, and cc-safety-net', async () => {
    assert.equal(classifyHostShellTool('win_bash'), 'host-posix-bash');
    assert.equal(classifyHostShellTool('ops_bash'), 'host-posix-bash');
    assert.equal(classifyHostShellTool('mcp__windows__PowerShell'), 'pwsh-dialect');
    assert.equal(classifyHostShellTool('mcp__windows__Click'), 'none');
    assert.equal(classifyHostShellTool('rw_exec'), 'none');
    assert.equal(classifyHostShellTool('ssh_exec'), 'none');
    assert.equal(classifyHostShellTool('redteam_webshell_add'), 'none');

    // 1. POSIX Bash syntax on `win_bash` / `ops_bash` MUST NOT be falsely flagged as PowerShell dialect!
    const posixOk = await runRealPreExecuteAndGuards('win_bash', {
      command: 'mkdir -p ./dist && cp -r ./src ./dist 2>/dev/null',
    });
    assert.equal(posixOk.allowed, true, `win_bash POSIX syntax must be allowed, got: ${posixOk.reason}`);

    // 2. Host escape (`\\wsl.localhost\` or `.wslconfig`) on `win_bash` / `ops_bash` MUST be blocked!
    const winBashEscape = await runRealPreExecuteAndGuards('ops_bash', {
      command: 'cp evil //wsl.localhost/MyMovedUbuntu26/home/dev/workspace/.git/hooks/pre-commit',
    });
    assert.equal(winBashEscape.allowed, false);

    // 3. `dsh-windows-mcp` GUI tool (`mcp__windows__Click`) passes untouched, while `mcp__windows__PowerShell` nested CMD is blocked!
    const guiClick = await runRealPreExecuteAndGuards('mcp__windows__Click', { x: 100, y: 200 });
    assert.equal(guiClick.allowed, true);

    const mcpPwshNestedCmd = await runRealPreExecuteAndGuards('mcp__windows__PowerShell', {
      command: 'Move-Item a b; cmd /c "rd /s /q c"',
    });
    assert.equal(mcpPwshNestedCmd.allowed, false);
    assert.match(mcpPwshNestedCmd.reason ?? '', /Single-shell purity violation/);

    // 4. Both our monotonic guard AND cc-safety-net's monotonic guard compose without order conflict!
    const ccBlock = await runRealPreExecuteAndGuards('pwsh', { command: 'Get-Date # cc-safety-block' });
    assert.equal(ccBlock.allowed, false);
    assert.match(ccBlock.reason ?? '', /cc-safety-net/);
  });

  it('serves live /wsl-sandbox/ui, /api/distros, /api/logs, /api/doctor (profile-aware), and blocks CSRF', async () => {
    const uiRes = await fetch(`${serverOrigin}/wsl-sandbox/ui`);
    assert.equal(uiRes.status, 200);
    const html = await uiRes.text();
    assert.match(html, /WSL 2 沙箱/);
    assert.doesNotMatch(html, /\brev-\d+\s*·\s*gen\s*#\d+/i);
    assert.match(html, /in-profile/);
    assert.match(html, /in-distro-select/);
    assert.match(html, /pane-logs/);

    const stRes = await fetch(`${serverOrigin}/wsl-sandbox/api/status`);
    assert.equal(stRes.status, 200);
    const stJson = (await stRes.json()) as {
      ok: boolean;
      config: { distro: string; environmentProfile: string };
      nodeRuntime: { hostNodeVersion: string; hostSharedWithDsh: boolean };
    };
    assert.equal(stJson.ok, true);
    assert.equal(stJson.config.distro, 'MyMovedUbuntu26');
    assert.equal(stJson.config.environmentProfile, 'core');
    assert.equal(stJson.nodeRuntime.hostSharedWithDsh, true);
    assert.equal(stJson.nodeRuntime.hostNodeVersion, process.version);

    const distrosRes = await fetch(`${serverOrigin}/wsl-sandbox/api/distros`);
    assert.equal(distrosRes.status, 200);
    const distrosJson = (await distrosRes.json()) as { ok: boolean; distros: unknown[] };
    assert.equal(distrosJson.ok, true);
    assert.ok(Array.isArray(distrosJson.distros));

    // Switch environmentProfile via API -> verify doctor immediately respects 'universal'!
    const putProf = await fetch(`${serverOrigin}/wsl-sandbox/api/config`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'X-DSH-WSL-Client': '1',
      },
      body: JSON.stringify({ environmentProfile: 'universal' }),
    });
    assert.equal(putProf.status, 200);

    // 验证 OOBE 状态流转（dismiss / reopen / complete）
    const oobeDismiss = await fetch(`${serverOrigin}/wsl-sandbox/api/oobe`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-DSH-WSL-Client': '1',
      },
      body: JSON.stringify({ action: 'dismiss' }),
    });
    assert.equal(oobeDismiss.status, 200);
    const oobeDismissJson = (await oobeDismiss.json()) as { ok: boolean; config: { oobeDismissed?: boolean } };
    assert.equal(oobeDismissJson.ok, true);
    assert.equal(oobeDismissJson.config.oobeDismissed, true);

    const oobeReopen = await fetch(`${serverOrigin}/wsl-sandbox/api/oobe`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-DSH-WSL-Client': '1',
      },
      body: JSON.stringify({ action: 'reopen' }),
    });
    assert.equal(oobeReopen.status, 200);
    const oobeReopenJson = (await oobeReopen.json()) as { ok: boolean; config: { oobeDismissed?: boolean } };
    assert.equal(oobeReopenJson.config.oobeDismissed, false);

    // Cross-origin CSRF attack from https://evil.example MUST be rejected with 403!
    const csrfRes = await fetch(`${serverOrigin}/wsl-sandbox/api/config`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Origin: 'https://evil.example',
      },
      body: JSON.stringify({ enabled: false }),
    });
    assert.equal(csrfRes.status, 403);
  });

  it('enforces DSH ctx.connection.admit authentication and supports clean disable/re-enable cycle', async () => {
    const tmpAuthDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-real-auth-'));
    try {
      const authRoutes: DshWebServerRoute[] = [];
      const authTools = new Map<string, DshToolDefinition>();
      const authPrompts = new Map<string, DshRealPromptSection>();
      const authCleanups: Array<() => void | Promise<void>> = [];

      const createAuthHostCtx = (authorizedRef: { ok: boolean; hostRejection?: number }): DshCordisContext => {
        const hostCtx: DshCordisContext = {
          tools: {
            register(tool) {
              assert.ok(!authTools.has(tool.name), `Duplicate tool on reload: ${tool.name}`);
              authTools.set(tool.name, tool);
              return () => authTools.delete(tool.name);
            },
            guard() {
              return () => {};
            },
          },
          systemPrompt: {
            section(sec) {
              assert.ok(!authPrompts.has(sec.name), `Duplicate prompt on reload: ${sec.name}`);
              authPrompts.set(sec.name, sec);
              return () => authPrompts.delete(sec.name);
            },
          },
          webServer: {
            host: '127.0.0.1',
            register(route) {
              const dup = authRoutes.find((r) => r.kind === route.kind && r.path === route.path);
              assert.equal(dup, undefined, `Duplicate webServer route on reload: ${route.kind} ${route.path}`);
              authRoutes.push(route);
              return () => {
                const idx = authRoutes.indexOf(route);
                if (idx >= 0) authRoutes.splice(idx, 1);
              };
            },
          },
          connection: {
            admit() {
              if (authorizedRef.hostRejection) {
                return { rejection: authorizedRef.hostRejection };
              }
              return authorizedRef.ok ? { peer: { id: 'owner-peer' } } : { rejection: 401 };
            },
          },
          inject(_deps, cb) {
            cb(hostCtx);
          },
          on() {
            return () => {};
          },
          waterfall(event) {
            if (event === 'tools/pre-execute') {
              throw new TypeError('next is not a function');
            }
            return Promise.resolve({ kind: 'allow' }) as never;
          },
          effect(setupFn) {
            const ret = (setupFn as () => (() => void | Promise<void>) | void)();
            if (typeof ret === 'function') authCleanups.push(ret);
          },
        };
        return hostCtx;
      };

      const authFlag = { ok: false, hostRejection: undefined as number | undefined };
      const authCtx = createAuthHostCtx(authFlag);
      const h1 = applyWslSandbox(authCtx, {
        configPath: path.join(tmpAuthDir, 'cfg.json'),
        persistConfig: true,
        persistLogs: false,
        initialConfig: { enabled: true, distro: 'Ubuntu-24.04', workspaceRoot: '/home/dev/workspace' },
      });

      const srv = http.createServer(async (req, res) => {
        const pathname = new URL(req.url ?? '/', 'http://127.0.0.1').pathname.replace(/\/+$/, '') || '/';
        const matched =
          authRoutes.find((r) => r.kind === 'exact' && r.path === pathname) ??
          authRoutes.find((r) => r.kind === 'prefix' && (pathname === r.path || pathname.startsWith(r.path + '/')));
        if (!matched) {
          res.writeHead(404).end();
          return;
        }
        await matched.handler(req, res);
      });
      await new Promise<void>((resolve) => srv.listen(0, '127.0.0.1', resolve));
      const p = (srv.address() as { port: number }).port;

      try {
        // 1. Missing DSH auth cookie -> 401 on API, 200 on UI HTML
        const apiUnauth = await fetch(`http://127.0.0.1:${p}/wsl-sandbox/api/status`);
        assert.equal(apiUnauth.status, 401);
        const uiAllowed = await fetch(`http://127.0.0.1:${p}/wsl-sandbox/ui`);
        assert.equal(uiAllowed.status, 200);

        // 2. Host policy 403 rejection blocks even /wsl-sandbox/ui
        authFlag.hostRejection = 403;
        const uiForbidden = await fetch(`http://127.0.0.1:${p}/wsl-sandbox/ui`);
        assert.equal(uiForbidden.status, 403);

        // 3. Authenticated DSH peer -> 200 OK
        authFlag.hostRejection = undefined;
        authFlag.ok = true;
        const apiAuth = await fetch(`http://127.0.0.1:${p}/wsl-sandbox/api/status`);
        assert.equal(apiAuth.status, 200);

        // 4. Simulate clean Cordis disable (`setBundleEnabled(..., false)`) + re-enable (`setBundleEnabled(..., true)`)!
        await Promise.all(authCleanups.splice(0).map((fn) => fn()));
        assert.equal(authTools.size, 0, 'Tools must be removed on disable');
        assert.equal(authRoutes.length, 0, 'Web routes must be removed on disable');
        assert.equal(authPrompts.size, 0, 'Prompt section must be removed on disable');
        await h1.dispose();

        const h2 = applyWslSandbox(authCtx, {
          configPath: path.join(tmpAuthDir, 'cfg.json'),
          persistConfig: true,
          persistLogs: false,
          initialConfig: { enabled: true, distro: 'Ubuntu-24.04', workspaceRoot: '/home/dev/workspace' },
        });
        assert.equal(authTools.size, 7);
        assert.equal(authRoutes.length, 2);
        assert.equal(authPrompts.size, 1);
        await Promise.all(authCleanups.splice(0).map((fn) => fn()));
        await h2.dispose();
      } finally {
        await new Promise<void>((resolve) => srv.close(() => resolve()));
      }
    } finally {
      fs.rmSync(tmpAuthDir, { recursive: true, force: true });
    }
  });

  it('runs real local-linux doctor & aborts in-flight wsl_bash cleanly with zero leaked processes', { skip: BWRAP_SKIP_REASON }, async () => {
    const docRes = await fetch(`${serverOrigin}/wsl-sandbox/api/doctor`);
    assert.equal(docRes.status, 200);
    const docJson = (await docRes.json()) as { ok: boolean; report: { verdict: string; selectedProfile: string } };
    assert.equal(docJson.ok, true);
    assert.equal(docJson.report.selectedProfile, 'universal');
    assert.ok(['ready', 'degraded'].includes(docJson.report.verdict));

    // Abort an in-flight wsl_bash (`sleep 30`) via AbortController -> zero leaked active processes!
    const wslBash = registeredTools.get('wsl_bash')!;
    const ac = new AbortController();
    const runPromise = wslBash.execute({ command: 'sleep 30', timeoutMs: 30_000 }, { signal: ac.signal }) as Promise<{
      aborted?: boolean;
    }>;
    await new Promise((r) => setTimeout(r, 250));
    ac.abort();
    const abortedOut = await runPromise;
    assert.equal(abortedOut.aborted, true, 'Aborting tool signal must immediately terminate in-flight sandbox process');

    const procsRes = await fetch(`${serverOrigin}/wsl-sandbox/api/processes`);
    const procsJson = (await procsRes.json()) as { ok: boolean; active: unknown[] };
    assert.equal(procsJson.ok, true);
    assert.equal(procsJson.active.length, 0, 'Zero active processes may remain after AbortController cancel');
  });

  it('loads and mounts built client.js inside window.__ModuleLoader__ registering sidebar, OOBE overlay, plugin detail & settings cleanly', () => {
    const pkgJson = JSON.parse(
      fs.readFileSync(path.resolve(path.dirname(BUILT_CLIENT_PATH), 'package.json'), 'utf8'),
    ) as {
      dsh?: {
        bundle?: { platforms?: string[] };
        client?: { inject?: string[] };
      };
    };
    assert.deepEqual(pkgJson.dsh?.bundle?.platforms, ['win32', 'linux']);
    assert.ok(pkgJson.dsh?.client?.inject?.includes('@deepseek-ai/dsh-client-ui-renderer'));
    assert.ok(pkgJson.dsh?.client?.inject?.includes('@deepseek-ai/dsh-client-ui-layout'));
    assert.ok(pkgJson.dsh?.client?.inject?.includes('@deepseek-ai/dsh-client-ui-sidebar'));
    assert.ok(pkgJson.dsh?.client?.inject?.includes('@deepseek-ai/dsh-client-ui-sidebar-right'));
    assert.ok(pkgJson.dsh?.client?.inject?.includes('@deepseek-ai/dsh-client-ui-plugin-manager'));
    assert.equal(pkgJson.dsh?.client?.inject?.includes('@deepseek-ai/dsh-client-ui-slots'), false);

    assert.equal(fs.existsSync(BUILT_CLIENT_PATH), true, 'client.js must be generated by build.mjs');
    const code = fs.readFileSync(BUILT_CLIENT_PATH, 'utf8');
    assert.ok(code.startsWith('window.__ModuleLoader__.load('), 'client.js must start with single-line ModuleLoader header');

    let loadedEntry: { id: string; factory: (req: (id: string) => unknown) => Record<string, unknown> } | undefined;
    const sandboxWindow = {
      __ModuleLoader__: {
        load(entry: { id: string; factory: (req: (id: string) => unknown) => Record<string, unknown> }) {
          loadedEntry = entry;
        },
      },
    };

    vm.runInNewContext(code, { window: sandboxWindow });
    assert.ok(loadedEntry);
    assert.equal(loadedEntry.id, 'dsh-wsl-sandbox');

    const mockReact = {
      Fragment: Symbol.for('react.fragment'),
      createElement: (tag: unknown, props: unknown, ...children: unknown[]) => ({ tag, props, children }),
      useState: <T>(init: T) => [init, () => {}] as const,
      useEffect: () => {},
      useCallback: <T>(fn: T) => fn,
    };

    const mod = loadedEntry.factory((spec) => {
      if (spec === 'react') return mockReact;
      if (spec === 'react-dom') return { createPortal: (n: unknown) => n };
      throw new Error(`Unexpected client require: ${spec}`);
    }) as {
      inject: string[];
      apply: (ctx: unknown) => void;
    };

    assert.deepEqual(Array.from(mod.inject), ['slots', 'locale']);

    const registeredSlots: Array<{ name: string; id?: string; key?: string; order?: number }> = [];
    const registeredRightTabs: Array<{ id: string; kind: string }> = [];
    const disposers: Array<() => void> = [];

    const mockClientCtx = {
      locale: {
        bind: () => (k: string) => k,
        register: () => () => {},
        getLocale: () => ({ active: 'zh' }),
      },
      layout: {
        selectPanel: () => {},
      },
      sidebarRightTabs: {
        register: (def: { id: string; kind: string }) => {
          registeredRightTabs.push(def);
          return () => {
            const idx = registeredRightTabs.indexOf(def);
            if (idx >= 0) registeredRightTabs.splice(idx, 1);
          };
        },
      },
      slots: {
        inject: (_slot: string, fn: () => () => void) => fn(),
        register: (opts: { name: string; id?: string; key?: string; order?: number }) => {
          registeredSlots.push(opts);
          return () => {
            const idx = registeredSlots.indexOf(opts);
            if (idx >= 0) registeredSlots.splice(idx, 1);
          };
        },
      },
      inject: (_deps: string[], cb: (c: unknown) => void) => {
        cb(mockClientCtx);
      },
      effect: (setup: () => (() => void) | void) => {
        const d = setup();
        if (typeof d === 'function') disposers.push(d);
      },
    };

    mod.apply(mockClientCtx);

    assert.deepEqual(
      registeredSlots.map((s) => `${s.name}:${s.id ?? s.key}`),
      [
        'main:wsl-sandbox',
        'sidebar.panellist:wsl-sandbox',
        'shell.overlay:dsh-wsl-sandbox.overlay',
        'plugins.bundle.activation:dsh-wsl-sandbox',
        'plugins.bundle.config:dsh-wsl-sandbox',
        'plugins.row.config:dsh-wsl-sandbox#dsh-wsl-sandbox',
        'plugins.detail.section:dsh-wsl-sandbox.detail',
        'settings.section:dsh-wsl-sandbox',
        'settings.section.icon:dsh-wsl-sandbox',
        'sidebar.right.pane.tab:dsh-wsl-sandbox',
      ],
    );
    assert.deepEqual(
      registeredRightTabs.map((t) => `${t.id}:${t.kind}`),
      ['dsh-wsl-sandbox:wsl-sandbox'],
    );

    // Clean unmount removes all slots & right-sidebar tabs
    for (const d of disposers) d();
    assert.equal(registeredSlots.length, 0);
    assert.equal(registeredRightTabs.length, 0);
  });
});
