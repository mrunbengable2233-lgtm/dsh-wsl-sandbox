import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { SandboxError } from '../../packages/core/src/index.ts';
import {
  apply as applyWslSandbox,
  apply as _unused,
  type DshApprovalService,
  type DshCordisContext,
  type DshHttpHandler,
  type DshHttpRequest,
  type DshHttpResponse,
  type DshSystemPromptSection,
  type DshToolDefinition,
  type DshWaterfallListener,
  type WslSandboxPluginHandle,
} from '../../packages/dsh-plugin/src/index.ts';
import { apply as applyWebUi } from '../../packages/dsh-plugin/src/web-ui-entry.ts';

void _unused;

/**
 * Simulated Cordis DSH Host running BOTH:
 *  - A faithful simulation of `dsh-purge` (`system-prompt` override, `postPrompt` at order 5100,
 *    `hooksDenyBypass: true` instant auto-approver, custom `dsh_purge_audit` tool, `/purge/api/status` route)
 *  - Our real `dsh-wsl-sandbox` plugin + `dsh-wsl-sandbox-web-ui`
 */
class MockCordisDshHost {
  readonly tools = new Map<string, DshToolDefinition>();
  readonly promptSections = new Map<string, DshSystemPromptSection>();
  readonly routes = new Map<string, DshHttpHandler>();
  readonly waterfalls = new Map<string, Array<DshWaterfallListener<unknown, unknown>>>();
  readonly disposers: Array<() => void | Promise<void>> = [];

  /** Simulates DSH's `system-prompt` row (modified by dsh-purge). */
  baseSystemPrompt = 'STOCK_DSH_SYSTEM_PROMPT';
  /** Simulates `dsh-purge` `hooksDenyBypass: true` behavior. */
  dshPurgeHooksDenyBypass = true;
  /** Counts how many times host `ctx.approval.request` was invoked. */
  hostApprovalCalls = 0;

  createContext(): DshCordisContext {
    const approval: DshApprovalService = {
      request: async (req) => {
        this.hostApprovalCalls++;
        if (this.dshPurgeHooksDenyBypass) {
          // Simulates dsh-purge bypassing host denial/prompt instantly!
          return {
            decision: 'allow-once',
            bypassed: true,
            hooksDenyBypass: true,
            source: 'dsh-purge',
          };
        }
        return {
          decision: 'allow-once',
          humanVerified: true,
          source: req.source,
        };
      },
    };

    return {
      tools: {
        register: (tool) => {
          if (this.tools.has(tool.name)) {
            throw new Error(`CORDIS_CONFLICT: Duplicate tool registration '${tool.name}'`);
          }
          this.tools.set(tool.name, tool);
          return () => this.tools.delete(tool.name);
        },
        has: (name) => this.tools.has(name),
      },
      systemPrompt: {
        register: (section) => {
          if (this.promptSections.has(section.id)) {
            throw new Error(`CORDIS_CONFLICT: Duplicate systemPrompt section '${section.id}'`);
          }
          this.promptSections.set(section.id, section);
          return () => this.promptSections.delete(section.id);
        },
      },
      approval,
      http: {
        route: (method, routePath, handler) => {
          const key = `${method} ${routePath}`;
          if (this.routes.has(key)) {
            throw new Error(`CORDIS_CONFLICT: Duplicate HTTP route '${key}'`);
          }
          this.routes.set(key, handler);
          return () => this.routes.delete(key);
        },
      },
      waterfall: (event, listener) => {
        const list = this.waterfalls.get(event) ?? [];
        list.push(listener as DshWaterfallListener<unknown, unknown>);
        this.waterfalls.set(event, list);
        return () => {
          const idx = list.indexOf(listener as DshWaterfallListener<unknown, unknown>);
          if (idx >= 0) list.splice(idx, 1);
        };
      },
      effect: (fn) => {
        this.disposers.push(fn);
      },
    };
  }

  async executeTool(toolName: string, input: Record<string, unknown>): Promise<unknown> {
    const tool = this.tools.get(toolName);
    if (!tool) throw new Error(`Tool not found: ${toolName}`);
    const listeners = this.waterfalls.get('tools/pre-execute') ?? [];

    const dispatch = async (idx: number): Promise<unknown> => {
      if (idx >= listeners.length) {
        return tool.execute(input);
      }
      return listeners[idx]!({ toolName, input }, () => dispatch(idx + 1));
    };
    return dispatch(0);
  }

  async composeSystemPrompt(): Promise<string> {
    const sections = Array.from(this.promptSections.values()).sort((a, b) => a.order - b.order);
    const parts = [this.baseSystemPrompt];
    for (const s of sections) {
      const content = typeof s.content === 'function' ? await s.content() : s.content;
      if (content) parts.push(content);
    }
    return parts.join('\n\n');
  }

  async callHttp(
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    routePattern: string,
    options?: { params?: Record<string, string>; body?: unknown },
  ): Promise<{ status: number; json?: unknown; html?: string; text?: string }> {
    const handler = this.routes.get(`${method} ${routePattern}`);
    if (!handler) throw new Error(`Route not found: ${method} ${routePattern}`);

    let statusCode = 200;
    let jsonPayload: unknown;
    let htmlPayload: string | undefined;
    let textPayload: string | undefined;

    const req: DshHttpRequest = {
      method,
      path: routePattern,
      params: options?.params ?? {},
      query: {},
      body: options?.body,
      headers: {},
    };
    const res: DshHttpResponse = {
      status(code) {
        statusCode = code;
        return this;
      },
      header() {
        return this;
      },
      json(payload) {
        jsonPayload = payload;
      },
      html(content) {
        htmlPayload = content;
      },
      text(content) {
        textPayload = content;
      },
    };
    await handler(req, res);
    return { status: statusCode, json: jsonPayload, html: htmlPayload, text: textPayload };
  }

  async disposeAll(): Promise<void> {
    for (const fn of this.disposers.splice(0)) {
      await fn();
    }
  }
}

const RUNNER_PATH = path.resolve('packages/wsl-runner/src/main.ts');

describe('plugin-coexistence — dsh-wsl-sandbox + dsh-purge full Cordis coexistence', () => {
  let host: MockCordisDshHost;
  let workspaceRoot = '';
  let configPath = '';
  let handle: WslSandboxPluginHandle;
  const pwshExecutedCommands: string[] = [];

  before(() => {
    workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-coexist-ws-'));
    configPath = path.join(workspaceRoot, '.dsh-test-config.json');
    fs.writeFileSync(path.join(workspaceRoot, 'AGENTS.md'), '# User Custom Rules\nKeep my tests green.\n', 'utf8');

    host = new MockCordisDshHost();
    const ctx = host.createContext();

    // 1. Load stock Windows host `pwsh` tool (MUST stay alive under Q12=B!)
    ctx.tools!.register({
      name: 'pwsh',
      description: 'Windows host PowerShell',
      parameters: {},
      execute: async (input) => {
        pwshExecutedCommands.push(String(input.command ?? ''));
        return { ok: true, hostPwsh: true, command: input.command };
      },
    });

    // 2. Load simulated `dsh-purge` plugin (system-prompt override + postPrompt 5100 + custom tool + custom route)
    host.baseSystemPrompt = 'DSH_PURGE_CUSTOMIZED_SYSTEM_PROMPT';
    ctx.systemPrompt!.register({
      id: 'dsh-purge-post-prompt',
      order: 5100,
      content: 'DSH_PURGE_POST_PROMPT_ACTIVE',
    });
    ctx.tools!.register({
      name: 'dsh_purge_audit',
      description: 'dsh-purge custom tool',
      parameters: {},
      execute: async () => ({ purgeToolAlive: true }),
    });
    ctx.http!.route('GET', '/purge/api/status', (_req, res) => {
      res.status(200).json({ purgeRouteAlive: true });
    });

    // 3. Load our real `dsh-wsl-sandbox` plugin (WITHOUT touching dsh-purge!)
    handle = applyWslSandbox(ctx, {
      configPath,
      persistConfig: true,
      allowLinuxDevMode: true,
      initialConfig: {
        transportMode: 'local-linux',
        distro: 'linux-devbox',
        workspaceRoot,
        runnerPath: RUNNER_PATH,
        approvalPolicyMode: 'balanced',
        networkMode: 'offline',
      },
    });

    // 4. Also verify `dsh-wsl-sandbox-web-ui` loads cleanly on a separate UI mount path
    applyWebUi(ctx, { routePrefix: '/wsl-sandbox/web-ui-alt/api', zIndexCap: 850 });
  });

  after(async () => {
    await host.disposeAll();
    fs.rmSync(workspaceRoot, { recursive: true, force: true });
  });

  it('preserves 100% of dsh-purge prompts, tools, and routes while adding 7 wsl_* tools and incremental routing prompt', async () => {
    // All 7 additive WSL tools + stock pwsh + dsh-purge tool coexist!
    for (const name of [
      'pwsh',
      'dsh_purge_audit',
      'wsl_bash',
      'wsl_read',
      'wsl_write',
      'wsl_edit',
      'wsl_glob',
      'wsl_grep',
      'wsl_terminal',
    ]) {
      assert.ok(host.tools.has(name), `Expected tool '${name}' to be registered`);
    }

    // dsh-purge tool & HTTP route work untouched
    assert.deepEqual(await host.executeTool('dsh_purge_audit', {}), { purgeToolAlive: true });
    const purgeHttp = await host.callHttp('GET', '/purge/api/status');
    assert.equal(purgeHttp.status, 200);
    assert.deepEqual(purgeHttp.json, { purgeRouteAlive: true });

    // System prompt keeps dsh-purge base + inserts wsl routing (order 4200) BEFORE dsh-purge postPrompt (order 5100)
    const composed = await host.composeSystemPrompt();
    const idxBase = composed.indexOf('DSH_PURGE_CUSTOMIZED_SYSTEM_PROMPT');
    const idxWsl = composed.indexOf('WSL 2 Sandbox Execution Policy (dsh-wsl-sandbox)');
    const idxPost = composed.indexOf('DSH_PURGE_POST_PROMPT_ACTIVE');
    assert.ok(idxBase >= 0 && idxWsl > idxBase && idxPost > idxWsl, 'Prompt section ordering must be base < wsl(4200) < dsh-purge(5100)');
  });

  it('guards host Windows pwsh: allows usbipd list, hard-blocks L0, and catches L3/physical-device even under dsh-purge hooksDenyBypass=true!', async () => {
    // 1. Safe host hardware read passes immediately
    const listRes = await host.executeTool('pwsh', { command: 'usbipd list' });
    assert.deepEqual(listRes, { ok: true, hostPwsh: true, command: 'usbipd list' });

    // 2. L0 destructive Windows command & Base64 encoded attack hard-blocked even with dsh-purge bypass ON!
    await assert.rejects(
      () => host.executeTool('pwsh', { command: 'Format-Volume -DriveLetter C' }),
      (err: unknown) => err instanceof SandboxError && err.code === 'POLICY_BLOCK',
    );

    const b64 = Buffer.from('wsl.exe --unregister Ubuntu-24.04', 'utf16le').toString('base64');
    await assert.rejects(
      () => host.executeTool('pwsh', { command: `powershell -EncodedCommand ${b64}` }),
      (err: unknown) => err instanceof SandboxError && err.code === 'POLICY_BLOCK',
    );

    // 3. Physical hardware mutating `usbipd attach --wsl --busid 1-2`:
    //    dsh-purge instantly returns { decision: 'allow-once', hooksDenyBypass: true },
    //    OUR ApprovalBridge MUST catch the bypass, route to our independent queue, and disable session caching!
    const waitForPending = async (expectedCount: number, timeoutMs = 5000): Promise<Array<Record<string, unknown>>> => {
      const deadline = Date.now() + timeoutMs;
      while (Date.now() < deadline) {
        const res = await host.callHttp('GET', '/wsl-sandbox/api/approvals');
        const list = (res.json as { pending: Array<Record<string, unknown>> }).pending;
        if (list.length >= expectedCount) return list;
        await new Promise((r) => setTimeout(r, 25));
      }
      return [];
    };

    const attachPromise = host.executeTool('pwsh', { command: 'usbipd attach --wsl --busid 1-2' });

    const pendingList = await waitForPending(1);
    assert.equal(pendingList.length, 1, 'Bypassed usbipd attach MUST land in independent approval queue');
    const item = pendingList[0]!;
    assert.equal(item.touchesPhysicalDevice, true);
    assert.equal(item.allowSessionRuleOption, false, 'Physical device must NOT offer session-rule caching');
    assert.equal(item.routedViaFallback, true);

    // Human approves via Web API
    const decideRes = await host.callHttp('POST', '/wsl-sandbox/api/approvals/:id/decide', {
      params: { id: String(item.requestId) },
      body: { decision: 'allow-once' },
    });
    assert.equal(decideRes.status, 200);

    const attachResult = await attachPromise;
    assert.deepEqual(attachResult, { ok: true, hostPwsh: true, command: 'usbipd attach --wsl --busid 1-2' });
  });

  it('executes real sandboxed wsl_* tools and catches bypassed wsl_bash L3 commands via independent queue', async () => {
    // Write + Read via wsl_* tools
    await host.executeTool('wsl_write', { path: 'demo.txt', content: 'coexistence works!\n' });
    const readRes = (await host.executeTool('wsl_read', { path: 'demo.txt' })) as { content: string };
    assert.match(readRes.content, /coexistence works!/);

    // Safe wsl_bash passes with zero prompts
    const echoRes = (await host.executeTool('wsl_bash', { command: 'cat demo.txt' })) as { exitCode: number; stdout: { text: string } };
    assert.equal(echoRes.exitCode, 0);
    assert.equal(echoRes.stdout.text.trim(), 'coexistence works!');

    // Destructive L3 `rm -rf ./demo.txt` under dsh-purge hooksDenyBypass=true -> caught by independent queue!
    const rmPromise = host.executeTool('wsl_bash', { command: 'rm -rf ./demo.txt' });
    const deadline = Date.now() + 5000;
    while (handle.approvalBridge.listPending().length < 1 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    const pending = handle.approvalBridge.listPending();
    assert.equal(pending.length, 1);
    assert.equal(pending[0]!.routedViaFallback, true);

    // Human denies with guidance!
    handle.approvalBridge.decidePending(pending[0]!.requestId, 'deny-with-guidance', {
      guidance: 'Keep demo.txt for QA',
    });

    await assert.rejects(
      () => rmPromise,
      (err: unknown) =>
        err instanceof SandboxError &&
        err.code === 'REVIEW_DENIED' &&
        err.message.includes('Keep demo.txt for QA'),
    );
    assert.equal(fs.existsSync(path.join(workspaceRoot, 'demo.txt')), true);
  });

  it('enforces Q8 UI & Web API invariants (blocks /mnt smuggling in basic config, supports Advanced share add/revoke, UI z-index<=850, idempotent AGENTS.md)', async () => {
    // 1. Basic PUT /config rejects smuggling full Windows drive mount
    const badBasic = await host.callHttp('PUT', '/wsl-sandbox/api/config', {
      body: { mountFullWindowsDrives: true },
    });
    assert.equal(badBasic.status, 403);

    // 2. Advanced single-dir share add & instant revoke bumps revision & generation
    const shareDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-adv-share-'));
    try {
      const addRes = await host.callHttp('POST', '/wsl-sandbox/api/advanced/shares', {
        body: { id: 'sh-docs', alias: 'docs', sourceLinuxPath: shareDir, mode: 'ro' },
      });
      assert.equal(addRes.status, 200);
      assert.equal(handle.configStore.get().advanced.shares.length, 1);

      const genBefore = handle.sessionManager.getGeneration();
      const delRes = await host.callHttp('DELETE', '/wsl-sandbox/api/advanced/shares/:id', {
        params: { id: 'sh-docs' },
      });
      assert.equal(delRes.status, 200);
      assert.equal(handle.configStore.get().advanced.shares.length, 0);
      assert.ok(handle.sessionManager.getGeneration() > genBefore);
    } finally {
      fs.rmSync(shareDir, { recursive: true, force: true });
    }

    // 3. UI HTML uses .dsh-wsl-sbx-* classes, z-index <= 850, and collapsed Advanced details
    const uiRes = await host.callHttp('GET', '/wsl-sandbox/ui');
    assert.equal(uiRes.status, 200);
    assert.ok(uiRes.html);
    assert.match(uiRes.html, /dsh-wsl-sbx-root/);
    assert.match(uiRes.html, /<details class="dsh-wsl-sbx-advanced">/);
    assert.doesNotMatch(uiRes.html, /z-index:\s*(?:9\d\d|1\d\d\d)/);

    // 4. AGENTS.md upsert preserves user rules and is idempotent
    const r1 = await host.callHttp('POST', '/wsl-sandbox/api/agents-md', { body: { projectRoot: workspaceRoot } });
    assert.equal(r1.status, 200);
    const r2 = await host.callHttp('POST', '/wsl-sandbox/api/agents-md', { body: { projectRoot: workspaceRoot } });
    assert.equal(r2.status, 200);
    const content = fs.readFileSync(path.join(workspaceRoot, 'AGENTS.md'), 'utf8');
    assert.match(content, /# User Custom Rules/);
    assert.match(content, /Keep my tests green\./);
    assert.equal(content.split('<!-- dsh-wsl-sandbox:start -->').length - 1, 1, 'Markers must not duplicate');
  });
});
