import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import {
  assertVerifiedProbe,
  type ProbeResponse,
  type ProcExecResult,
  type SessionBinding,
  type TerminalExecResult,
} from '../../packages/core/src/index.ts';
import { WslTransport } from '../../packages/dsh-plugin/src/wsl-transport.ts';
import { BUILT_RUNNER_PATH, BWRAP_SKIP_REASON } from '../test-env.ts';

/**
 * REAL Linux Kernel Sandbox Verification Suite (Q17=A).
 * Executes actual `wsl-runner` -> `bwrap` + `seccomp-bpf` + `prlimit` + `UdsAllowlistProxy`
 * on the real Linux kernel (no mocks for kernel isolation!).
 */

const RUNNER_PATH = BUILT_RUNNER_PATH;

describe('linux-sandbox — REAL bwrap + seccomp-bpf + prlimit + UdsAllowlistProxy kernel enforcement', { skip: BWRAP_SKIP_REASON }, () => {
  let workspaceRoot = '';
  let shareDir = '';
  let outsideFile = '';
  let transport: WslTransport;
  let binding: SessionBinding;

  before(async () => {
    workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-real-ws-'));
    shareDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-real-share-'));
    outsideFile = path.join(os.tmpdir(), `dsh-outside-${process.pid}.txt`);
    fs.writeFileSync(outsideFile, 'OUTSIDE_SECRET', 'utf8');

    // Seed workspace with git repo, .env secret, .env.example, and existing .git/hooks/pre-commit
    fs.writeFileSync(path.join(workspaceRoot, 'hello.txt'), 'hello sandbox\n', 'utf8');
    fs.writeFileSync(path.join(workspaceRoot, '.env'), 'SECRET_TOKEN=super-secret-value\n', 'utf8');
    fs.writeFileSync(path.join(workspaceRoot, '.env.example'), 'SECRET_TOKEN=changeme\n', 'utf8');
    fs.writeFileSync(path.join(shareDir, 'firmware.bin'), 'SHARE_PAYLOAD_OK', 'utf8');

    execFileSync('git', ['init', '-q'], { cwd: workspaceRoot });
    execFileSync('git', ['config', 'user.email', 'test@dsh.local'], { cwd: workspaceRoot });
    execFileSync('git', ['config', 'user.name', 'DSH Test'], { cwd: workspaceRoot });
    fs.mkdirSync(path.join(workspaceRoot, '.git', 'hooks'), { recursive: true });
    fs.writeFileSync(path.join(workspaceRoot, '.git', 'hooks', 'pre-commit'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });

    transport = new WslTransport({
      mode: 'local-linux',
      distro: 'linux-devbox',
      runnerPath: RUNNER_PATH,
    });

    const probe = await transport.call<ProbeResponse>('probe', {
      sessionId: 'sess-real-1',
      distribution: 'linux-devbox',
      workspaceRoot,
      cwd: workspaceRoot,
      profile: 'workspace-write',
      revision: 'rev-1',
      allowLinuxDevMode: true,
      authorizedShares: [
        { id: 'sh-1', alias: 'assets', sourceLinuxPath: shareDir, mode: 'ro' },
      ],
    });

    binding = assertVerifiedProbe(probe, {
      expectedSessionId: 'sess-real-1',
      expectedDistribution: 'linux-devbox',
      expectedWorkspaceRoot: workspaceRoot,
      expectedCwd: workspaceRoot,
      expectedProfile: 'workspace-write',
      expectedRevision: 'rev-1',
      generation: 1,
      authorizedShares: [
        { id: 'sh-1', alias: 'assets', sourceLinuxPath: shareDir, mode: 'ro' },
      ],
    });
  });

  after(async () => {
    await transport?.dispose();
    if (workspaceRoot && fs.existsSync(workspaceRoot)) fs.rmSync(workspaceRoot, { recursive: true, force: true });
    if (shareDir && fs.existsSync(shareDir)) fs.rmSync(shareDir, { recursive: true, force: true });
    if (outsideFile && fs.existsSync(outsideFile)) fs.rmSync(outsideFile, { force: true });
  });

  it('Positive: runs commands, private /tmp heredocs, git status/commit, and stateful wsl_terminal', async () => {
    const r1 = await transport.call<ProcExecResult>('proc.exec', {
      binding,
      cwd: workspaceRoot,
      mode: 'workspace-write',
      networkMode: 'offline',
      command: 'cat <<EOF\nHEREDOC_OK\nEOF\necho "written" > created.txt && git status --short',
    });
    assert.equal(r1.exitCode, 0, `stderr: ${r1.stderr.text}`);
    assert.match(r1.stdout.text, /HEREDOC_OK/);
    assert.match(r1.stdout.text, /\?\? created\.txt/);
    assert.equal(r1.sandbox.enforcement, 'full');

    // Stateful terminal preserves cwd across calls
    fs.mkdirSync(path.join(workspaceRoot, 'sub'), { recursive: true });
    const t1 = await transport.call<TerminalExecResult>('term.exec', {
      binding,
      terminalId: 'term-1',
      cwd: workspaceRoot,
      mode: 'workspace-write',
      networkMode: 'offline',
      command: 'cd sub && pwd',
    });
    assert.equal(t1.exitCode, 0);
    assert.equal(t1.cwd, path.join(workspaceRoot, 'sub'));

    const t2 = await transport.call<TerminalExecResult>('term.exec', {
      binding,
      terminalId: 'term-1',
      cwd: workspaceRoot,
      mode: 'workspace-write',
      networkMode: 'offline',
      command: 'pwd',
    });
    assert.equal(t2.exitCode, 0);
    assert.equal(t2.stdout.text.trim(), path.join(workspaceRoot, 'sub'));
  });

  it('Positive & Negative: mounts Advanced /shares/assets read-only and blocks writes', async () => {
    const r = await transport.call<ProcExecResult>('proc.exec', {
      binding,
      cwd: workspaceRoot,
      mode: 'workspace-write',
      networkMode: 'offline',
      command: 'cat /shares/assets/firmware.bin && echo "" && (echo hijack > /shares/assets/firmware.bin 2>&1 || echo WRITE_BLOCKED)',
    });
    assert.equal(r.exitCode, 0, `stderr: ${r.stderr.text}`);
    assert.match(r.stdout.text, /SHARE_PAYLOAD_OK/);
    assert.match(r.stdout.text, /WRITE_BLOCKED|Read-only file system/i);
    assert.equal(fs.readFileSync(path.join(shareDir, 'firmware.bin'), 'utf8'), 'SHARE_PAYLOAD_OK');
  });

  it('Negative (Kernel EROFS): blocks writes outside workspace & to Checklist B (.git/hooks, .git/config, nonexistent .bashrc) with zero leftover files', async () => {
    // 1. Write to `/` and `/etc` blocked
    const rSys = await transport.call<ProcExecResult>('proc.exec', {
      binding,
      cwd: workspaceRoot,
      mode: 'workspace-write',
      networkMode: 'offline',
      command: 'touch /pwned_root 2>&1',
    });
    assert.notEqual(rSys.exitCode, 0);
    assert.match(rSys.stdout.text + rSys.stderr.text, /Read-only file system/i);

    // 2. Write to existing .git/hooks/pre-commit & .git/config blocked
    const rGit = await transport.call<ProcExecResult>('proc.exec', {
      binding,
      cwd: workspaceRoot,
      mode: 'workspace-write',
      networkMode: 'offline',
      command: 'echo evil >> .git/hooks/pre-commit',
    });
    assert.notEqual(rGit.exitCode, 0);
    assert.equal(rGit.sandbox.denied, true);

    const rGitCfg = await transport.call<ProcExecResult>('proc.exec', {
      binding,
      cwd: workspaceRoot,
      mode: 'workspace-write',
      networkMode: 'offline',
      command: 'echo evil >> .git/config',
    });
    assert.notEqual(rGitCfg.exitCode, 0);
    assert.equal(rGitCfg.sandbox.denied, true);

    // 3. Create nonexistent .bashrc blocked AND host workspace remains clean (no 0-byte leftover!)
    assert.equal(fs.existsSync(path.join(workspaceRoot, '.bashrc')), false);
    const rBashrc = await transport.call<ProcExecResult>('proc.exec', {
      binding,
      cwd: workspaceRoot,
      mode: 'workspace-write',
      networkMode: 'offline',
      command: 'echo "export PWN=1" > .bashrc',
    });
    assert.notEqual(rBashrc.exitCode, 0);
    assert.equal(fs.existsSync(path.join(workspaceRoot, '.bashrc')), false, 'Zero leftover .bashrc placeholder on disk');
  });

  it('Negative (.env* Secret Masking): masks .env in both bwrap shell and ConfinedFsService while keeping .env.example readable', async () => {
    const rShell = await transport.call<ProcExecResult>('proc.exec', {
      binding,
      cwd: workspaceRoot,
      mode: 'workspace-write',
      networkMode: 'offline',
      maskEnvSecrets: true,
      command: 'echo "ENV=$(cat .env)" && echo "EXAMPLE=$(cat .env.example)"',
    });
    assert.equal(rShell.exitCode, 0);
    assert.match(rShell.stdout.text, /^ENV=\nEXAMPLE=SECRET_TOKEN=changeme/m);
    assert.doesNotMatch(rShell.stdout.text, /super-secret-value/);

    const fsReadEnv = await transport.call<{ content: string; maskedEnv: boolean }>('fs.read', {
      binding,
      path: '.env',
      maskEnvSecrets: true,
    });
    assert.equal(fsReadEnv.maskedEnv, true);
    assert.equal(fsReadEnv.content, '');

    const fsGrep = await transport.call<{ matches: Array<{ file: string; text: string }> }>('fs.grep', {
      binding,
      query: 'super-secret-value',
      maskEnvSecrets: true,
    });
    assert.equal(fsGrep.matches.length, 0);
  });

  it('Negative (Kernel Seccomp-BPF & Escape Surface): blocks io_uring_setup (EPERM), AF_VSOCK (EPERM), offline AF_INET (EACCES), and masks /mnt & /run', async () => {
    const pyCheck = [
      'import ctypes, json, os, socket',
      'libc = ctypes.CDLL(None, use_errno=True)',
      'buf = ctypes.create_string_buffer(120)',
      'ctypes.set_errno(0)',
      'r1 = libc.syscall(425, 1, buf)',
      'e1 = ctypes.get_errno()',
      'e_vsock = 0',
      'try:',
      '    socket.socket(40, socket.SOCK_STREAM).close()',
      'except OSError as ex:',
      '    e_vsock = ex.errno',
      'e_inet = 0',
      'try:',
      '    socket.socket(socket.AF_INET, socket.SOCK_STREAM).close()',
      'except OSError as ex:',
      '    e_inet = ex.errno',
      'print(json.dumps({',
      '  "io_uring_ret": r1, "io_uring_errno": e1,',
      '  "vsock_errno": e_vsock, "inet_errno": e_inet,',
      '  "mnt_entries": os.listdir("/mnt"),',
      '  "run_entries": os.listdir("/run"),',
      '}))',
    ].join('\n');

    const r = await transport.call<ProcExecResult>('proc.exec', {
      binding,
      cwd: workspaceRoot,
      mode: 'workspace-write',
      networkMode: 'offline',
      command: `python3 - <<'PY'\n${pyCheck}\nPY`,
    });
    assert.equal(r.exitCode, 0, `stderr: ${r.stderr.text}`);
    const data = JSON.parse(r.stdout.text.trim()) as {
      io_uring_ret: number;
      io_uring_errno: number;
      vsock_errno: number;
      inet_errno: number;
      mnt_entries: string[];
      run_entries: string[];
    };
    assert.equal(data.io_uring_ret, -1);
    assert.equal(data.io_uring_errno, 1, 'io_uring_setup must return EPERM (1)');
    assert.equal(data.vsock_errno, 1, 'AF_VSOCK must return EPERM (1)');
    assert.equal(data.inet_errno, 13, 'Offline mode AF_INET must return EACCES (13)');
    assert.deepEqual(data.mnt_entries, [], '/mnt must be completely empty');
    assert.deepEqual(data.run_entries, [], '/run must be completely empty in offline mode');
  });

  it('Positive & Negative (Managed UdsAllowlistProxy inside --unshare-net): allows localLabPorts via UDS bridge, blocks SSRF & direct TCP', async () => {
    const labServer = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('SANDBOX_UDS_LAB_OK');
    });
    await new Promise<void>((resolve) => labServer.listen(0, '127.0.0.1', resolve));
    const labPort = (labServer.address() as net.AddressInfo).port;

    try {
      const cfgRes = await transport.call<{ enabled: boolean; socketPath?: string }>('proxy.configure', {
        enabled: true,
        localLabPorts: [labPort],
        enableInteractiveApproval: false,
      });
      assert.equal(cfgRes.enabled, true);
      assert.ok(cfgRes.socketPath);

      // 1. Allowed localLabPorts request via HTTP_PROXY UDS bridge succeeds!
      const okRes = await transport.call<ProcExecResult>('proc.exec', {
        binding,
        cwd: workspaceRoot,
        mode: 'workspace-write',
        networkMode: 'allowlist-proxy',
        command: `curl -fsS http://127.0.0.1:${labPort}/check`,
      });
      assert.equal(okRes.exitCode, 0, `stderr: ${okRes.stderr.text}`);
      assert.equal(okRes.stdout.text.trim(), 'SANDBOX_UDS_LAB_OK');

      // 2. Direct connect bypassing proxy (--noproxy '*') fails because of --unshare-net!
      const directRes = await transport.call<ProcExecResult>('proc.exec', {
        binding,
        cwd: workspaceRoot,
        mode: 'workspace-write',
        networkMode: 'allowlist-proxy',
        command: `curl --noproxy '*' --connect-timeout 2 -sS http://127.0.0.1:${labPort}/check`,
      });
      assert.notEqual(directRes.exitCode, 0, 'Direct bypass must fail inside --unshare-net');

      // 3. SSRF to cloud metadata IP via proxy returns 403 Forbidden!
      const ssrfRes = await transport.call<ProcExecResult>('proc.exec', {
        binding,
        cwd: workspaceRoot,
        mode: 'workspace-write',
        networkMode: 'allowlist-proxy',
        command: 'curl -sS -i http://169.254.169.254/latest/meta-data/',
      });
      assert.match(ssrfRes.stdout.text, /403 Forbidden/);
      assert.match(ssrfRes.stdout.text, /DSH WSL Sandbox Proxy Blocked/);
    } finally {
      await transport.call('proxy.configure', { enabled: false });
      await new Promise<void>((r) => labServer.close(() => r()));
    }
  });

  it('Negative (prlimit & invalidate): caps process count and kills live background process groups on invalidate()', async () => {
    // 1. prlimit --nproc check: verify ulimit -u inside sandbox matches configured rlimits.nproc
    const rCap = await transport.call<ProcExecResult>('proc.exec', {
      binding,
      cwd: workspaceRoot,
      mode: 'workspace-write',
      networkMode: 'offline',
      rlimits: { nproc: 64, nofile: 512 },
      command: 'echo "NPROC=$(ulimit -u) NOFILE=$(ulimit -n)"',
    });
    assert.equal(rCap.exitCode, 0, `stderr: ${rCap.stderr.text}`);
    assert.equal(rCap.stdout.text.trim(), 'NPROC=64 NOFILE=512');

    // 2. Start a long sleep process, then call invalidate() -> kills process tree immediately!
    const longCall = transport.call<ProcExecResult>('proc.exec', {
      binding,
      cwd: workspaceRoot,
      mode: 'workspace-write',
      networkMode: 'offline',
      timeoutMs: 30_000,
      command: 'sleep 30',
    });

    await new Promise((r) => setTimeout(r, 200));
    const killed = await transport.invalidate(binding.generation + 1);
    assert.ok(killed >= 1, `Expected at least 1 killed process, got ${killed}`);

    const outcome = await longCall;
    assert.equal(outcome.aborted, true);
  });

  it('Negative (Real bwrap Config Masking): hides ~/.config/dsh-wsl-sandbox read/write and blocks outsideFile access', async () => {
    const cfgDir = path.join(os.homedir(), '.config', 'dsh-wsl-sandbox');
    const createdCfgDir = !fs.existsSync(cfgDir);
    const probeFile = path.join(cfgDir, '__dsh_mask_probe.txt');
    fs.mkdirSync(cfgDir, { recursive: true, mode: 0o700 });
    fs.chmodSync(cfgDir, 0o700);
    fs.writeFileSync(probeFile, 'TOP_SECRET_CONFIG_PAYLOAD', { mode: 0o600 });

    try {
      const r = await transport.call<ProcExecResult>('proc.exec', {
        binding,
        cwd: workspaceRoot,
        mode: 'workspace-write',
        networkMode: 'offline',
        command: [
          `ENTRIES=$(ls -A '${cfgDir}' 2>/dev/null || true)`,
          `echo "ENTRIES=[$ENTRIES]"`,
          `if touch '${cfgDir}/evil' 2>/dev/null; then echo "CFG_WRITABLE"; else echo "CFG_RO_BLOCKED"; fi`,
          `if test -e '${outsideFile}'; then echo "OUTSIDE_VISIBLE"; else echo "OUTSIDE_HIDDEN"; fi`,
        ].join('\n'),
      });
      assert.equal(r.exitCode, 0, `stderr: ${r.stderr.text}`);
      assert.match(r.stdout.text, /ENTRIES=\[\]/, 'Private config directory MUST appear completely empty inside bwrap');
      assert.doesNotMatch(r.stdout.text, /__dsh_mask_probe/);
      assert.match(r.stdout.text, /CFG_RO_BLOCKED/, 'Private config directory MUST be read-only inside bwrap');
      assert.match(r.stdout.text, /OUTSIDE_HIDDEN/, 'Outside /tmp host file MUST be invisible inside sandbox private /tmp');
    } finally {
      fs.rmSync(probeFile, { force: true });
      if (createdCfgDir) {
        fs.rmSync(cfgDir, { recursive: true, force: true });
      }
    }
  });

  it('Isolation (Multi-Session & Multi-Terminal): killing/resetting Session A NEVER kills Session B or clobbers its terminal CWD', async () => {
    const subA = path.join(workspaceRoot, 'sessA-dir');
    const subB = path.join(workspaceRoot, 'sessB-dir');
    fs.mkdirSync(subA, { recursive: true });
    fs.mkdirSync(subB, { recursive: true });

    const bindingA: SessionBinding = { ...binding, sessionId: 'sess-A', generation: 1 };
    const bindingB: SessionBinding = { ...binding, sessionId: 'sess-B', generation: 1 };

    // Both sessions share the same terminalId 't1' — their CWDs MUST remain independent!
    const initA = await transport.call<TerminalExecResult>('term.exec', {
      binding: bindingA,
      terminalId: 't1',
      cwd: workspaceRoot,
      mode: 'workspace-write',
      networkMode: 'offline',
      command: 'cd sessA-dir && pwd',
    });
    const initB = await transport.call<TerminalExecResult>('term.exec', {
      binding: bindingB,
      terminalId: 't1',
      cwd: workspaceRoot,
      mode: 'workspace-write',
      networkMode: 'offline',
      command: 'cd sessB-dir && pwd',
    });
    assert.equal(initA.cwd, subA);
    assert.equal(initB.cwd, subB);

    // Launch two concurrent long-running commands across Session A and Session B
    const procA = transport.call<ProcExecResult>('proc.exec', {
      binding: bindingA,
      terminalId: 't1',
      cwd: subA,
      mode: 'workspace-write',
      networkMode: 'offline',
      timeoutMs: 30_000,
      command: 'sleep 30',
    });
    const procB = transport.call<ProcExecResult>('proc.exec', {
      binding: bindingB,
      terminalId: 't1',
      cwd: subB,
      mode: 'workspace-write',
      networkMode: 'offline',
      timeoutMs: 30_000,
      command: 'sleep 30',
    });

    await new Promise((r) => setTimeout(r, 250));

    // Invalidate & reset ONLY Session A
    const killedA = await transport.invalidate(bindingA.generation + 1, { sessionId: 'sess-A' });
    assert.equal(killedA, 1, 'Expected ONLY Session A process to be killed');
    await transport.call('term.reset', { sessionId: 'sess-A', terminalId: 't1' });

    const outcomeA = await procA;
    assert.equal(outcomeA.aborted, true);

    // Session B MUST still be alive!
    const listB = await transport.call<{ active: Array<{ sessionId: string }> }>('proc.list', { sessionId: 'sess-B' });
    assert.equal(listB.active.length, 1, 'Session B process MUST remain alive when Session A is invalidated');

    // Session B terminal 't1' MUST still remember subB even after Session A reset 't1'!
    const pwdB = await transport.call<TerminalExecResult>('term.exec', {
      binding: bindingB,
      terminalId: 't1',
      cwd: workspaceRoot,
      mode: 'workspace-write',
      networkMode: 'offline',
      command: 'pwd',
    });
    assert.equal(pwdB.stdout.text.trim(), subB, 'Session B terminal CWD must be untouched by Session A reset');

    // Now cleanly terminate Session B
    const killedB = await transport.invalidate(bindingB.generation + 1, { sessionId: 'sess-B' });
    assert.equal(killedB, 1);
    const outcomeB = await procB;
    assert.equal(outcomeB.aborted, true);
  });

  it('Lifecycle (Zero Leaks): WslTransport.dispose() kills wsl-runner cleanly, removes temp proxy dir, and doctor grades profiles accurately', async () => {
    const dedicated = new WslTransport({
      mode: 'local-linux',
      distro: 'linux-devbox',
      runnerPath: RUNNER_PATH,
    });

    try {
      const ping = await dedicated.call<{ pid: number; runnerId: string }>('ping');
      assert.ok(Number.isInteger(ping.pid) && ping.pid > 1);

      const proxyCfg = await dedicated.call<{ enabled: boolean; socketPath?: string }>('proxy.configure', {
        enabled: true,
        enableInteractiveApproval: false,
      });
      assert.equal(proxyCfg.enabled, true);
      assert.ok(proxyCfg.socketPath);
      const proxyDir = path.dirname(proxyCfg.socketPath);
      assert.equal(fs.existsSync(proxyDir), true);

      // Run a command over the UDS loopback bridge (spawns socat/node bridge inside bwrap) to ensure zero leaked bridge
      const bridgeRun = await dedicated.call<ProcExecResult>('proc.exec', {
        binding,
        cwd: workspaceRoot,
        mode: 'workspace-write',
        networkMode: 'allowlist-proxy',
        command: 'echo "BRIDGE_RAN_OK"',
      });
      assert.equal(bridgeRun.exitCode, 0, bridgeRun.stderr.text);

      // Graceful dispose -> must terminate runner PID and remove proxyDir!
      await dedicated.dispose();
      await new Promise((r) => setTimeout(r, 150));

      let alive = true;
      try {
        process.kill(ping.pid, 0);
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === 'ESRCH') alive = false;
      }
      assert.equal(alive, false, `wsl-runner PID ${ping.pid} must be completely dead after dispose()`);
      assert.equal(fs.existsSync(proxyDir), false, `Proxy temp directory ${proxyDir} must be deleted after dispose()`);

      // Verify real dsh-wsl-doctor grades selectedProfile accurately
      const { runDoctor } = await import('../../packages/bootstrap/src/doctor.ts');
      const coreDoc = await runDoctor({ profile: 'core' });
      const uniDoc = await runDoctor({ profile: 'universal' });
      assert.equal(coreDoc.selectedProfile, 'core');
      assert.equal(uniDoc.selectedProfile, 'universal');
      assert.equal(coreDoc.sandbox.escapeMaskSelfTest, true);
      assert.equal(coreDoc.sandbox.configMaskSelfTest, true);
      assert.equal(coreDoc.sandbox.seccompIoUringBlocked, true);
      assert.equal(coreDoc.sandbox.seccompAfVsockBlocked, true);
      assert.ok(coreDoc.hardware.driverNote.includes('USBIP'));
    } finally {
      await dedicated.dispose();
    }
  });
});
