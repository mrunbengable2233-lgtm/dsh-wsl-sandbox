# `packages/runner` — NDJSON Wire Protocol & Execution Contracts

## 1. Transport Framing
- Single persistent process per `(distribution, username)` launched via `wsl.exe -d <distro> -u <user> -- node <runnerPath>`.
- Line-delimited JSON (`\n`) over `stdin` (Host → Runner) and `stdout` (Runner → Host); `stderr` reserved strictly for structured fatal diagnostics.
- Max frame size: `16 MiB` (reject larger frames with `INVALID_ACTION`).
- Heartbeat lease: Host sends `ping` every 10s; if `stdin` hits EOF or heartbeat lease expires (default 60s), Runner kills all active child process groups (`SIGKILL` after `graceMs`) and exits cleanly.

## 2. RPC Methods

| Method | Request Params | Response Result | Failure Codes |
| :--- | :--- | :--- | :--- |
| `ping` | `{}` | `{ ok: true, runnerId, uptimeMs }` | — |
| `probe` | `{ workspaceRoot, cwd, distribution, allowMockWsl? }` | `WslProbeResult` (real UID, arch, WSL2 kernel check, `bwrap` version, `--disable-userns` support, functional `bwrap + seccomp` self-test verdict, probed sockets, canonical `workspaceRoot` & `cwd`) | `BACKEND_UNAVAILABLE`, `SANDBOX_UNAVAILABLE`, `POLICY_BLOCK` |
| `fs.stat` | `{ binding, path }` | `{ exists, kind, size, mtimeMs, maskedEnv? }` | `POLICY_BLOCK`, `STALE_BINDING` |
| `fs.read` | `{ binding, path, offset?, limit?, unmaskEnv? }` | `{ content, truncated, totalBytes, maskedEnv? }` | `POLICY_BLOCK`, `STALE_BINDING` |
| `fs.write` | `{ binding, path, content, mode? }` | `{ bytesWritten, canonicalPath }` | `POLICY_BLOCK`, `STALE_BINDING` |
| `fs.edit` | `{ binding, path, oldText, newText, replaceAll? }` | `{ replacements, canonicalPath }` | `POLICY_BLOCK`, `STALE_BINDING` |
| `fs.list` | `{ binding, path, maxEntries? }` | `{ entries: FsDirEntry[] }` | `POLICY_BLOCK`, `STALE_BINDING` |
| `fs.glob` | `{ binding, pattern, cwd?, maxResults? }` | `{ matches: string[], truncated: boolean }` | `POLICY_BLOCK`, `STALE_BINDING` |
| `fs.grep` | `{ binding, query, cwd?, regex?, glob?, maxMatches? }` | `{ matches: GrepMatch[], truncated: boolean }` | `POLICY_BLOCK`, `STALE_BINDING` |
| `fs.delete` | `{ binding, path }` | `{ deleted: true }` | `POLICY_BLOCK`, `STALE_BINDING` |
| `fs.move` | `{ binding, from, to }` | `{ moved: true }` | `POLICY_BLOCK`, `STALE_BINDING` |
| `proc.exec` | `{ binding, command, argv?, cwd, mode, env?, dshEnv?, timeoutMs, maxOutputBytes, rlimits?, networkMode, proxySocketHostPath?, cacheDir?, maskEnvSecrets?, mirrorCn? }` | `ProcExecResult` (`exitCode`, `signal`, `timedOut`, `aborted`, `stdout`, `stderr`, `sandbox: { mode, denied, enforcement, runnerFailed, denialMatches }`) | `SANDBOX_UNAVAILABLE`, `SANDBOX_PREPARATION_FAILED`, `STALE_BINDING` |
| `proc.kill` | `{ execId }` | `{ killed: boolean }` | — |
| `term.exec` | `{ ...ProcExecParams, terminalId }` | `TerminalExecResult` (`...ProcExecResult, terminalId, cwd`) | `SANDBOX_UNAVAILABLE`, `STALE_BINDING` |
| `term.reset` | `{ terminalId }` | `{ reset: boolean }` | — |
| `proxy.configure` | `{ enabled, customAllowedDomains?, upstreamProxy?, localLabCidrs?, localLabPorts?, enableInteractiveApproval? }` | `{ enabled, socketPath? }` | `INVALID_SETUP` |
| `proxy.approveDomain` | `{ host }` | `{ approved: boolean, host }` | — |
| `proxy.status` | `{}` | `{ enabled: boolean, socketPath? }` | — |
| `invalidate` | `{ generation }` | `{ killedCount: number }` | — |

### Bidirectional Runner → Host Callback Frame
Because `UdsAllowlistProxy` runs inside WSL 2 (`wsl-runner`) so `bwrap` always binds a native Linux UDS even when DSH runs on Windows, unknown non-SSRF host requests emit a callback frame on `stdout`:
- Request: `{ kind: 'callback', id, method: 'proxy.authorizeHost', params: { host, port } }`
- Response (Host → Runner on `stdin`): `{ kind: 'callback-response', id, ok: true, result: { allowed: boolean } }`

## 3. FS Security & Anti-TOCTOU Contract
- Resolve every requested path against `binding.workspaceRoot` (or authorized `/shares/<alias>` when explicitly enabled).
- Reject symlink escapes (`fs.realpath` + segment-by-segment containment verification; open writes with `O_NOFOLLOW` where creating/replacing, atomic temp-file + rename within same parent directory).
- Enforce identical **Checklist B** write blocks (`DANGEROUS_FILES` & `DANGEROUS_DIRECTORIES`) and **`.env*` read masking** (`maskedEnv: true`, empty content unless `maskEnvSecrets === false`) as `bwrap`.
- In `read-only` sandbox mode, `fs.write`, `fs.edit`, `fs.delete`, `fs.move` unconditionally throw `POLICY_BLOCK`.

## 4. Process Confinement & Teardown Contract
- Write compiled `seccomp-bpf` Buffer to a private `0600` temp file, pass its fd to `bwrap --seccomp 3` via Node `stdio` extra fd array (`stdio: ['pipe', 'pipe', 'pipe', seccompFd]`), and close parent fd + unlink temp file immediately after spawn.
- Refcount `bwrapBuild.createdPlaceholders` (`placeholderRefs: Map<string, number>`) across concurrent executions and unlink any 0-byte placeholder file when refcount reaches 0 in `finally`, guaranteeing zero `git status` pollution.
- Spawn in detached process group (`detached: true`) so `process.kill(-pid, 'SIGTERM')` followed by `SIGKILL` after `graceMs` kills the entire descendant tree.
- Collect bounded stdout/stderr tails in memory; spill full stream to private `0600` temp spill file when `maxOutputBytes` is exceeded.
- On `invalidate(generation)`: clear terminal cwds, clear session-approved proxy domains, terminate every running process belonging to `< generation`, and wait for process group exit.
