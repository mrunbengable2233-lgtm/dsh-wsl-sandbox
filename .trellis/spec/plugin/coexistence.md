# `packages/dsh-plugin` — Cordis Bundle, Tools & Coexistence Contracts

## 1. Cordis Bundle Declaration (`cordis.patch.yml`)
- Inserts ONLY namespaced rows (`dsh-wsl-sandbox`, `dsh-wsl-sandbox-web-ui`); **NEVER** disables or modifies `system-prompt`, `fs-local`, `subprocess-local`, `sandbox-local`, `pwsh-local`, `dsh-purge`, or agent presets.
- Works identically across Electron Desktop (`desktop` profile) and CLI (`web` / `headless` profiles).

## 2. Additive Sandboxed WSL Tool Suite (`src/tools.ts`)
All 7 tools share one verified `SessionBinding` + persistent `wsl-runner` + `bwrap`/`seccomp`/`UdsProxy` + `ApprovalController`:
- `wsl_bash`: Run POSIX shell commands in the bound WSL 2 sandbox (`command`, `cwd?`, `timeoutMs?`, `sandbox_permissions?`, `justification?`). Runs `EnvSanitizer` → `BashAstGuard` → `ApprovalBridge` → `wsl-runner` `proc.exec`.
- `wsl_read`: Read file inside WSL workspace (honors `.env*` masking).
- `wsl_write`: Write file inside WSL workspace (honors `read-only` mode & Checklist B locks).
- `wsl_edit`: String-replace edit inside WSL workspace (honors `read-only` mode & Checklist B locks).
- `wsl_glob`: Fast in-distro file glob (no 9P).
- `wsl_grep`: Fast in-distro content search (`rg` / JS fallback, honors `.env*` masking).
- `wsl_terminal`: Controlled stateful WSL session wrapper running inside the same sandbox boundary (never exposes human interactive terminal stdin/PTY).

## 3. Non-Invasive Prompt Injection & `AGENTS.md` Generator (`src/prompt-injector.ts`)
- Calls `ctx.systemPrompt.register({ id: 'dsh-wsl-sandbox-routing', order: 4200, ... })` (incremental section API, never touches `id: system-prompt` row owned/modified by `dsh-purge`).
- Injects concise operational rule: prefer `wsl_*` tools for all Linux/POSIX/code/git/build/test/Kali/firmware compilation tasks; reserve Windows host tools (`pwsh`) strictly for Windows-only host hardware/OS actions (`usbipd-win`, COM port inspection, Windows binaries).
- Exports `upsertAgentsMdWslSection(projectRoot)` to cleanly insert/update a delimited `<!-- dsh-wsl-sandbox:start --> ... <!-- dsh-wsl-sandbox:end -->` block in `AGENTS.md` without overwriting user instructions.

## 4. Host PowerShell Guard Hook (`src/pwsh-hook.ts`)
- Registers a `tools/pre-execute` waterfall listener (optional, enabled by default).
- Filters strictly to host Windows shell tool names (`pwsh`, `powershell`, `cmd`, `shell` when targeting Windows); immediately calls `next()` for `wsl_*`, `dsh-purge` tools, MCP tools, and all non-shell tools.
- Evaluates command through `PwshGuard`:
  - `deny` → blocks with `POLICY_BLOCK` and actionable message.
  - `ask` → routes through `ApprovalBridge` (with `touchesPhysicalDevice: true` forcing manual `allow-once` for `usbipd bind/attach/detach`).
  - `allow` → `return next()`.

## 5. Approval Bridge (`src/approval-bridge.ts`) — `dsh-purge` Coexistence Protocol
- Supports `approvalPolicyMode`: `'balanced'` (default) | `'strict'` | `'trust-workspace'`.
- In `balanced`:
  1. Checks `ApprovalController` session rules (never matches banned prefixes or `touchesPhysicalDevice`).
  2. Calls host `ctx.approval.request(req)` when mounted.
  3. **Bypass detection**: if host `ctx.approval.request()` resolves `'allowed-once'` synchronously/non-interactively via a known bypass flag (`dsh-purge` `hooksDenyBypass` / instant auto-approve without human token) AND the request is marked `requiresIndependentFallback` (L3 destructive, `wsl.exe` bypass, physical device, out-of-workspace, unknown domain), routes to our plugin's independent approval queue (`/wsl-sandbox/api/approvals/:id/decide`) before launching.
- In `strict`: always routes L3 directly to our independent approval queue.
- In `trust-workspace`: in-workspace non-hardware L3 commands pass without prompt; out-of-workspace / escalation / unknown domain / physical device / `wsl.exe` bypass still require approval.

## 6. Human-Only Config Store & Web API/UI (`src/config-store.ts`, `src/web-api.ts`)
- Config persisted at `$DSH_HOME/dsh-wsl-sandbox/config.json` (mode `0600`), mutable ONLY via authenticated host HTTP routes `/wsl-sandbox/api/*` (NEVER via model tools).
- Basic panel: distro selector, sandbox mode, approval mode (`balanced`/`strict`/`trust-workspace`), network mode (`allowlist-proxy`/`offline`), upstream proxy (`http://127.0.0.1:7890` etc.), cache mode (`workspace-persistent`/`ephemeral-tmp`), per-project `.env*` unmask toggle, live pending approvals queue, `dsh-wsl-doctor` panel. **Zero `/mnt` full-drive controls on basic view.**
- **Advanced panel** (collapsed by default):
  - Per-use single-directory shares (`/shares/<alias>`, default `ro`, one-click revoke → `invalidate()`).
  - Single-device passthrough whitelist (`/dev/ttyUSB*`, `/dev/ttyACM*`, `/dev/bus/usb/*`, default empty, every command using them auto-downgrades to manual `allow-once`).
  - Local lab CIDR/port allowlist for UDS proxy (`127.0.0.1:<port>` / experimental subnet).
  - Custom domain allowlist editor.
- UI CSS classes prefixed `.dsh-wsl-sbx-*`; `z-index <= 850`.
