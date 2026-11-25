# `packages/dsh-plugin` — Cordis Bundle, Tools & Top-27 Plugin Coexistence Contracts

## 1. Cordis Bundle & Native Browser Client (`package.json`, `cordis.patch.yml`, `client.js`)
- `cordis.patch.yml` inserts ONLY `id: dsh-wsl-sandbox` (`name: 'dsh-wsl-sandbox'`); **NEVER** disables or modifies `system-prompt`, `fs-local`, `subprocess-local`, `sandbox-local`, `pwsh-local`, `dsh-purge`, `dshmarket`, or agent presets.
- `package.json` declares `dsh.bundle: { "patch": "./cordis.patch.yml" }` and `dsh.client` (`platform: "web"`, `inject: ["@deepseek-ai/dsh-client-locale", "@deepseek-ai/dsh-client-ui-slots", "@deepseek-ai/dsh-client-ui-settings"]`), registering `settings.section` (`id: 'dsh-wsl-sandbox'`, `order: 45`) and `settings.section.icon` without colliding with `dshmarket` (`20`), `dsh-purge` (`30`), `cc-safety-net` (`60`), or `dsh-better-sidebar` (`80`).
- Uses `getOptionalService(ctx, key)` (`ctx.get(key)`) so strict `@deepseek-ai/cordis` proxy contexts never throw uninjected property errors across `desktop`, `web`, and `headless` profiles.

## 2. Additive Sandboxed WSL Tool Suite (`src/tools.ts`)
All 7 tools provide `output: { schema, render }` + `isConcurrencySafe` and share one verified `SessionBinding` + persistent `wsl-runner` + `bwrap`/`seccomp`/`UdsProxy` + `ApprovalController`:
- `wsl_bash`: Run POSIX Bash commands in the bound WSL 2 sandbox (`--no-cwd-arg` compatible with `cc-safety-net`). Runs `EnvSanitizer` → `BashAstGuard` (including pre-execution shell dialect guard) → `ApprovalBridge` → `wsl-runner` `proc.exec`.
- `wsl_read`: 1-based line `offset`/`limit` file reader inside WSL workspace (honors `.env*` masking).
- `wsl_write` / `wsl_edit`: `O_NOFOLLOW` atomic file writer/editor (honors `read-only` mode & Checklist B locks).
- `wsl_glob` / `wsl_grep`: Fast in-distro glob & content search (zero 9P, honors `.env*` masking).
- `wsl_terminal`: Controlled stateful WSL session wrapper preserving CWD across `exit 0` via Bash `EXIT` trap.

## 3. Non-Invasive Prompt Injection & `AGENTS.md` Generator (`src/prompt-injector.ts`)
- Calls `ctx.systemPrompt.section({ id: 'dsh-wsl-sandbox-routing', order: 4200, interpolate: false, ... })` (never touches `id: system-prompt` row or triggers `{{...}}` template collisions).
- Exports `upsertAgentsMdWslSection(projectRoot)` to cleanly insert/update `<!-- dsh-wsl-sandbox:start --> ... <!-- dsh-wsl-sandbox:end -->`.

## 4. Host Shell Single-Shell Purity & Dialect Guard (`src/pwsh-hook.ts`)
- Registers BOTH monotonic `ctx.tools.guard(...)` (cannot be overridden by listener ordering) AND `tools/pre-execute` waterfall listener.
- Routes Windows PowerShell/CMD tools (`pwsh`, `powershell`, `cmd`, `mcp__windows__PowerShell`, etc.) through `PwshGuard` (blocking nested `cmd` inside `pwsh`, mixing `pwsh.exe` and `powershell.exe`, `/s /q` slash flags, `2>nul`, and `\\wsl.localhost\` UNC sandbox escapes).
- Treats Windows-hosted POSIX Bash tools (`@linxin666/dsh-win-bash` `win_bash`, `dsh-ops` `ops_bash`) with POSIX-aware rules (`evaluateHostPosixBashOnWindows`), preventing false-positive PowerShell dialect blocks while still guarding `.wslconfig`, UNC shares, and `usbipd`.

## 5. Approval Bridge (`src/approval-bridge.ts`) — `dsh-purge` Coexistence Protocol
- Supports `approvalPolicyMode`: `'balanced'` (default) | `'strict'` | `'trust-workspace'`.
- Detects `< 15ms` synthetic non-human auto-approvals (`dsh-purge` `hooksDenyBypass`) and routes L3 destructive commands, `wsl.exe` bypasses, out-of-workspace accesses, unknown domains, and **all physical hardware operations** (`touchesPhysicalDevice: true` → mandatory `allow-once`) to the independent approval queue (`/wsl-sandbox/api/approvals`).

## 6. Human-Only Config Store, Direct Mount Controls & Original WSL Backup (`src/config-store.ts`, `src/web-api.ts`)
- Config persisted at `$DSH_HOME/dsh-wsl-sandbox/config.json` (`0600`), mutable ONLY via same-origin/loopback `/wsl-sandbox/api/*` with CSRF origin verification.
- Prominent main-screen quick controls on `状态` (`Status`) view:
  - **Disable Full Windows Drive Mount**: Kernel `--tmpfs /mnt` lock active by default + one-click original WSL config backup (`POST /wsl-sandbox/api/wsl-config/backup`) & optional `/etc/wsl.conf` `[automount] enabled = false` helper (`provision-wsl.sh --disable-automount` / `--restore-configs`).
  - **Quick Mount Single Directory**: Accepts Windows folder paths (`D:\Datasets\ESP32`) or Linux paths, auto-converting to `/mnt/d/Datasets/ESP32` → `/shares/ESP32` (`ro` default) while rejecting bare drive roots (`C:\`, `D:\`) and Windows system/profile roots, with instant one-click unmount (`DELETE /wsl-sandbox/api/advanced/shares/:id` → `invalidateNow()`).
