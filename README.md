# `dsh-wsl-sandbox` — DeepSeek Harness (DSH) WSL 2 Execution Backend & OS Sandbox

Codex-grade Linux kernel sandbox (`bubblewrap` + pure-TypeScript `seccomp-bpf` + `prlimit` + UDS allowlist proxy), zero-token Bash & Windows PowerShell command approval system, laptop-friendly Agent-guided Codex toolchain setup, and **100% coexistence with host DSH plugins (including `dsh-purge`)**.

---

## Core Architecture

| Package | Responsibility |
| :--- | :--- |
| `packages/core` | Pure TypeScript (Node 22 ESM, **zero npm runtime dependencies**, zero `node-gyp`): `SessionBinding` validation, `EnvSanitizer`, Checklist B `dangerous-paths` + `.env*` depth-3 masking, `x86_64`/`aarch64` `seccomp-bpf` compiler (`io_uring`, `AF_VSOCK`, `AF_PACKET`, `ptrace`, `mount`, `bpf`, x32), `bwrap-builder`, 8-layer `BashAstGuard`, `PwshGuard` (UTF-16LE `-EncodedCommand` & backtick deobfuscation), concurrent `ApprovalController`, `UdsAllowlistProxy` (SSRF defense + HTTP/SOCKS5 upstream chaining). |
| `packages/wsl-runner` | Persistent in-distro NDJSON RPC worker: `probe`, `ConfinedFsService` (zero 9P), `ConfinedProcManager` (`bwrap --seccomp 3` + `prlimit` + refcounted Checklist B placeholder cleanup + PGID teardown), `ConfinedTerminalManager`, and managed in-WSL `UdsAllowlistProxy` with bidirectional `proxy.authorizeHost` callbacks. |
| `packages/dsh-plugin` | Coexistence-safe Cordis plugin (`dsh-wsl-sandbox` + `dsh-wsl-sandbox-web-ui`): 7 additive `wsl_*` tools (`wsl_bash`, `wsl_read`, `wsl_write`, `wsl_edit`, `wsl_glob`, `wsl_grep`, `wsl_terminal`), non-invasive `ctx.systemPrompt` routing section (`order: 4200`), `AGENTS.md` marker-delimited upsert, host `pwsh` `tools/pre-execute` guard, `ApprovalBridge` (`balanced` / `strict` / `trust-workspace` with `dsh-purge` `hooksDenyBypass` fallback detection), human-only `ConfigStore` (`0600`), and `/wsl-sandbox/api/*` + `/wsl-sandbox/ui` (`z-index <= 850`, basic panel hides `/mnt`). |
| `packages/bootstrap` | Laptop-friendly, **zero-Docker**, **zero-kernel-build**, **zero-`pyenv`-compile** provisioning: `dsh-wsl-env-setup` Agent prompt/skill + idempotent binary-only `provision-wsl.sh` (`core` / `standard` / `universal`, `--mirror cn`, `--proxy`) + `dsh-wsl-doctor` live kernel & 22-tool Codex matrix CLI + `install-dsh-plugin.ps1`. |

---

## Coexistence with Host DSH Plugins (e.g. `dsh-purge`)

- **Zero Cordis Conflicts**: `cordis.patch.yml` only `- insert:`s `dsh-wsl-sandbox` and `dsh-wsl-sandbox-web-ui`. Never disables or edits `system-prompt`, `fs-local`, `subprocess-local`, `sandbox-local`, `pwsh-local`, `app.asar`, `@deepseek-ai/*`, or `pnpm-workspace.yaml`.
- **Hybrid Windows + WSL Workflows**: Keeps Windows native tools alive for `usbipd-win` / ESP32 / COM-port tasks while routing coding, git, builds, tests, ESP-IDF compilation, and Kali/Linux workflows to `wsl_*` tools.
- **`balanced` Approval Protection**: Even when `dsh-purge` sets `hooksDenyBypass: true`, `ApprovalBridge` detects instant/bypassed host auto-approvals on L3 high-risk commands, `wsl.exe` bypass attempts, out-of-workspace writes, unknown network domains, and **all physical device operations**, routing them to the independent human approval queue (`/wsl-sandbox/api/approvals`).
- **Physical Device Auto-Downgrade**: Any operation touching `/dev/ttyUSB*`, `/dev/ttyACM*`, `/dev/bus/usb/*`, `esptool`, `openocd`, or `usbipd bind/attach/detach/unbind` unconditionally forces single-shot manual `allow-once` (session caching blocked).

---

## Quick Start (Windows Laptop + WSL 2)

### 1. Prepare WSL 2 (Zero Docker, Zero Kernel Build)
Either reuse an existing Ubuntu 22.04/24.04 WSL 2 distro, or install a clean official distro:
```powershell
wsl.exe --install -d Ubuntu-24.04
```
Then let your AI Agent drive the setup interactively using the bundled **`dsh-wsl-env-setup`** skill (`.agents/skills/dsh-wsl-env-setup/SKILL.md` / `packages/bootstrap/prompts/wsl-env-setup.md`), OR run the idempotent binary-only script directly inside WSL 2:
```bash
bash packages/bootstrap/provision-wsl.sh --profile standard --mirror cn
# Or with local Clash/Mihomo/v2rayN proxy:
bash packages/bootstrap/provision-wsl.sh --profile standard --proxy http://127.0.0.1:7890
```

### 2. Verify WSL 2 Kernel Isolation & Codex Toolchain
```bash
node packages/bootstrap/src/doctor.ts
# JSON output for Agent consumption:
node packages/bootstrap/src/doctor.ts --json
```

### 3. Build & Register Plugin with DSH (Desktop or CLI)
```powershell
node scripts/build.mjs
.\packages\bootstrap\install-dsh-plugin.ps1 -Distro Ubuntu-24.04 -WorkspaceRoot /home/<user>/workspace -UpsertAgentsMd
```

### 4. Verify End-to-End on Real Windows + WSL 2
```powershell
.\tests\windows-wsl-verify\verify-wsl2.ps1 -Distro Ubuntu-24.04
```

---

## Development & Testing

```bash
# Build all packages to dist/ (zero npm dependencies, Node >= 22.18)
npm run build

# Run all 3 test suites (unit + real Linux kernel sandbox + dsh-purge coexistence)
npm test

# Run individual suites
npm run test:unit
npm run test:linux-sandbox
npm run test:coexistence

# Run live kernel & Codex toolchain diagnostic
npm run doctor
```

### Verification Boundary
- **Verified locally on Linux 6.18 x86_64**: Unit tests (`tests/unit/core.test.ts`), real Linux kernel `bwrap 0.9.0` + `seccomp-bpf` (`io_uring_setup` EPERM, `AF_VSOCK` EPERM, offline `AF_INET` EACCES) + `prlimit` + Checklist B EROFS + `.env*` masking + `/shares/<alias>` + `UdsAllowlistProxy` inside `--unshare-net` + `invalidate()` process-group kill (`tests/linux-sandbox/real-kernel-sandbox.test.ts`), and full simulated Cordis `dsh-purge` coexistence (`tests/plugin-coexistence/dsh-purge-coexistence.test.ts`).
- **Verify on your Windows host**: Run `tests/windows-wsl-verify/verify-wsl2.ps1` against your actual Windows 11 + WSL 2 distro + DSH Desktop/CLI instance.
