# `dsh-wsl-sandbox` — DeepSeek Harness (DSH) WSL 2 Execution Backend & OS Sandbox (`v0.3.0`)

> **Language / 语言选择**: [**简体中文**](./README.md) | **English**

Codex-grade Linux kernel sandbox (`bubblewrap` + native `seccomp-bpf` + `prlimit` + UDS allowlist proxy) for **DeepSeek Harness (`@deepseek-ai/dsh@0.2.2-rc.5`)**, featuring a **Shared DSH/WSL Node Runtime** (`Node >=20.11.0`, `22.19+` / `24 LTS` recommended + `ELECTRON_RUN_AS_NODE=1`), **SSD-Safe Coalesced Structured Logging** (`2.5s`/`64 KiB` batched writes, zero idle FDs, 100% RAM-served queries), **Official PowerShell System AST (`[Parser]::ParseInput`/`ParseFile`) + 8-Layer `BashAstGuard` Single-Shell Dialect Guard**, zero-token Bash & Windows PowerShell approval with **physical hardware/driver single-shot lock**, **DIY/WSL Manager moved-VHDX auto-discovery & automatic native `ext4` `wsl-runner` staging**, single-folder `/shares/<alias>` quick mounts, read-only WSL config backup/restore, zero-leak process lifecycle, and **100% conflict-free coexistence with Top-27 DSH Marketplace & CLI plugins (including `dsh-purge`, `dshmarket`, `cc-safety-net`, `dsh-win-bash`, and `dsh-better-sidebar`)**.

---

## Documentation Index

- **Beginner Build, PowerShell 7 + UTF-8 & Deployment Guide (Chinese)**: [`docs/BEGINNER-BUILD-AND-DEPLOY.zh.md`](./docs/BEGINNER-BUILD-AND-DEPLOY.zh.md)
- **Installation, Multi-Distro / WSL Manager, Backup/Restore & Release Guide (Chinese)**: [`INSTALL.zh.md`](./INSTALL.zh.md)
- **Red-Team Fuzzing & Zero-Execution Matrix Guide (Chinese)**: [`docs/AI-DANGEROUS-COMMAND-FUZZING-GUIDE.zh.md`](./docs/AI-DANGEROUS-COMMAND-FUZZING-GUIDE.zh.md)
- **Linux Kernel Isolation & Security Audit Handoff Whitepaper (Chinese)**: [`docs/KERNEL-SECURITY-HANDOFF.zh.md`](./docs/KERNEL-SECURITY-HANDOFF.zh.md)
- **Engineering Specification v2.0 & v0.3.0 Status Archive (Chinese)**: [`docs/specification-v2.0.md`](./docs/specification-v2.0.md)
- **Architecture Research & Reference Archive (Chinese)**: [`docs/dsh-wsl-sandbox-architecture.md`](./docs/dsh-wsl-sandbox-architecture.md)
- **WSL Reference Config Templates**: [`packages/bootstrap/templates/`](./packages/bootstrap/templates/)
- **简体中文主页**: [`README.md`](./README.md)

---

## Core Architecture

| Package | Responsibility |
| :--- | :--- |
| **`packages/core`** | Pure TypeScript (zero runtime npm dependencies, zero `node-gyp`): `node-runtime.ts` (shares DSH's `process.execPath` / `ELECTRON_RUN_AS_NODE=1` on Windows and reuses Linux Node `>=22` / 24 LTS inside WSL while blocking `/mnt/*` `.exe`), `logger.ts` (`2.5s`/`64 KiB` coalesced NDJSON sink with `0` idle open FDs, `3s` burst folding, `120/10s` disk rate cap, `5 MiB × 3` rotation, recursive secret redaction, RAM-served UI queries), `binding.ts` & `env-sanitizer.ts` & `dangerous-paths.ts` (DIY distro & single-folder share normalization, USB/HID/CDC/video/serial device validation, Checklist B + `.env*` depth-3 masking + `$HOME` config dir masking), `seccomp-bpf.ts` & `bwrap-builder.ts` (`x86_64`/`aarch64` cBPF compiler blocking `io_uring_*`, `AF_VSOCK`, `AF_PACKET`, `ptrace`, `mount`, `bpf`, `x32`), `pwsh-system-parser.ts` + `pwsh-guard.ts` + 8-layer `bash-ast-guard.ts` (official PowerShell `[System.Management.Automation.Language.Parser]` AST worker + POSIX dialect & physical hardware/driver single-shot guard), `approval-controller.ts`, and `uds-proxy.ts` (SSRF + DNS-rebinding defense + clean socket teardown). |
| **`packages/wsl-runner`** | Persistent in-distro NDJSON RPC worker staged in native WSL `ext4` (`~/.local/share/dsh-wsl-sandbox/runner/` — zero `/mnt` dependency, zero Windows NTFS lock): streams structured logs over memory pipe to Host `StructuredLogger`, `probe`, `ConfinedFsService` (`O_NOFOLLOW` atomic writes + realpath confinement), `ConfinedProcManager` (`bwrap --seccomp 3` + `prlimit` + `(sessionId, terminalId)` `-pgid` teardown + `/proc/<pid>/stat` PGID verification + subshell-safe UDS bridge cleanup), `ConfinedTerminalManager`, `wsl.backupConfigs` (`0400` read-only), and managed `UdsAllowlistProxy` with lease watchdog. |
| **`packages/dsh-plugin`** | Native `@deepseek-ai/dsh@0.2.2-rc.5` Cordis plugin (`cordis.patch.yml` + browser `client.js` `settings.section` slot): dynamic multi-distro & WSL Manager `Lxss` discovery (`wsl-discovery.ts`), single-flight `ensureBound()` + automatic native `ext4` staging (`stageRunnerIntoWslAsync`), 7 `wsl_*` tools with `AbortController` cancellation, non-invasive `ctx.systemPrompt` routing (`order: 4200`), monotonic `ctx.tools.guard` + `tools/pre-execute` host guard, `ApprovalBridge`, `0600` + Windows `icacls` `ConfigStore`, and `/wsl-sandbox/api/*` (DNS rebinding `Host` + CSRF `Origin`/`X-DSH-WSL-Client` hardened) + `/wsl-sandbox/ui` with built-in Chinese/English console switcher. |
| **`packages/bootstrap`** | Laptop-friendly, **zero-Docker**, **zero-kernel-build**, **zero-`pyenv`-compile** provisioning across Ubuntu 26.04/24.04/22.04, Debian, Kali, Fedora, Arch (`archlinux`), openSUSE, and Alpine: `provision-wsl.sh` (`core`/`standard`/`universal` profiles in `profile.json` + incremental `provision-manifest.json`, Node 24 LTS fallback, `--step`, `--mirror cn`, `--proxy`, AppArmor `bwrap` setup, `--disable-automount`, `--uninstall`), pure-Node `scripts/stage-wsl-runner.mjs`, profile-aware `dsh-wsl-doctor`, and UTF-8 BOM + CRLF `install-dsh-plugin.ps1` / `uninstall-dsh-plugin.ps1`. |

---

## Quick Start (Windows 10/11 + WSL 2 — Two Coherent Setup Paths)

> **Deterministic L0 Installer Lock & Step-Order Gate**: By default, host monotonic `ctx.tools.guard` blocks AI tools from executing installer/uninstaller scripts autonomously (`L0 deny`). Choose either pre-installing via PowerShell (Path A) or opening the time-boxed **Controlled AI Bootstrap Channel** inside DSH Settings after previewing the scripts & SHA-256 (Path B). Full walkthroughs in [`docs/BEGINNER-BUILD-AND-DEPLOY.zh.md`](./docs/BEGINNER-BUILD-AND-DEPLOY.zh.md) and [`INSTALL.zh.md`](./INSTALL.zh.md).

### Path A: Pre-Install from PowerShell 7, then Register Plugin (Recommended)
```powershell
# 1. Optional zero-write preview (checks target distro, paths & SHA-256 checksums):
.\packages\bootstrap\install-dsh-plugin.ps1 -Provision -Profile standard -Mirror cn -DryRun

# 2. Run installer & provisioning wizard (auto-discovers WSL 2 / WSL Manager distros,
#    backs up .wslconfig & /etc/wsl.conf read-only, stages runner into native WSL ext4, and runs doctor):
.\packages\bootstrap\install-dsh-plugin.ps1 -Provision -Profile standard -Mirror cn -UpsertAgentsMd

# 3. Register plugin into DSH (Web/CLI or Desktop):
dsh plugin --profile web add .\dsh-wsl-sandbox-0.3.0.tgz
dsh plugin --profile desktop add .\dsh-wsl-sandbox-0.3.0.tgz
```

### Path B: Install Plugin First -> Preview Scripts -> Controlled 4-Step AI Bootstrap Channel
1. Import/enable `dsh-wsl-sandbox-0.3.0.tgz` inside DSH;
2. Open **Settings -> WSL 2 Sandbox** (or `/wsl-sandbox/ui`) and click **Preview Installer Scripts & SHA-256**;
3. Click **Open Bootstrap Channel & Copy Session Prompt** — host guards mechanically enforce **`1. Read-only Probe -> 2. -DryRun Preview Card -> 3. Single-Shot Install Approval -> 4. dsh-wsl-doctor`**, then auto-close the channel upon first verified `wsl_bash` binding.

> **WSL Networking & Distro Support**: `mirrored` networking is **NOT required** (`dsh-wsl-sandbox` communicates over `wsl.exe` stdio pipes + in-WSL `AF_UNIX` UDS proxy); default **`NAT`** mode is recommended for daily & USB/phone testing stability. Mainstream distros (Ubuntu 26.04/24.04/22.04, Debian, Kali, Fedora, Arch, openSUSE, Alpine) are fully supported without requiring `systemd`.

---

## Development & Verification

> **Host Safety**: Under `win32`, `npm test` / `node test` automatically enforces `DSH_WSL_NO_HOST_SPAWN=1` and never spawns host `wsl.exe` or `explorer.exe`. Run inside a WSL 2 / Linux kernel environment to execute all `81` tests including live `bwrap` + `seccomp-bpf` containment checks.

```bash
# Build all TypeScript modules, precompiled test artifacts, & native DSH browser client.js
npm run build

# Run automated test suite (81 tests total; 71 pass / 0 fail / 10 Linux-only skipped on win32; all 81 run on WSL 2)
npm test
node test

# Run zero-execution in-memory red-team command matrices (246 vectors across 3 suites: 30 + 24 + 192)
npm run fuzz:check
node scripts/run-dangerous-cmd-matrix.mjs --input tests/fixtures/audit-redteam-cases.json
node scripts/run-dangerous-cmd-matrix.mjs --input tests/fixtures/redteam-v021.json

# Live kernel isolation, config masking, USB driver & profile-aware toolchain diagnostic (inside WSL 2)
npm run doctor -- --profile standard
```
