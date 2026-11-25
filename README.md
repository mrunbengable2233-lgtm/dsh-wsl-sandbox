# `dsh-wsl-sandbox` — DeepSeek Harness (DSH) WSL 2 Execution Backend & OS Sandbox

Codex-grade Linux kernel sandbox (`bubblewrap` + pure-TypeScript `seccomp-bpf` + `prlimit` + UDS allowlist proxy), Single-Shell Purity & Dialect Guard, zero-token Bash & Windows PowerShell command approval system, direct UI quick-controls for disabling full-drive mounts & mounting single directories, automatic original WSL config backup/restore, and **verified 100% coexistence with Top-27 DSH Marketplace & CLI plugins (including `dsh-purge`, `dshmarket`, `cc-safety-net`, `dsh-win-bash`, and `dsh-better-sidebar`)**.

- **简明中文安装、原始 WSL 配置备份还原与 npm 托管指南**：[`INSTALL.zh.md`](./INSTALL.zh.md)
- **Linux 内核隔离机制与安全审计交接白皮书（面向内核/系统工程师）**：[`docs/KERNEL-SECURITY-HANDOFF.zh.md`](./docs/KERNEL-SECURITY-HANDOFF.zh.md)
- **原始 WSL 配置参考备份模板**：[`packages/bootstrap/templates/`](./packages/bootstrap/templates/)

---

## Core Architecture

| Package | Responsibility |
| :--- | :--- |
| `packages/core` | Pure TypeScript (Node 22+ ESM, **zero npm runtime dependencies**, zero `node-gyp`): `SessionBinding` & Windows-to-WSL single-folder share normalization (`D:\Datasets\ESP32` -> `/mnt/d/Datasets/ESP32` -> `/shares/ESP32`), `EnvSanitizer`, Checklist B `dangerous-paths` + `.env*` depth-3 masking, `x86_64`/`aarch64` `seccomp-bpf` compiler (`io_uring_*`, `AF_VSOCK`, `AF_PACKET`, `ptrace`, `mount`, `bpf`, `x32`), `bwrap-builder`, 8-layer `BashAstGuard` + POSIX dialect linter, `PwshGuard` (Single-Shell Purity + CMD/PS5.1/PS7 dialect & UNC escape guard), concurrent `ApprovalController`, `UdsAllowlistProxy` (SSRF + DNS-rebinding defense + HTTP/SOCKS5 upstream chaining). |
| `packages/wsl-runner` | Persistent in-distro NDJSON RPC worker: `probe`, `ConfinedFsService` (1-based line slicing, `O_NOFOLLOW` atomic writes, zero 9P), `ConfinedProcManager` (`bwrap --seccomp 3` + `prlimit` + refcounted Checklist B placeholder cleanup + `-pgid` teardown), `ConfinedTerminalManager` (`EXIT` trap CWD continuity), `wsl.backupConfigs` / `wsl.listBackups`, and managed in-WSL `UdsAllowlistProxy`. |
| `packages/dsh-plugin` | Native `@deepseek-ai/dsh@0.2.2-rc.5` Cordis plugin (`cordis.patch.yml` + browser `client.js` `settings.section` slot): 7 additive `wsl_*` tools (`wsl_bash`, `wsl_read`, `wsl_write`, `wsl_edit`, `wsl_glob`, `wsl_grep`, `wsl_terminal`), non-invasive `ctx.systemPrompt` routing (`order: 4200`, `interpolate: false`), monotonic `ctx.tools.guard` + `tools/pre-execute` host shell guard, `ApprovalBridge`, human-only `ConfigStore` (`0600`), and `/wsl-sandbox/api/*` + `/wsl-sandbox/ui` with direct main-screen controls for full-drive mount lock, single-folder mounting, and WSL config backup. |
| `packages/bootstrap` | Laptop-friendly, **zero-Docker**, **zero-kernel-build**, **zero-`pyenv`-compile** provisioning: `provision-wsl.sh` (`core` / `standard` / `universal`, `--mirror cn`, `--proxy`, `--backup-configs`, `--disable-automount`, `--restore-configs`), stock WSL config backup templates (`packages/bootstrap/templates/`), `dsh-wsl-doctor` live kernel & 22-tool Codex matrix CLI, and `install-dsh-plugin.ps1`. |

---

## Quick Start (Windows 10/11 + WSL 2)

See [`INSTALL.zh.md`](./INSTALL.zh.md) for the complete beginner-friendly walkthrough, WSL backup/restore commands, and **npm** publishing steps.

```bash
# 1. Inside WSL 2 (auto-backs up original /etc/wsl.conf & /etc/fstab before installing prebuilt binaries):
bash packages/bootstrap/provision-wsl.sh --profile standard --mirror cn
node dist/packages/bootstrap/src/doctor.js
```

```powershell
# 2. On Windows PowerShell (auto-backs up %USERPROFILE%\.wslconfig and registers plugin):
.\packages\bootstrap\install-dsh-plugin.ps1 -Distro Ubuntu-24.04 -WorkspaceRoot /home/<user>/workspace -UpsertAgentsMd
dsh plugin --profile web add .\dsh-wsl-sandbox-0.1.0.tgz
```

---

## Development & Verification

```bash
# Build all TypeScript packages & native DSH browser client.js
npm run build

# Run full automated test suite (unit + real Linux kernel sandbox + Top-27 DSH plugin coexistence)
npm test

# Live kernel isolation & 22-tool diagnostic
npm run doctor
```
