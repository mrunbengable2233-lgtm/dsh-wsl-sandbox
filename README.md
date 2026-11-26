# `dsh-wsl-sandbox` — DeepSeek Harness (DSH) WSL 2 Execution Backend & OS Sandbox

Codex-grade Linux kernel sandbox (`bubblewrap` + pure-TypeScript `seccomp-bpf` + `prlimit` + UDS allowlist proxy), Single-Shell Purity & Dialect Guard, zero-token Bash & Windows PowerShell command/hardware/driver approval system, direct UI quick-controls for disabling full-drive mounts & mounting single directories, multi-distro & **WSL Manager** moved-VHDX auto-discovery, automatic read-only WSL config backup/restore, zero-leak process lifecycle, and **verified 100% coexistence with Top-27 DSH Marketplace & CLI plugins (including `dsh-purge`, `dshmarket`, `cc-safety-net`, `dsh-win-bash`, and `dsh-better-sidebar`)**.

- **简明中文安装、原始 WSL 配置备份还原与 npm 托管指南**：[`INSTALL.zh.md`](./INSTALL.zh.md)
- **Linux 内核隔离机制与安全审计交接白皮书（面向内核/系统工程师）**：[`docs/KERNEL-SECURITY-HANDOFF.zh.md`](./docs/KERNEL-SECURITY-HANDOFF.zh.md)
- **原始 WSL 配置参考备份模板**：[`packages/bootstrap/templates/`](./packages/bootstrap/templates/)

---

## Core Architecture

| Package | Responsibility |
| :--- | :--- |
| `packages/core` | Pure TypeScript (Node 22+ ESM, **zero npm runtime dependencies**, zero `node-gyp`): `SessionBinding`, Windows-to-WSL single-folder share normalization (`D:\Datasets\Project` -> `/mnt/d/Datasets/Project` -> `/shares/Project`) blocking live config/credential/VHDX paths, explicit USB/HID/CDC/video/serial device node validation, `EnvSanitizer`, Checklist B `dangerous-paths` + `.env*` depth-3 masking + `$HOME` config directory masking (`~/.dsh`, `~/.config/dsh-wsl-sandbox`, `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`, `~/.docker`), `x86_64`/`aarch64` `seccomp-bpf` compiler (`io_uring_*`, `AF_VSOCK`, `AF_PACKET`, `ptrace`, `mount`, `bpf`, `x32`), `bwrap-builder`, 8-layer `BashAstGuard` + POSIX dialect linter, `PwshGuard` (Single-Shell Purity + CMD/PS5.1/PS7 dialect + phone Bootloader/ADB/Fastboot/EDL & Windows driver/USB-NIC single-shot guard), concurrent `ApprovalController`, `UdsAllowlistProxy` (SSRF + DNS-rebinding defense + zero-hang socket teardown). |
| `packages/wsl-runner` | Persistent in-distro NDJSON RPC worker staged in native WSL ext4 (`~/.local/share/dsh-wsl-sandbox/runner/` — zero `/mnt` dependency, zero Windows NTFS lock): `probe`, `ConfinedFsService` (`O_NOFOLLOW` atomic writes), `ConfinedProcManager` (`bwrap --seccomp 3` + `prlimit` + session/terminal-scoped `-pgid` teardown + `/proc/<pid>/stat` PGID ownership verification + subshell-safe UDS bridge cleanup), `ConfinedTerminalManager` (`${sessionId}::${terminalId}` isolated CWD continuity), `wsl.backupConfigs` (`0400` read-only), and managed in-WSL `UdsAllowlistProxy` with lease watchdog & graceful `shutdown`. |
| `packages/dsh-plugin` | Native `@deepseek-ai/dsh@0.2.2-rc.5` Cordis plugin (`cordis.patch.yml` + browser `client.js` `settings.section` slot): dynamic multi-distro & WSL Manager `Lxss` registry discovery (`wsl-discovery.ts`), 7 additive `wsl_*` tools with `AbortController` cancellation, non-invasive `ctx.systemPrompt` routing (`order: 4200`, `interpolate: false`), monotonic `ctx.tools.guard` + `tools/pre-execute` host shell/driver guard, `ApprovalBridge`, owner-only `ConfigStore` (`0600` + Windows `icacls /inheritance:r`), and `/wsl-sandbox/api/*` + `/wsl-sandbox/ui`. |
| `packages/bootstrap` | Laptop-friendly, **zero-Docker**, **zero-kernel-build**, **zero-`pyenv`-compile** provisioning across Ubuntu 26.04/24.04/22.04, Debian, Kali, Fedora, Arch, openSUSE, and Alpine: `provision-wsl.sh` (strict `core` / `standard` / `universal` profiles persisted to `profile.json`, `--step base|cli|node|python|go|rust|go-rust|extra`, `--mirror cn`, `--proxy`, read-only backups, single-distro `--terminate` guidance), pure-JS `scripts/stage-wsl-runner.mjs` (native ext4 staging), profile-aware `dsh-wsl-doctor` (real kernel seccomp + config-masking + USBIP/driver diagnostics), and dynamic multi-distro `install-dsh-plugin.ps1`. |

---

## Quick Start (Windows 10/11 + WSL 2)

See [`INSTALL.zh.md`](./INSTALL.zh.md) for the complete beginner-friendly walkthrough, WSL Manager moved-VHDX compatibility, WSL backup/restore commands, and **npm** publishing steps.

```powershell
# 1. On Windows PowerShell: auto-discovers existing WSL 2 distros (including Ubuntu-26.04, Debian, Fedora, Arch,
#    and WSL Manager moved VHDX instances), lets you choose core/standard/universal profile, backs up original
#    .wslconfig & /etc/wsl.conf read-only, stages runner into native WSL ext4 (zero /mnt lock), and provisions WSL 2:
.\packages\bootstrap\install-dsh-plugin.ps1 -Provision -Profile standard -Mirror cn -UpsertAgentsMd

# 2. Register plugin into DSH (CLI/Web or Desktop):
dsh plugin --profile web add .\dsh-wsl-sandbox-0.1.0.tgz
dsh plugin --profile desktop add .\dsh-wsl-sandbox-0.1.0.tgz
```

---

## Development & Verification

```bash
# Build all TypeScript packages & native DSH browser client.js
npm run build

# Run full automated test suite (unit + real Linux kernel sandbox + multi-session isolation + leak checks + Top-27 coexistence)
npm test

# Live kernel isolation, config masking, USB driver & profile-aware toolchain diagnostic
npm run doctor -- --profile standard
```
