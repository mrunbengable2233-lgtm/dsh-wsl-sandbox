---
name: dsh-wsl-env-setup
description: "Laptop-friendly, zero-Docker, zero-kernel-build Agent workflow to provision and verify a WSL 2 sandbox environment for DeepSeek Harness (dsh-wsl-sandbox). Dynamically probes existing WSL 2 distros (including Ubuntu 26.04/24.04, Debian, Fedora, Arch, and WSL Manager imported/moved VHDX instances), guides the user through choosing a Codex-aligned profile (core/standard/universal) plus China mirrors or upstream proxy, stages the runner into native ext4 (zero /mnt lock), runs small idempotent binary-only setup steps under human approval, and verifies with dsh-wsl-doctor. Use when initializing, repairing, or upgrading the WSL 2 sandbox environment."
---

# DSH WSL 2 Sandbox Environment Setup (Agent-Guided, Zero-Docker / Zero-Kernel-Build)

> **Purpose**: Provision a Codex-grade WSL 2 sandbox distro on a Windows laptop **without Docker Desktop image builds and without compiling kernels or toolchains from source**. Every privileged or mutating step is small, idempotent, resumable, and explicitly approved by the user.

## Non-Negotiable Safety Rules

1. **NEVER build Docker images or compile Linux kernels / Python-from-source (`pyenv`)** on the user's laptop. Support ANY modern WSL 2 distro (Ubuntu 26.04/24.04/22.04, Debian, Kali, Fedora, Arch, openSUSE, Alpine, or custom WSL Manager imported/moved VHDX instances) and install prebuilt binaries only (`apt`/`dnf`/`pacman`/`zypper`/`apk`, NodeSource/`mise`, Astral `uv`, official Go tarball, `golangci-lint`, `rustup --profile minimal`).
2. **NEVER silently edit `/etc/wsl.conf`, `/etc/fstab`, or `%USERPROFILE%\.wslconfig`**, and **NEVER recommend `wsl.exe --shutdown`**: Windows WSL Settings and WSL Manager share those exact config paths; keep backups read-only (`0400`/`+R`) in owner-only directories, and always target single distros with `wsl.exe --terminate <Distro>` so other WSL sessions are never killed.
3. **NEVER lock host Windows folders via `/mnt`**: Always pass `--cd ~` to `wsl.exe` and stage the runner + provisioner into native WSL ext4 (`$HOME/.local/share/dsh-wsl-sandbox/runner/`) via `node scripts/stage-wsl-runner.mjs --distro <Distro>`.
4. **NEVER use `root` as the runtime sandbox user**: Verify a non-root UID (`uid > 0`) is configured as the default WSL user.
5. **Ask once before installing**: Always run Phase 1 read-only probes first, present the exact plan (distro, profile, mirror/proxy, estimated disk footprint), and wait for user confirmation before running any install command.

## Phase 1: Read-Only Discovery (No Changes)

1. Enumerate installed WSL distros & custom moved VHDX paths (exclude internal container distros like `docker-desktop`):
   ```powershell
   wsl.exe -l -v
   Get-ChildItem HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss | ForEach-Object { Get-ItemProperty $_.PSPath | Select-Object DistributionName, BasePath, Version }
   ```
   > Even if a WSL Manager imported/moved distro does not appear in Windows Explorer's left "Linux" sidebar, it remains fully registered here and works cleanly over `wsl.exe --cd ~`.
2. Probe the target WSL 2 distro read-only:
   ```powershell
   wsl.exe -d <distro> --cd ~ -- sh -c 'id; head -n 3 /etc/os-release 2>/dev/null; uname -r; uname -m; command -v bwrap prlimit socat node python3 git rg fdfind fd jq uv go cargo mise || true'
   ```
3. Present options and confirm once with the user:
   - **Target distro**: reuse an existing WSL 2 distro (including WSL Manager moved instances), OR install a fresh official distro (`wsl.exe --install -d Ubuntu-26.04` [current Ubuntu default], or `Ubuntu-24.04`, `Debian`, `FedoraLinux-42`, `Arch`, `kali-linux`).
   - **Profile tier** (enforced across every step & persisted in `~/.config/dsh-wsl-sandbox/profile.json`):
     - `core` (~350MB, ~2 min): sandbox base + Codex CLI + C/C++ base + system `python3` + Node 22 LTS.
     - `standard` (~1.2GB, recommended): `core` + `ccache`/`protobuf`/`libpq`/`libxml2` + `mise` + `uv`/`pytest`/`ruff`/`mypy`/`pyright`/`black` + `pnpm`/`yarn`/`bun`/`typescript`/`eslint`/`prettier` + Go + `golangci-lint` + Rust minimal (`rustfmt`, `clippy`).
     - `universal` (~3.5GB, binary-only): `standard` + prebuilt `clang`/`clang-format`/`clang-tidy` + `bazelisk` + `mise` Node 20/22/24 + `poetry`/`isort` + OpenJDK 21 + `maven` + `gradle` + `ruby` + `php-cli` + `composer`.
   - **China network acceleration**: `--mirror cn` (Tsinghua APT/PyPI, `UV_PYTHON_INSTALL_MIRROR`, `npmmirror`, `goproxy.cn`, `rsproxy.cn`) and/or `--proxy http://<host>:<port>`.

## Phase 2: Native ext4 Staging & Step-by-Step Idempotent Provisioning

Stage into native WSL ext4 first (works even with `[automount] enabled = false` and moved WSL Manager instances):
```powershell
.\packages\bootstrap\install-dsh-plugin.ps1 -Distro <distro> -Profile <core|standard|universal> -Mirror <global|cn> -Provision
```
Or run individual resumable steps inside WSL (`--step all|base|cli|node|python|go|rust|go-rust|extra`):
```bash
bash ~/.local/share/dsh-wsl-sandbox/runner/packages/bootstrap/provision-wsl.sh \
  --profile <core|standard|universal> [--mirror cn] [--proxy http://...] [--step all|base|cli|node|python|go|rust|extra]
```

## Phase 3: Mandatory Verification Gate (`dsh-wsl-doctor`)

```bash
node ~/.local/share/dsh-wsl-sandbox/runner/dist/packages/bootstrap/src/doctor.js --strict-wsl2 --profile <core|standard|universal> --json
```

All hard gates MUST pass (`os.isWsl2`, `user.nonRoot`, `sandbox.unprivilegedUserns`, `sandbox.seccompIoUringBlocked`, `sandbox.seccompAfVsockBlocked`, `sandbox.escapeMaskSelfTest`, `sandbox.configMaskSelfTest`, `sandbox.configDirPermsOk`). If Ubuntu AppArmor blocks unprivileged userns, report the exact AppArmor `bwrap` profile remediation command for human approval — NEVER bypass confinement.
