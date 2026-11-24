---
name: dsh-wsl-env-setup
description: "Laptop-friendly, zero-Docker, zero-kernel-build Agent workflow to provision and verify a WSL 2 sandbox environment for DeepSeek Harness (dsh-wsl-sandbox). Probes existing WSL 2 distros, guides the user through choosing a Codex-aligned profile (core/standard/universal) plus China mirrors or upstream proxy, runs small idempotent binary-only setup steps under human approval, and verifies with dsh-wsl-doctor. Use when initializing, repairing, or upgrading the WSL 2 sandbox environment."
---

# DSH WSL 2 Sandbox Environment Setup (Agent-Guided, Zero-Docker / Zero-Kernel-Build)

> **Purpose**: Provision a Codex-grade WSL 2 sandbox distro on a Windows laptop **without Docker Desktop image builds and without compiling kernels or toolchains from source**. Every privileged or mutating step is small, idempotent, resumable, and explicitly approved by the user.

## Non-Negotiable Safety Rules

1. **NEVER build Docker images or compile Linux kernels / Python-from-source (`pyenv`)** on the user's laptop. Use official prebuilt WSL 2 distros and prebuilt binaries (`apt`, NodeSource/`mise`, Astral `uv`, official Go tarball, `rustup --profile minimal`) only.
2. **NEVER silently edit `/etc/wsl.conf`, `/etc/fstab`, or `%USERPROFILE%\.wslconfig`**. Only inspect them read-only and print advisory notices if suboptimal (e.g., WSL 1 detected).
3. **NEVER use `root` as the runtime sandbox user**. Verify a non-root UID (`uid > 0`) exists and is configured as the default WSL user.
4. **Ask once before installing**: Always run Phase 1 read-only probes first, present the exact plan (distro, profile, mirror/proxy, estimated disk footprint), and wait for user confirmation before running any install command.

## Phase 1: Read-Only Discovery (No Changes)

1. Enumerate installed WSL distros & versions (exclude internal container distros like `docker-desktop`):
   ```powershell
   wsl.exe -l -v
   ```
2. Probe the target WSL 2 distro read-only:
   ```powershell
   wsl.exe -d <distro> -- sh -c 'id; uname -r; uname -m; command -v bwrap prlimit socat node python3 git rg fdfind fd jq uv go cargo mise || true'
   ```
3. Present options and confirm once with the user:
   - **Target distro**: reuse an existing WSL 2 Ubuntu/Debian distro, OR install a fresh official distro (`wsl.exe --install Ubuntu-24.04 --name dsh-sandbox` on WSL 2.4+, or `wsl.exe --install -d Ubuntu-24.04`).
   - **Profile tier**: `core` (~350MB) / `standard` (~1.2GB, recommended) / `universal` (~3.5GB, binary-only).
   - **China network acceleration**: `--mirror cn` (Tsinghua APT/PyPI, `npmmirror`, `goproxy.cn`, `rsproxy.cn`) and/or `--proxy http://<host>:<port>`.

## Phase 2: Step-by-Step Idempotent Provisioning (Under Human Approval)

Execute in clean, resumable stages via `provision-wsl.sh` (or explicit per-stage commands):
- **Step A (`base`)**: `bubblewrap`, `util-linux`, `socat`, Codex CLI tools (`git`, `git-lfs`, `rg`, `fd-find` + `/usr/local/bin/fd` symlink, `jq`, `sqlite3`, `rsync`, `zip`/`unzip`, `xz-utils`, `universal-ctags`, `inotify-tools`, `moreutils`, `gawk`, `tree`, `file`, `patch`), C/C++ base (`build-essential`, `pkg-config`, `cmake`, `ninja-build`, `libssl-dev`, `zlib1g-dev`, `libffi-dev`, `libsqlite3-dev`), `python3` + `python3-venv`.
- **Step B (`node`)**: Prebuilt Node 22 LTS (mandatory for `wsl-runner`); for `standard`/`universal`: `pnpm`, `yarn`, prebuilt `bun`, `typescript`, `eslint`, `prettier`.
- **Step C (`python`)**: Astral **`uv`** prebuilt binary + `uv tool install ruff pytest mypy pyright black` (`standard`/`universal`).
- **Step D (`go-rust`)**: Prebuilt Go tarball + `golangci-lint`, prebuilt Rust stable via `rustup --profile minimal --component rustfmt --component clippy` (`standard`/`universal`).
- **Step E (`extra`)**: `apt` prebuilt `clang`, `clang-format`, `clang-tidy`, `openjdk-21-jdk-headless`, `maven`, `gradle`, `ruby`, `php-cli`, `composer`, `bazelisk` (`universal` only).

```bash
bash packages/bootstrap/provision-wsl.sh --profile <core|standard|universal> [--mirror cn] [--proxy http://...]
```

## Phase 3: Mandatory Verification Gate (`dsh-wsl-doctor`)

```bash
node packages/bootstrap/src/doctor.ts --json
```

All hard gates MUST pass (`os.isWsl2`, `user.nonRoot`, `sandbox.unprivilegedUserns`, `sandbox.seccompIoUringBlocked`, `sandbox.seccompAfVsockBlocked`, `sandbox.escapeMaskSelfTest`). If Ubuntu 24.04 AppArmor blocks unprivileged userns, report the exact AppArmor `bwrap` profile remediation command for human approval — NEVER bypass confinement.
