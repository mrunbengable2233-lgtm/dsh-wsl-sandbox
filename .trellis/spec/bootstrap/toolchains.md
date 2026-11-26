# `packages/bootstrap` — Agent-Guided Zero-Build WSL 2 Provisioning & Doctor Contracts

## 1. Core Strategy (Q18: Laptop-Friendly, Zero Docker / Zero Kernel Build)
Instead of building multi-GB Docker images or compiling Linux kernels locally on a laptop:
1. **Distro Acquisition (Official Prebuilt Only)**:
   - Either reuse an existing WSL 2 Ubuntu 22.04/24.04 or Debian distro, OR install an official clean distro via `wsl.exe --install -d Ubuntu-24.04` (or `wsl.exe --install Ubuntu-24.04 --name dsh-sandbox` on WSL 2.4+ — zero Docker, ~300MB official Microsoft rootfs).
2. **Agent-Guided Step-by-Step Provisioning (`dsh-wsl-env-setup` Skill + Prompt Injection)**:
   - Ships a dedicated **Setup Skill & Prompt** (`.agents/skills/dsh-wsl-env-setup/SKILL.md` + `packages/bootstrap/prompts/wsl-env-setup.md`).
   - During initial environment setup, the user invokes the Agent with this Skill/Prompt; the Agent runs **read-only probes first** (`wsl -l -v`, `dsh-wsl-doctor --json`), checks proxy & China mirror preference, asks the user to choose profile (`core` / `standard` / `universal`), and executes **small, idempotent, resumable install steps** (each individually visible and confirmable by the user), finishing with `dsh-wsl-doctor` verification!
   - **Prebuilt binaries only** (`apt`, official Go tarball, `rustup` binary, `uv` binary, NodeSource/mise prebuilt Node 22) — **NEVER** compiles Python from source via `pyenv` or compiles kernels/LLVM on the user's laptop!
3. **Optional Direct CLI Fallback (`provision-wsl.sh`)**:
   - The exact same idempotent steps are packaged in `packages/bootstrap/provision-wsl.sh --profile core|standard|universal [--mirror cn] [--proxy http://...] [--step base|cli|python|node|go|rust|extra]` so either the Agent or the user can run single steps or the full profile cleanly.

## 2. Three Selectable Profiles (Aligned with `openai/codex-universal`, Binary-Only Fast Install)

| Layer | `core` (~350MB, ~2 min) | `standard` (~1.2GB, recommended) | `universal` (~3.5GB, binary-only) |
| :--- | :--- | :--- | :--- |
| **Sandbox Base (Mandatory)** | `bubblewrap` (`bwrap`), `util-linux` (`prlimit`, `findmnt`), `bash`, `ca-certificates`, `socat`, `procps` | `core` | `standard` |
| **Codex High-Freq CLI** | `git`, `git-lfs`, `ripgrep` (`rg`), `fd-find` (`fd` symlink), `jq`, `curl`, `wget`, `rsync`, `zip`, `unzip`, `xz-utils`, `sqlite3`, `openssh-client`, `gnupg`, `dnsutils`, `iputils-ping`, `netcat-openbsd`, `inotify-tools`, `moreutils`, `universal-ctags`, `gawk`, `tree`, `file`, `patch` | `core` | `standard` |
| **C/C++ Build** | `build-essential`, `pkg-config`, `cmake`, `ninja-build`, `libssl-dev`, `zlib1g-dev`, `libffi-dev`, `libsqlite3-dev` | `core` + `ccache`, `protobuf-compiler`, `libpq-dev`, `libxml2-dev` | `standard` + `clang`, `clang-format`, `clang-tidy` (apt prebuilt, NO source build), `bazelisk` |
| **Version Manager** | — | `mise` (apt/prebuilt binary) | `mise` |
| **Python (Binary-Only, NO pyenv compile!)** | System `python3` (3.12) + `python3-venv` | `core` + **`uv`** (handles fast prebuilt multi-Python downloads when needed!), `pytest`, `ruff`, `mypy`, `pyright`, `black` (installed via `uv tool install`) | `standard` + `poetry`, `isort` |
| **Node / TS** | Node.js 22 LTS (prebuilt binary via NodeSource or `mise`) | Node 22 + `pnpm`, `yarn` (corepack), `bun`, `typescript`, `eslint`, `prettier` | Node 20/22/24 prebuilt via `mise` + full tools |
| **Go / Rust** | — | Prebuilt Go latest + `golangci-lint`; prebuilt Rust stable (`rustup --profile minimal` + `rustfmt` + `clippy`) | `standard` |
| **Extended (Prebuilt Only)** | — | — | OpenJDK 21 (`openjdk-21-jdk-headless`) + `maven` + `gradle`, `ruby`, `php-cli` + `composer` |

> **Why `uv` instead of `pyenv` source compilation?** OpenAI's `codex-universal` Dockerfile compiles 5 Python versions from source with `pyenv install` (taking 20+ minutes and heavy CPU/RAM). Using Astral's **`uv`** gives instant prebuilt standalone Python binaries in seconds — ideal for laptops!

## 3. China Network Adaptation (`--mirror cn` & `--proxy`)
- **APT**: `https://mirrors.tuna.tsinghua.edu.cn/ubuntu` (Ubuntu 24.04 DEB822 `/etc/apt/sources.list.d/ubuntu.sources` with `.bak` backup before editing, or legacy `sources.list`).
- **npm / pnpm**: `https://registry.npmmirror.com`
- **PyPI / uv / pip**: `https://pypi.tuna.tsinghua.edu.cn/simple` (`UV_INDEX_URL`, `PIP_INDEX_URL`) + `UV_PYTHON_INSTALL_MIRROR` option
- **Go**: `GOPROXY=https://goproxy.cn,direct`
- **Rust / rustup**: `RUSTUP_DIST_SERVER=https://rsproxy.cn`, `RUSTUP_UPDATE_ROOT=https://rsproxy.cn/rustup`
- **Proxy**: optional `--proxy http://host:port` (auto-detects WSL NAT host IP or `127.0.0.1` in `mirrored` mode when asked by the setup Agent).

## 4. `dsh-wsl-doctor` Diagnostic Contract
Structured JSON + human-readable report:
1. `os`: `{ platform, arch, kernel, isWsl2 }`
2. `user`: `{ uid, username, nonRoot }` (blocks if `uid === 0`)
3. `sandbox`: `{ bwrapPath, bwrapVersion, unprivilegedUserns, disableUsernsFlag, seccompIoUringBlocked, seccompAfVsockBlocked, escapeMaskSelfTest }`
4. `tools`: Codex matrix check (`bwrap`, `prlimit`, `socat`, `bash`, `git`, `rg`, `fd`/`fdfind`, `jq`, `curl`, `python3`, `uv`, `pytest`, `ruff`, `node`, `pnpm`, `bun`, `gcc`, `cmake`, `go`, `rustc`, `cargo`, `mise`)
5. `network`: optional upstream proxy reachability check
6. `verdict`: `'ready' | 'degraded' | 'blocked'` + exact actionable remediation steps (directly consumable by the `dsh-wsl-env-setup` Agent!).
