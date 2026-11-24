#!/usr/bin/env bash
# dsh-wsl-sandbox — Laptop-Friendly, Zero-Docker, Zero-Kernel-Build WSL 2 Provisioner
#
# Installs Codex-aligned prebuilt binary toolchains into an Ubuntu/Debian WSL 2 distro
# in small, idempotent, resumable steps. NEVER builds Docker images, NEVER compiles
# Linux kernels, NEVER compiles Python from source (uses Astral `uv` instead of pyenv),
# and NEVER edits /etc/wsl.conf or /etc/fstab.
#
# Usage:
#   bash provision-wsl.sh --profile standard [--mirror cn|global] [--proxy http://127.0.0.1:7890] [--step all|base|cli|node|python|go-rust|extra] [--dry-run]

set -euo pipefail

PROFILE="standard"
MIRROR="global"
PROXY=""
STEP="all"
DRY_RUN="false"

usage() {
  cat <<'EOF'
Usage: provision-wsl.sh [options]
  --profile core|standard|universal   Toolchain profile (default: standard)
  --mirror  global|cn                 Use global upstream or China mirrors (default: global)
  --proxy   <url>                     Optional HTTP/SOCKS5 upstream proxy (e.g. http://127.0.0.1:7890)
  --step    all|base|cli|node|python|go-rust|extra
                                      Run one idempotent step or all steps (default: all)
  --dry-run                           Print planned commands without modifying the system
  -h, --help                          Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE="${2:?Missing value for --profile}"; shift 2 ;;
    --mirror)  MIRROR="${2:?Missing value for --mirror}"; shift 2 ;;
    --proxy)   PROXY="${2:?Missing value for --proxy}"; shift 2 ;;
    --step)    STEP="${2:?Missing value for --step}"; shift 2 ;;
    --dry-run) DRY_RUN="true"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[ERROR] Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

case "$PROFILE" in
  core|standard|universal) ;;
  *) echo "[ERROR] Invalid --profile '$PROFILE' (expected core|standard|universal)" >&2; exit 2 ;;
esac

case "$MIRROR" in
  global|cn) ;;
  *) echo "[ERROR] Invalid --mirror '$MIRROR' (expected global|cn)" >&2; exit 2 ;;
esac

case "$STEP" in
  all|base|cli|node|python|go-rust|extra) ;;
  *) echo "[ERROR] Invalid --step '$STEP'" >&2; exit 2 ;;
esac

if [[ "$(id -u)" -eq 0 ]]; then
  echo "[ERROR] Do not run provision-wsl.sh as root (UID 0). Run as your non-root WSL user (sudo will be invoked only for apt)." >&2
  exit 1
fi

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  GO_ARCH="amd64" ;;
  aarch64) GO_ARCH="arm64" ;;
  *) echo "[ERROR] Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

if [[ -n "$PROXY" ]]; then
  export HTTP_PROXY="$PROXY"
  export HTTPS_PROXY="$PROXY"
  export http_proxy="$PROXY"
  export https_proxy="$PROXY"
  export ALL_PROXY="$PROXY"
  echo "[info] Using upstream proxy: $PROXY"
fi

run_cmd() {
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] $*"
  else
    "$@"
  fi
}

apt_install() {
  run_cmd sudo env DEBIAN_FRONTEND=noninteractive \
    ${HTTP_PROXY:+http_proxy="$HTTP_PROXY"} \
    ${HTTPS_PROXY:+https_proxy="$HTTPS_PROXY"} \
    apt-get install -y --no-install-recommends "$@"
}

apt_update() {
  run_cmd sudo env DEBIAN_FRONTEND=noninteractive \
    ${HTTP_PROXY:+http_proxy="$HTTP_PROXY"} \
    ${HTTPS_PROXY:+https_proxy="$HTTPS_PROXY"} \
    apt-get update -y
}

write_mirror_env() {
  local env_file="$HOME/.dsh-wsl-env.sh"
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] Write $env_file (mirror=$MIRROR)"
    return 0
  fi

  cat > "$env_file" <<EOF
# Managed by dsh-wsl-sandbox provision-wsl.sh (mirror=${MIRROR})
export PATH="\$HOME/.local/bin:\$HOME/.cargo/bin:\$HOME/.bun/bin:/usr/local/go/bin:\$PATH"
EOF

  if [[ "$MIRROR" == "cn" ]]; then
    cat >> "$env_file" <<'EOF'
export UV_INDEX_URL="https://pypi.tuna.tsinghua.edu.cn/simple"
export PIP_INDEX_URL="https://pypi.tuna.tsinghua.edu.cn/simple"
export NPM_CONFIG_REGISTRY="https://registry.npmmirror.com"
export GOPROXY="https://goproxy.cn,direct"
export RUSTUP_DIST_SERVER="https://rsproxy.cn"
export RUSTUP_UPDATE_ROOT="https://rsproxy.cn/rustup"
EOF
  fi

  local rc
  for rc in "$HOME/.bashrc" "$HOME/.profile"; do
    touch "$rc"
    if ! grep -Fq '.dsh-wsl-env.sh' "$rc"; then
      printf '\n[ -f "$HOME/.dsh-wsl-env.sh" ] && . "$HOME/.dsh-wsl-env.sh"\n' >> "$rc"
    fi
  done

  # shellcheck disable=SC1090
  . "$env_file"
}

configure_apt_cn_mirror() {
  if [[ "$MIRROR" != "cn" ]]; then
    return 0
  fi
  echo "[step:base] Configuring Tsinghua TUNA APT mirror (with .bak backup)..."
  if [[ -f /etc/apt/sources.list.d/ubuntu.sources ]]; then
    if [[ ! -f /etc/apt/sources.list.d/ubuntu.sources.bak ]]; then
      run_cmd sudo cp /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list.d/ubuntu.sources.bak
    fi
    run_cmd sudo sed -i -E 's|https?://(archive|security|ports)\.ubuntu\.com/ubuntu|https://mirrors.tuna.tsinghua.edu.cn/ubuntu|g' \
      /etc/apt/sources.list.d/ubuntu.sources
  elif [[ -f /etc/apt/sources.list ]]; then
    if [[ ! -f /etc/apt/sources.list.bak ]]; then
      run_cmd sudo cp /etc/apt/sources.list /etc/apt/sources.list.bak
    fi
    run_cmd sudo sed -i -E 's|https?://(archive|security|ports)\.ubuntu\.com/ubuntu|https://mirrors.tuna.tsinghua.edu.cn/ubuntu|g' \
      /etc/apt/sources.list
  fi
}

step_base() {
  echo "=== [step:base] Installing mandatory sandbox primitives (bwrap, prlimit, socat) ==="
  write_mirror_env
  configure_apt_cn_mirror
  apt_update
  apt_install bubblewrap util-linux bash ca-certificates socat procps curl wget gnupg lsb-release
}

step_cli() {
  echo "=== [step:cli] Installing Codex high-frequency CLI & C/C++ build headers ==="
  apt_update
  apt_install \
    git git-lfs ripgrep fd-find jq rsync zip unzip xz-utils sqlite3 \
    openssh-client dnsutils iputils-ping netcat-openbsd inotify-tools \
    moreutils universal-ctags gawk tree file patch \
    build-essential pkg-config cmake ninja-build \
    libssl-dev zlib1g-dev libffi-dev libsqlite3-dev

  if command -v fdfind >/dev/null 2>&1 && ! command -v fd >/dev/null 2>&1; then
    run_cmd mkdir -p "$HOME/.local/bin"
    run_cmd ln -sf "$(command -v fdfind)" "$HOME/.local/bin/fd"
  fi

  if [[ "$PROFILE" == "standard" || "$PROFILE" == "universal" ]]; then
    apt_install ccache protobuf-compiler libpq-dev libxml2-dev
  fi

  if [[ "$PROFILE" == "universal" ]]; then
    # Prebuilt apt LLVM/clang packages only — zero source builds
    apt_install clang clang-format clang-tidy
  fi
}

step_node() {
  echo "=== [step:node] Installing prebuilt Node.js 22 LTS + pnpm/yarn/bun/mise ==="
  write_mirror_env

  local need_node="true"
  if command -v node >/dev/null 2>&1; then
    local major
    major="$(node -v | sed -E 's/^v([0-9]+).*/\1/')"
    if [[ "$major" -ge 22 ]]; then
      echo "[step:node] Node $(node -v) already >= 22, skipping Node install."
      need_node="false"
    fi
  fi

  if [[ "$need_node" == "true" ]]; then
    if [[ "$DRY_RUN" == "true" ]]; then
      echo "[dry-run] Install Node.js 22 LTS via NodeSource apt repository"
    else
      curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
      apt_install nodejs
    fi
  fi

  if [[ "$PROFILE" == "standard" || "$PROFILE" == "universal" ]]; then
    if command -v corepack >/dev/null 2>&1; then
      run_cmd sudo corepack enable || true
    fi
    if ! command -v pnpm >/dev/null 2>&1; then
      run_cmd npm install -g pnpm typescript eslint prettier
    fi
    if ! command -v bun >/dev/null 2>&1; then
      if [[ "$DRY_RUN" == "true" ]]; then
        echo "[dry-run] Install prebuilt bun binary via https://bun.sh/install"
      else
        curl -fsSL https://bun.sh/install | bash
      fi
    fi
    if ! command -v mise >/dev/null 2>&1; then
      if [[ "$DRY_RUN" == "true" ]]; then
        echo "[dry-run] Install prebuilt mise binary via https://mise.run"
      else
        curl -fsSL https://mise.run | sh
      fi
    fi
  fi
}

step_python() {
  echo "=== [step:python] Installing Python 3 + Astral uv (binary-only, NO pyenv source compilation) ==="
  write_mirror_env
  apt_install python3 python3-venv python3-pip

  if [[ "$PROFILE" == "standard" || "$PROFILE" == "universal" ]]; then
    if ! command -v uv >/dev/null 2>&1; then
      if [[ "$DRY_RUN" == "true" ]]; then
        echo "[dry-run] Install prebuilt Astral uv binary"
      else
        curl -LsSf https://astral.sh/uv/install.sh | sh
      fi
    fi
    export PATH="$HOME/.local/bin:$PATH"
    local tools=(pytest ruff mypy pyright black)
    if [[ "$PROFILE" == "universal" ]]; then
      tools+=(poetry isort)
    fi
    local t
    for t in "${tools[@]}"; do
      if ! command -v "$t" >/dev/null 2>&1; then
        run_cmd uv tool install "$t"
      else
        echo "[step:python] $t already installed."
      fi
    done
  fi
}

step_go_rust() {
  if [[ "$PROFILE" == "core" ]]; then
    echo "=== [step:go-rust] Skipped for 'core' profile ==="
    return 0
  fi
  echo "=== [step:go-rust] Installing prebuilt Go tarball + Rust minimal toolchain ==="
  write_mirror_env

  if ! command -v go >/dev/null 2>&1; then
    local go_ver="1.23.6"
    local go_base="https://go.dev/dl"
    if [[ "$MIRROR" == "cn" ]]; then
      go_base="https://golang.google.cn/dl"
    fi
    local tarball="go${go_ver}.linux-${GO_ARCH}.tar.gz"
    if [[ "$DRY_RUN" == "true" ]]; then
      echo "[dry-run] Download ${go_base}/${tarball} and extract into /usr/local/go"
    else
      curl -fsSL "${go_base}/${tarball}" -o "/tmp/${tarball}"
      sudo rm -rf /usr/local/go
      sudo tar -C /usr/local -xzf "/tmp/${tarball}"
      rm -f "/tmp/${tarball}"
    fi
  else
    echo "[step:go-rust] Go already installed: $(go version)"
  fi

  if ! command -v rustc >/dev/null 2>&1; then
    if [[ "$DRY_RUN" == "true" ]]; then
      echo "[dry-run] Install Rust minimal profile via rustup (--profile minimal + rustfmt + clippy)"
    else
      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --component rustfmt,clippy
    fi
  else
    echo "[step:go-rust] Rust already installed: $(rustc --version)"
  fi
}

step_extra() {
  if [[ "$PROFILE" != "universal" ]]; then
    echo "=== [step:extra] Skipped for '${PROFILE}' profile (universal only) ==="
    return 0
  fi
  echo "=== [step:extra] Installing prebuilt OpenJDK 21, Maven, Ruby, PHP CLI ==="
  apt_update
  apt_install openjdk-21-jdk-headless maven ruby php-cli composer
}

echo "[dsh-wsl-sandbox] Provisioning profile=${PROFILE} mirror=${MIRROR} step=${STEP} arch=${ARCH}"

case "$STEP" in
  base)    step_base ;;
  cli)     step_cli ;;
  node)    step_node ;;
  python)  step_python ;;
  go-rust) step_go_rust ;;
  extra)   step_extra ;;
  all)
    step_base
    step_cli
    step_node
    step_python
    step_go_rust
    step_extra
    ;;
esac

echo "[dsh-wsl-sandbox] Step '${STEP}' finished cleanly. Next: run 'dsh-wsl-doctor' to verify kernel isolation & tool matrix."
