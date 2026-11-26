#!/usr/bin/env bash
# dsh-wsl-sandbox — Laptop-Friendly, Zero-Docker, Zero-Kernel-Build WSL 2 Provisioner
#
# Installs Codex-aligned prebuilt binary toolchains into any modern WSL 2 Linux distro
# (Ubuntu 26.04/24.04/22.04, Debian, Kali, Fedora, Arch, openSUSE, Alpine) in small,
# idempotent, resumable steps.
#
# Hard invariants:
# - ZERO Docker builds, ZERO kernel compilation, ZERO Python source compilation (uses Astral `uv`).
# - NEVER edits /etc/wsl.conf or /etc/fstab during normal provisioning (WSL Settings & WSL Manager
#   share those exact paths).
# - NEVER recommends `wsl.exe --shutdown` (which kills all other WSL terminals/distros); always
#   targets ONLY the current distro via `wsl.exe --terminate <Distro>`.
# - Locks private config directories to 0700 and backup snapshots to read-only 0400.
#
# Usage:
#   bash provision-wsl.sh --profile core|standard|universal [--mirror global|cn] \
#     [--proxy http://127.0.0.1:7890] [--step all|base|cli|node|python|go|rust|go-rust|extra] [--dry-run]

set -euo pipefail

PROFILE="standard"
MIRROR="global"
PROXY=""
STEP="all"
DRY_RUN="false"
ACTION="provision"
CUSTOM_BACKUP_DIR=""
OPEN_BACKUP_EXPLORER="false"

usage() {
  cat <<'EOF'
Usage: provision-wsl.sh [options]
  --profile core|standard|universal   Toolchain profile (default: standard)
                                        core      (~350MB): sandbox base + Codex CLI + C/C++ base + system python3 + Node 22
                                        standard  (~1.2GB): core + ccache/proto + mise + uv + pytest/ruff/mypy/pyright/black
                                                            + pnpm/yarn/bun/ts/eslint/prettier + Go + golangci-lint + Rust minimal
                                        universal (~3.5GB): standard + clang/bazelisk + mise Node 20/22/24 + poetry/isort
                                                            + OpenJDK 21 + maven + gradle + ruby + php-cli + composer
  --mirror  global|cn                 Use global upstream or China mirrors (default: global)
  --proxy   <url>                     Optional HTTP/SOCKS5 upstream proxy (e.g. http://127.0.0.1:7890)
  --step    all|base|cli|node|python|go|rust|go-rust|extra
                                      Run one idempotent step or all steps (default: all)
  --backup-configs                    Snapshot original /etc/wsl.conf, /etc/fstab & mounts (read-only 0400)
  --backup-dir <path>                 Custom backup directory (Linux path or Windows path like D:\Backups\WSL)
  --open-backup-dir                   Open the backup directory in native Windows Explorer
  --disable-automount                 Back up /etc/wsl.conf and set [automount] enabled = false
                                      (Note: shared with WSL Settings & WSL Manager; apply via `wsl.exe --terminate <Distro>`)
  --restore-configs                   Restore original /etc/wsl.conf & package mirror sources from backup
  --dry-run                           Print planned profile commands without modifying the system
  -h, --help                          Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE="${2:?Missing value for --profile}"; shift 2 ;;
    --mirror)  MIRROR="${2:?Missing value for --mirror}"; shift 2 ;;
    --proxy)   PROXY="${2:?Missing value for --proxy}"; shift 2 ;;
    --step)    STEP="${2:?Missing value for --step}"; shift 2 ;;
    --backup-configs)    ACTION="backup"; shift ;;
    --backup-dir)        CUSTOM_BACKUP_DIR="${2:?Missing value for --backup-dir}"; shift 2 ;;
    --open-backup-dir)   OPEN_BACKUP_EXPLORER="true"; shift ;;
    --disable-automount) ACTION="disable-automount"; shift ;;
    --restore-configs)   ACTION="restore"; shift ;;
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
  all|base|cli|node|python|go|rust|go-rust|extra) ;;
  *) echo "[ERROR] Invalid --step '$STEP' (expected all|base|cli|node|python|go|rust|go-rust|extra)" >&2; exit 2 ;;
esac

if [[ "$(id -u)" -eq 0 ]]; then
  echo "[ERROR] Do not run provision-wsl.sh as root (UID 0). Run as your non-root WSL user (sudo is invoked only for package installs)." >&2
  exit 1
fi

# Detect Linux distribution & package manager dynamically (supports Ubuntu 26.04/24.04/22.04, Debian, Fedora, Arch, openSUSE, Alpine)
DISTRO_ID="linux"
DISTRO_LIKE=""
DISTRO_PRETTY="Linux"
if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  DISTRO_ID="${ID:-linux}"
  DISTRO_LIKE="${ID_LIKE:-}"
  DISTRO_PRETTY="${PRETTY_NAME:-$DISTRO_ID}"
fi

PKG_MGR="unknown"
if command -v apt-get >/dev/null 2>&1; then
  PKG_MGR="apt"
elif command -v dnf >/dev/null 2>&1; then
  PKG_MGR="dnf"
elif command -v pacman >/dev/null 2>&1; then
  PKG_MGR="pacman"
elif command -v zypper >/dev/null 2>&1; then
  PKG_MGR="zypper"
elif command -v apk >/dev/null 2>&1; then
  PKG_MGR="apk"
fi

CURRENT_WSL_DISTRO="${WSL_DISTRO_NAME:-<YourDistro>}"

CONFIG_ROOT="$HOME/.config/dsh-wsl-sandbox"
BACKUP_DIR="$CONFIG_ROOT/backups"
if [[ -n "$CUSTOM_BACKUP_DIR" ]]; then
  if [[ "$CUSTOM_BACKUP_DIR" =~ ^([A-Za-z]):[\\/](.*)$ ]]; then
    DRV="$(echo "${BASH_REMATCH[1]}" | tr '[:upper:]' '[:lower:]')"
    REST="$(echo "${BASH_REMATCH[2]}" | tr '\\' '/')"
    BACKUP_DIR="/mnt/${DRV}/${REST%/}"
  else
    BACKUP_DIR="${CUSTOM_BACKUP_DIR%/}"
  fi
fi

validate_backup_dir() {
  local target="$1"
  local norm="${target%/}"
  case "$norm" in
    ""|"/"|"/etc"|"/root"|"$HOME"|"$HOME/.dsh"|"$HOME/.ssh"|"$HOME/.gnupg"|"$HOME/.aws"|"$HOME/.kube"|"$CONFIG_ROOT")
      echo "[ERROR] Refusing to use sensitive/live configuration directory as backup dir: '$target'" >&2
      exit 2
      ;;
  esac
  if [[ "$norm" == */.dsh || "$norm" == */.ssh || "$norm" == */.gnupg || "$norm" == */AppData/Local/Packages* || "$norm" == */AppData/Local/wsl* ]]; then
    echo "[ERROR] Refusing to write backups into a live credential or WSL VHDX storage directory: '$target'" >&2
    exit 2
  fi
}
validate_backup_dir "$BACKUP_DIR"

save_readonly_file() {
  local src="$1"
  local dest="$2"
  if [[ -f "$dest" ]]; then
    chmod u+w "$dest" 2>/dev/null || true
  fi
  cp "$src" "$dest"
  chmod 400 "$dest"
}

write_readonly_text() {
  local dest="$1"
  local text="$2"
  if [[ -f "$dest" ]]; then
    chmod u+w "$dest" 2>/dev/null || true
  fi
  printf '%s\n' "$text" > "$dest"
  chmod 400 "$dest"
}

backup_original_wsl_configs() {
  local ts
  ts="$(date +%Y%m%d-%H%M%S)"
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] mkdir -p -m 700 $BACKUP_DIR && snapshot /etc/wsl.conf, /etc/fstab, /proc/mounts (read-only 0400)"
    return 0
  fi
  mkdir -p "$CONFIG_ROOT"
  chmod 700 "$CONFIG_ROOT"
  mkdir -p "$BACKUP_DIR"
  chmod 700 "$BACKUP_DIR"

  if [[ -f /etc/wsl.conf ]]; then
    if [[ ! -f "$BACKUP_DIR/wsl.conf.orig" && ! -f "$BACKUP_DIR/wsl.conf.orig.absent" ]]; then
      save_readonly_file /etc/wsl.conf "$BACKUP_DIR/wsl.conf.orig"
      echo "[backup] Saved pristine read-only /etc/wsl.conf -> $BACKUP_DIR/wsl.conf.orig"
    fi
    save_readonly_file /etc/wsl.conf "$BACKUP_DIR/wsl.conf.${ts}.bak"
  else
    if [[ ! -f "$BACKUP_DIR/wsl.conf.orig" && ! -f "$BACKUP_DIR/wsl.conf.orig.absent" ]]; then
      write_readonly_text "$BACKUP_DIR/wsl.conf.orig.absent" "# /etc/wsl.conf did not exist prior to dsh-wsl-sandbox setup (${ts})"
      echo "[backup] Recorded pristine state (no /etc/wsl.conf) -> $BACKUP_DIR/wsl.conf.orig.absent"
    fi
  fi

  if [[ -f /etc/fstab ]]; then
    [[ ! -f "$BACKUP_DIR/fstab.orig" ]] && save_readonly_file /etc/fstab "$BACKUP_DIR/fstab.orig"
    save_readonly_file /etc/fstab "$BACKUP_DIR/fstab.${ts}.bak"
  fi

  if [[ -r /proc/mounts ]]; then
    local mount_tmp
    mount_tmp="$(mktemp)"
    grep -E 'drvfs|9p|/mnt/' /proc/mounts > "$mount_tmp" 2>/dev/null || true
    save_readonly_file "$mount_tmp" "$BACKUP_DIR/drvfs-mounts.${ts}.txt"
    [[ ! -f "$BACKUP_DIR/drvfs-mounts.orig.txt" ]] && save_readonly_file "$mount_tmp" "$BACKUP_DIR/drvfs-mounts.orig.txt"
    rm -f "$mount_tmp"
  fi
}

disable_wsl_automount() {
  backup_original_wsl_configs
  echo "=== [wsl.conf] Disabling OS-level Windows full-drive automount ([automount] enabled = false) ==="
  echo "[note] /etc/wsl.conf is shared with Windows WSL Settings and WSL Manager. Original backed up read-only under $BACKUP_DIR."
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] Write [automount] enabled = false to /etc/wsl.conf"
    echo "[dry-run] Next: run 'wsl.exe --terminate ${CURRENT_WSL_DISTRO}' in Windows PowerShell (do NOT use --shutdown)"
    return 0
  fi
  local tmp_conf
  tmp_conf="$(mktemp)"
  if [[ -f /etc/wsl.conf ]]; then
    awk '
      BEGIN { in_auto=0; wrote_auto=0 }
      /^\[automount\]/ {
        print "[automount]"
        print "enabled = false"
        print "mountFsTab = false"
        in_auto=1; wrote_auto=1; next
      }
      /^\[/ { in_auto=0 }
      in_auto && /^[[:space:]]*(enabled|mountFsTab)[[:space:]]*=/ { next }
      { print }
      END {
        if (!wrote_auto) {
          print ""
          print "[automount]"
          print "enabled = false"
          print "mountFsTab = false"
        }
      }
    ' /etc/wsl.conf > "$tmp_conf"
  else
    cat > "$tmp_conf" <<'EOF'
[boot]
systemd = true

[automount]
enabled = false
mountFsTab = false
EOF
  fi
  sudo cp "$tmp_conf" /etc/wsl.conf
  sudo chmod 644 /etc/wsl.conf
  rm -f "$tmp_conf"
  echo "[ok] Updated /etc/wsl.conf ([automount] enabled = false). Original backed up under $BACKUP_DIR."
  echo "[next] Run ONLY 'wsl.exe --terminate ${CURRENT_WSL_DISTRO}' in Windows PowerShell to apply to this distro without killing other WSL distros."
}

restore_original_wsl_configs() {
  echo "=== [restore] Restoring original WSL configuration from $BACKUP_DIR ==="
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] Restore /etc/wsl.conf and package mirror sources from $BACKUP_DIR"
    return 0
  fi
  if [[ -f "$BACKUP_DIR/wsl.conf.orig" ]]; then
    sudo cp "$BACKUP_DIR/wsl.conf.orig" /etc/wsl.conf
    sudo chmod 644 /etc/wsl.conf
    echo "[ok] Restored /etc/wsl.conf from $BACKUP_DIR/wsl.conf.orig"
  elif [[ -f "$BACKUP_DIR/wsl.conf.orig.absent" ]]; then
    sudo rm -f /etc/wsl.conf
    echo "[ok] Removed /etc/wsl.conf (system originally had no /etc/wsl.conf)"
  else
    echo "[warn] No backup marker found in $BACKUP_DIR; /etc/wsl.conf left untouched."
  fi

  local src
  for src in /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list.d/debian.sources /etc/apt/sources.list; do
    if [[ -f "${src}.bak" ]]; then
      sudo cp "${src}.bak" "$src"
      echo "[ok] Restored $src from ${src}.bak"
    fi
  done
  echo "[next] Run 'wsl.exe --terminate ${CURRENT_WSL_DISTRO}' in Windows PowerShell if /etc/wsl.conf was changed (avoids killing other distros)."
}

if [[ "$ACTION" == "backup" ]]; then
  backup_original_wsl_configs
  echo "[ok] Original WSL configuration snapshot saved (read-only 0400) under: $BACKUP_DIR"
  ls -la "$BACKUP_DIR" || true
  if [[ "$OPEN_BACKUP_EXPLORER" == "true" ]] && command -v wslpath >/dev/null 2>&1 && command -v explorer.exe >/dev/null 2>&1; then
    explorer.exe "$(wslpath -w "$BACKUP_DIR")" || true
  fi
  exit 0
elif [[ "$ACTION" == "disable-automount" ]]; then
  disable_wsl_automount
  exit 0
elif [[ "$ACTION" == "restore" ]]; then
  restore_original_wsl_configs
  exit 0
fi

# Always snapshot original WSL configs non-destructively before provisioning
backup_original_wsl_configs

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

pkg_update() {
  case "$PKG_MGR" in
    apt)
      run_cmd sudo env DEBIAN_FRONTEND=noninteractive \
        ${HTTP_PROXY:+http_proxy="$HTTP_PROXY"} \
        ${HTTPS_PROXY:+https_proxy="$HTTPS_PROXY"} \
        apt-get update -y
      ;;
    dnf)
      run_cmd sudo env ${HTTP_PROXY:+http_proxy="$HTTP_PROXY"} ${HTTPS_PROXY:+https_proxy="$HTTPS_PROXY"} \
        dnf makecache -y
      ;;
    pacman)
      run_cmd sudo env ${HTTP_PROXY:+http_proxy="$HTTP_PROXY"} ${HTTPS_PROXY:+https_proxy="$HTTPS_PROXY"} \
        pacman -Sy --noconfirm
      ;;
    zypper)
      run_cmd sudo env ${HTTP_PROXY:+http_proxy="$HTTP_PROXY"} ${HTTPS_PROXY:+https_proxy="$HTTPS_PROXY"} \
        zypper --non-interactive refresh
      ;;
    apk)
      run_cmd sudo env ${HTTP_PROXY:+http_proxy="$HTTP_PROXY"} ${HTTPS_PROXY:+https_proxy="$HTTPS_PROXY"} \
        apk update
      ;;
    *)
      echo "[ERROR] Unsupported Linux package manager on '${DISTRO_PRETTY}'. Install tools manually or switch to Ubuntu/Debian/Fedora/Arch/openSUSE/Alpine." >&2
      exit 1
      ;;
  esac
}

pkg_install() {
  if [[ $# -eq 0 ]]; then return 0; fi
  case "$PKG_MGR" in
    apt)
      run_cmd sudo env DEBIAN_FRONTEND=noninteractive \
        ${HTTP_PROXY:+http_proxy="$HTTP_PROXY"} \
        ${HTTPS_PROXY:+https_proxy="$HTTPS_PROXY"} \
        apt-get install -y --no-install-recommends "$@"
      ;;
    dnf)
      run_cmd sudo env ${HTTP_PROXY:+http_proxy="$HTTP_PROXY"} ${HTTPS_PROXY:+https_proxy="$HTTPS_PROXY"} \
        dnf install -y --skip-unavailable "$@"
      ;;
    pacman)
      run_cmd sudo env ${HTTP_PROXY:+http_proxy="$HTTP_PROXY"} ${HTTPS_PROXY:+https_proxy="$HTTPS_PROXY"} \
        pacman -S --needed --noconfirm "$@"
      ;;
    zypper)
      run_cmd sudo env ${HTTP_PROXY:+http_proxy="$HTTP_PROXY"} ${HTTPS_PROXY:+https_proxy="$HTTPS_PROXY"} \
        zypper --non-interactive install --no-recommends "$@"
      ;;
    apk)
      run_cmd sudo env ${HTTP_PROXY:+http_proxy="$HTTP_PROXY"} ${HTTPS_PROXY:+https_proxy="$HTTPS_PROXY"} \
        apk add --no-cache "$@"
      ;;
    *)
      echo "[ERROR] Unsupported Linux package manager on '${DISTRO_PRETTY}'." >&2
      exit 1
      ;;
  esac
}

persist_profile_and_env() {
  local env_file="$HOME/.dsh-wsl-env.sh"
  local profile_json="$CONFIG_ROOT/profile.json"
  local now_iso
  now_iso="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] Persist profile=${PROFILE} mirror=${MIRROR} to ${env_file} (0600) and ${profile_json} (0600)"
    return 0
  fi

  mkdir -p "$CONFIG_ROOT"
  chmod 700 "$CONFIG_ROOT"

  cat > "$profile_json" <<EOF
{
  "profile": "${PROFILE}",
  "mirror": "${MIRROR}",
  "distroId": "${DISTRO_ID}",
  "distroPrettyName": "${DISTRO_PRETTY}",
  "updatedAt": "${now_iso}"
}
EOF
  chmod 600 "$profile_json"

  cat > "$env_file" <<EOF
# Managed by dsh-wsl-sandbox provision-wsl.sh (profile=${PROFILE}, mirror=${MIRROR})
export DSH_WSL_PROFILE="${PROFILE}"
export DSH_WSL_MIRROR="${MIRROR}"
export PATH="\$HOME/.local/share/mise/shims:\$HOME/.local/bin:\$HOME/.cargo/bin:\$HOME/.bun/bin:/usr/local/go/bin:\$PATH"
EOF

  if [[ "$MIRROR" == "cn" ]]; then
    cat >> "$env_file" <<'EOF'
export UV_INDEX_URL="https://pypi.tuna.tsinghua.edu.cn/simple"
export UV_PYTHON_INSTALL_MIRROR="https://mirror.nju.edu.cn/github-release/astral-sh/python-build-standalone"
export PIP_INDEX_URL="https://pypi.tuna.tsinghua.edu.cn/simple"
export NPM_CONFIG_REGISTRY="https://registry.npmmirror.com"
export GOPROXY="https://goproxy.cn,direct"
export RUSTUP_DIST_SERVER="https://rsproxy.cn"
export RUSTUP_UPDATE_ROOT="https://rsproxy.cn/rustup"
EOF
  fi
  chmod 600 "$env_file"

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

configure_pkg_cn_mirror() {
  if [[ "$MIRROR" != "cn" ]]; then
    return 0
  fi
  if [[ "$PKG_MGR" != "apt" ]]; then
    echo "[step:base] Non-APT distro (${DISTRO_ID}/${PKG_MGR}): keeping distro repos untouched; toolchain CN mirrors (PyPI/uv/npm/Go/Rust) are configured."
    return 0
  fi
  echo "[step:base] Configuring Tsinghua TUNA APT mirror for ${DISTRO_ID} (with .bak backup)..."
  if [[ -f /etc/apt/sources.list.d/ubuntu.sources ]]; then
    if [[ ! -f /etc/apt/sources.list.d/ubuntu.sources.bak ]]; then
      run_cmd sudo cp /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list.d/ubuntu.sources.bak
    fi
    run_cmd sudo sed -i -E 's|https?://(archive|security|ports)\.ubuntu\.com/ubuntu|https://mirrors.tuna.tsinghua.edu.cn/ubuntu|g' \
      /etc/apt/sources.list.d/ubuntu.sources
  elif [[ -f /etc/apt/sources.list.d/debian.sources ]]; then
    if [[ ! -f /etc/apt/sources.list.d/debian.sources.bak ]]; then
      run_cmd sudo cp /etc/apt/sources.list.d/debian.sources /etc/apt/sources.list.d/debian.sources.bak
    fi
    run_cmd sudo sed -i -E 's|https?://deb\.debian\.org/debian|https://mirrors.tuna.tsinghua.edu.cn/debian|g' \
      /etc/apt/sources.list.d/debian.sources
  elif [[ -f /etc/apt/sources.list ]]; then
    if [[ ! -f /etc/apt/sources.list.bak ]]; then
      run_cmd sudo cp /etc/apt/sources.list /etc/apt/sources.list.bak
    fi
    run_cmd sudo sed -i -E \
      -e 's|https?://(archive|security|ports)\.ubuntu\.com/ubuntu|https://mirrors.tuna.tsinghua.edu.cn/ubuntu|g' \
      -e 's|https?://deb\.debian\.org/debian|https://mirrors.tuna.tsinghua.edu.cn/debian|g' \
      -e 's|https?://http\.kali\.org/kali|https://mirrors.tuna.tsinghua.edu.cn/kali|g' \
      /etc/apt/sources.list
  fi
}

step_base() {
  echo "=== [step:base][profile=${PROFILE}] Installing mandatory sandbox primitives (bwrap, prlimit, socat) on ${DISTRO_PRETTY} (${PKG_MGR}) ==="
  persist_profile_and_env
  configure_pkg_cn_mirror
  pkg_update
  case "$PKG_MGR" in
    apt)
      pkg_install bubblewrap util-linux bash ca-certificates socat procps curl wget gnupg tar
      ;;
    dnf)
      pkg_install bubblewrap util-linux bash ca-certificates socat procps-ng curl wget gnupg2 tar
      ;;
    pacman)
      pkg_install bubblewrap util-linux bash ca-certificates socat procps-ng curl wget gnupg tar
      ;;
    zypper)
      pkg_install bubblewrap util-linux bash ca-certificates socat procps curl wget gpg2 tar
      ;;
    apk)
      pkg_install bubblewrap util-linux bash ca-certificates socat procps curl wget gnupg tar
      ;;
  esac
}

step_cli() {
  echo "=== [step:cli][profile=${PROFILE}] Installing Codex high-frequency CLI & C/C++ build headers ==="
  persist_profile_and_env
  pkg_update

  # 1. Core layer (all profiles)
  case "$PKG_MGR" in
    apt)
      pkg_install \
        git git-lfs ripgrep fd-find jq rsync zip unzip xz-utils sqlite3 \
        openssh-client dnsutils iputils-ping netcat-openbsd inotify-tools \
        moreutils universal-ctags gawk tree file patch \
        build-essential pkg-config cmake ninja-build \
        libssl-dev zlib1g-dev libffi-dev libsqlite3-dev
      ;;
    dnf)
      pkg_install \
        git git-lfs ripgrep fd-find jq rsync zip unzip xz sqlite \
        openssh-clients bind-utils iputils nmap-ncat inotify-tools \
        moreutils ctags gawk tree file patch \
        gcc gcc-c++ make pkgconf-pkg-config cmake ninja-build \
        openssl-devel zlib-devel libffi-devel sqlite-devel
      ;;
    pacman)
      pkg_install \
        git git-lfs ripgrep fd jq rsync zip unzip xz sqlite \
        openssh bind iputils openbsd-netcat inotify-tools \
        moreutils ctags gawk tree file patch \
        base-devel pkgconf cmake ninja openssl zlib libffi
      ;;
    zypper)
      pkg_install \
        git git-lfs ripgrep fd jq rsync zip unzip xz sqlite3 \
        openssh bind-utils iputils netcat-openbsd inotify-tools \
        moreutils ctags gawk tree file patch \
        gcc gcc-c++ make pkg-config cmake ninja \
        libopenssl-devel zlib-devel libffi-devel sqlite3-devel
      ;;
    apk)
      pkg_install \
        git git-lfs ripgrep fd jq rsync zip unzip xz sqlite \
        openssh-client bind-tools iputils netcat-openbsd inotify-tools \
        moreutils ctags gawk tree file patch \
        build-base pkgconf cmake ninja \
        openssl-dev zlib-dev libffi-dev sqlite-dev
      ;;
  esac

  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] Ensure \$HOME/.local/bin/fd symlink if distro ships fdfind"
  elif command -v fdfind >/dev/null 2>&1 && ! command -v fd >/dev/null 2>&1; then
    run_cmd mkdir -p "$HOME/.local/bin"
    run_cmd ln -sf "$(command -v fdfind)" "$HOME/.local/bin/fd"
  fi

  # 2. Standard & Universal layer (C/C++ extended headers)
  if [[ "$PROFILE" == "standard" || "$PROFILE" == "universal" ]]; then
    echo "[step:cli][profile=${PROFILE}] Installing standard C/C++ build accelerators (ccache, protobuf, libpq, libxml2)..."
    case "$PKG_MGR" in
      apt)    pkg_install ccache protobuf-compiler libpq-dev libxml2-dev ;;
      dnf)    pkg_install ccache protobuf-compiler libpq-devel libxml2-devel ;;
      pacman) pkg_install ccache protobuf postgresql-libs libxml2 ;;
      zypper) pkg_install ccache protobuf-devel postgresql-devel libxml2-devel ;;
      apk)    pkg_install ccache protobuf libpq-dev libxml2-dev ;;
    esac
  fi

  # 3. Universal layer (prebuilt clang + bazelisk — ZERO source builds)
  if [[ "$PROFILE" == "universal" ]]; then
    echo "[step:cli][profile=universal] Installing prebuilt clang toolchain & bazelisk binary..."
    case "$PKG_MGR" in
      apt)    pkg_install clang clang-format clang-tidy ;;
      dnf)    pkg_install clang clang-tools-extra ;;
      pacman) pkg_install clang ;;
      zypper) pkg_install clang ;;
      apk)    pkg_install clang clang-extra-tools ;;
    esac

    local bazelisk_url="https://github.com/bazelbuild/bazelisk/releases/latest/download/bazelisk-linux-${GO_ARCH}"
    if [[ "$DRY_RUN" == "true" ]]; then
      echo "[dry-run] Download prebuilt bazelisk (${bazelisk_url}) -> \$HOME/.local/bin/bazelisk (+ bazel symlink)"
    elif ! command -v bazelisk >/dev/null 2>&1; then
      mkdir -p "$HOME/.local/bin"
      curl -fsSL "$bazelisk_url" -o "$HOME/.local/bin/bazelisk"
      chmod +x "$HOME/.local/bin/bazelisk"
      ln -sf "$HOME/.local/bin/bazelisk" "$HOME/.local/bin/bazel"
    else
      echo "[step:cli] bazelisk already installed: $(command -v bazelisk)"
    fi
  fi
}

step_node() {
  echo "=== [step:node][profile=${PROFILE}] Installing prebuilt Node.js toolchain ==="
  persist_profile_and_env

  # Core + all profiles: Node.js 22 LTS prebuilt binary
  local need_node="true"
  if command -v node >/dev/null 2>&1; then
    local major
    major="$(node -v | sed -E 's/^v([0-9]+).*/\1/')"
    if [[ "$major" -ge 22 ]]; then
      echo "[step:node] Node $(node -v) already >= 22, skipping base Node 22 install."
      need_node="false"
    fi
  fi

  if [[ "$need_node" == "true" ]]; then
    if [[ "$DRY_RUN" == "true" ]]; then
      echo "[dry-run] Install prebuilt Node.js 22 LTS for ${PKG_MGR}"
    else
      case "$PKG_MGR" in
        apt)
          curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
          pkg_install nodejs
          ;;
        dnf)
          curl -fsSL https://rpm.nodesource.com/setup_22.x | sudo -E bash -
          pkg_install nodejs
          ;;
        pacman)
          pkg_install nodejs npm
          ;;
        zypper)
          pkg_install nodejs22 npm22 || pkg_install nodejs npm
          ;;
        apk)
          pkg_install nodejs npm
          ;;
      esac
    fi
  fi

  if [[ "$PROFILE" == "core" ]]; then
    echo "[step:node][profile=core] Core profile stops at Node.js 22 LTS (skipping mise/pnpm/yarn/bun/eslint)."
    return 0
  fi

  # Standard & Universal: mise + pnpm + yarn (corepack/npm) + bun + typescript + eslint + prettier
  echo "[step:node][profile=${PROFILE}] Installing mise, pnpm, yarn, bun, typescript, eslint, prettier..."
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] Ensure prebuilt mise binary (https://mise.run)"
    echo "[dry-run] Enable corepack (yarn/pnpm) and ensure global npm packages: pnpm yarn typescript eslint prettier"
    echo "[dry-run] Ensure prebuilt bun binary (https://bun.sh/install)"
  else
    if ! command -v mise >/dev/null 2>&1; then
      curl -fsSL https://mise.run | sh
    fi
    export PATH="$HOME/.local/share/mise/shims:$HOME/.local/bin:$HOME/.bun/bin:$PATH"

    if command -v corepack >/dev/null 2>&1; then
      sudo corepack enable 2>/dev/null || corepack enable --install-directory "$HOME/.local/bin" 2>/dev/null || true
    fi

    local npm_prefix="$HOME/.local"
    mkdir -p "$npm_prefix/bin"
    local missing_npm_pkgs=()
    command -v pnpm >/dev/null 2>&1 || missing_npm_pkgs+=(pnpm)
    command -v yarn >/dev/null 2>&1 || missing_npm_pkgs+=(yarn)
    command -v tsc >/dev/null 2>&1 || missing_npm_pkgs+=(typescript)
    command -v eslint >/dev/null 2>&1 || missing_npm_pkgs+=(eslint)
    command -v prettier >/dev/null 2>&1 || missing_npm_pkgs+=(prettier)
    if [[ ${#missing_npm_pkgs[@]} -gt 0 ]]; then
      npm install -g --prefix "$npm_prefix" "${missing_npm_pkgs[@]}"
    fi

    if ! command -v bun >/dev/null 2>&1; then
      curl -fsSL https://bun.sh/install | bash
    fi
  fi

  # Universal only: multi-version Node 20 / 22 / 24 prebuilt via mise
  if [[ "$PROFILE" == "universal" ]]; then
    echo "[step:node][profile=universal] Installing prebuilt Node 20, 22, 24 via mise..."
    if [[ "$DRY_RUN" == "true" ]]; then
      echo "[dry-run] mise install node@20 node@22 node@24 && mise use -g node@22"
    else
      export PATH="$HOME/.local/share/mise/shims:$HOME/.local/bin:$PATH"
      mise install node@20 node@22 node@24
      mise use -g node@22
    fi
  fi
}

step_python() {
  echo "=== [step:python][profile=${PROFILE}] Installing Python 3 (binary-only, ZERO pyenv source compilation) ==="
  persist_profile_and_env
  case "$PKG_MGR" in
    apt)    pkg_install python3 python3-venv python3-pip ;;
    dnf)    pkg_install python3 python3-pip ;;
    pacman) pkg_install python python-pip ;;
    zypper) pkg_install python3 python3-pip ;;
    apk)    pkg_install python3 py3-pip ;;
  esac

  if [[ "$PROFILE" == "core" ]]; then
    echo "[step:python][profile=core] Core profile stops at system python3 + venv (skipping uv/pytest/ruff/mypy/pyright/black)."
    return 0
  fi

  # Standard & Universal: Astral uv + CLI tools
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] Ensure prebuilt Astral uv binary (https://astral.sh/uv/install.sh)"
  elif ! command -v uv >/dev/null 2>&1; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
  fi
  export PATH="$HOME/.local/bin:$PATH"

  local tools=(pytest ruff mypy pyright black)
  if [[ "$PROFILE" == "universal" ]]; then
    tools+=(poetry isort)
  fi
  local t
  for t in "${tools[@]}"; do
    if [[ "$DRY_RUN" == "true" ]]; then
      echo "[dry-run] uv tool install ${t}"
    elif ! command -v "$t" >/dev/null 2>&1; then
      run_cmd uv tool install "$t"
    else
      echo "[step:python] ${t} already installed."
    fi
  done
}

step_go() {
  if [[ "$PROFILE" == "core" ]]; then
    echo "=== [step:go][profile=core] Skipped for 'core' profile ==="
    return 0
  fi
  echo "=== [step:go][profile=${PROFILE}] Installing prebuilt Go tarball + prebuilt golangci-lint ==="
  persist_profile_and_env

  local go_ver="1.24.2"
  local go_base="https://go.dev/dl"
  if [[ "$MIRROR" == "cn" ]]; then
    go_base="https://golang.google.cn/dl"
  fi
  local tarball="go${go_ver}.linux-${GO_ARCH}.tar.gz"

  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] Download ${go_base}/${tarball} and extract into /usr/local/go"
    echo "[dry-run] Install prebuilt golangci-lint binary -> \$HOME/.local/bin/golangci-lint"
    return 0
  fi

  if ! command -v go >/dev/null 2>&1; then
    curl -fsSL "${go_base}/${tarball}" -o "/tmp/${tarball}"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "/tmp/${tarball}"
    rm -f "/tmp/${tarball}"
  else
    echo "[step:go] Go already installed: $(go version)"
  fi

  if ! command -v golangci-lint >/dev/null 2>&1; then
    mkdir -p "$HOME/.local/bin"
    curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b "$HOME/.local/bin"
  else
    echo "[step:go] golangci-lint already installed: $(golangci-lint --version | head -n 1)"
  fi
}

step_rust() {
  if [[ "$PROFILE" == "core" ]]; then
    echo "=== [step:rust][profile=core] Skipped for 'core' profile ==="
    return 0
  fi
  echo "=== [step:rust][profile=${PROFILE}] Installing prebuilt Rust minimal toolchain (rustup + rustfmt + clippy) ==="
  persist_profile_and_env

  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] Install Rust minimal profile via rustup (--profile minimal --component rustfmt,clippy)"
    return 0
  fi

  if ! command -v rustc >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --component rustfmt,clippy
  else
    echo "[step:rust] Rust already installed: $(rustc --version)"
  fi
}

step_extra() {
  if [[ "$PROFILE" != "universal" ]]; then
    echo "=== [step:extra][profile=${PROFILE}] Skipped for '${PROFILE}' profile (universal only) ==="
    return 0
  fi
  echo "=== [step:extra][profile=universal] Installing prebuilt OpenJDK 21, Maven, Gradle, Ruby, PHP CLI + Composer ==="
  persist_profile_and_env
  pkg_update
  case "$PKG_MGR" in
    apt)    pkg_install openjdk-21-jdk-headless maven gradle ruby php-cli composer ;;
    dnf)    pkg_install java-21-openjdk-headless maven gradle ruby php-cli composer ;;
    pacman) pkg_install jdk21-openjdk maven gradle ruby php composer ;;
    zypper) pkg_install java-21-openjdk-headless maven gradle ruby php8 composer ;;
    apk)    pkg_install openjdk21-jre-headless maven gradle ruby php83 composer ;;
  esac
}

echo "[dsh-wsl-sandbox] Provisioning distro='${DISTRO_PRETTY}' (${PKG_MGR}) profile=${PROFILE} mirror=${MIRROR} step=${STEP} arch=${ARCH}"

case "$STEP" in
  base)    step_base ;;
  cli)     step_cli ;;
  node)    step_node ;;
  python)  step_python ;;
  go)      step_go ;;
  rust)    step_rust ;;
  go-rust) step_go; step_rust ;;
  extra)   step_extra ;;
  all)
    step_base
    step_cli
    step_node
    step_python
    step_go
    step_rust
    step_extra
    ;;
esac

echo "[dsh-wsl-sandbox] Step '${STEP}' finished cleanly for profile '${PROFILE}'. Next: run 'dsh-wsl-doctor --profile ${PROFILE}' to verify kernel isolation & tool matrix."
