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
UPGRADE_NODE="false"
PURGE_TOOLCHAINS="false"
SKIP_RESTORE_ON_UNINSTALL="false"

usage() {
  cat <<'EOF'
Usage: provision-wsl.sh [options]
  --profile core|standard|universal   Toolchain profile (default: standard)
                                        core      (~350MB): sandbox base + Codex CLI + C/C++ base + system python3
                                                            + shared Node (>=22) or verified prebuilt Node 24 LTS
                                        standard  (~1.2GB): core + ccache/proto + mise + uv + pytest/ruff/mypy/pyright/black
                                                            + pnpm/yarn/bun/ts/eslint/prettier + Go + golangci-lint + Rust minimal
                                        universal (~3.5GB): standard + clang/bazelisk + mise Node 22 & 24 LTS + poetry/isort
                                                            + OpenJDK 21 + maven + gradle + ruby + php-cli + composer
  --mirror  global|cn                 Use global upstream or China mirrors (default: global)
  --proxy   <url>                     Optional HTTP/SOCKS5 upstream proxy (e.g. http://127.0.0.1:7890)
  --step    all|base|cli|node|python|go|rust|go-rust|extra
                                      Run one idempotent step or all steps (default: all)
  --upgrade-node                      Upgrade existing Node 22.x in WSL to Node 24 Active LTS (default reuses >=22)
  --backup-configs                    Snapshot original /etc/wsl.conf, /etc/fstab & mounts (read-only 0400, SHA-256 deduped)
  --backup-dir <path>                 Custom backup directory (Linux path or Windows path like D:\Backups\WSL)
  --open-backup-dir                   Open the backup directory in native Windows Explorer
  --disable-automount                 Back up /etc/wsl.conf and set [automount] enabled = false
                                      (Note: shared with WSL Settings & WSL Manager; apply via `wsl.exe --terminate <Distro>`)
  --restore-configs                   Restore original /etc/wsl.conf & package mirror sources from backup
  --uninstall                         Restore configs, strip shell hooks, and remove all WSL plugin state/runner/caches/temp dirs
  --purge-toolchains                  With --uninstall: also remove packages & toolchains recorded as newly installed in provision-manifest.json
  --skip-restore                      With --uninstall: skip restoring /etc/wsl.conf & APT mirror sources
  --dry-run                           Print planned actions without modifying the system
  -h, --help                          Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE="${2:?Missing value for --profile}"; shift 2 ;;
    --mirror)  MIRROR="${2:?Missing value for --mirror}"; shift 2 ;;
    --proxy)   PROXY="${2:?Missing value for --proxy}"; shift 2 ;;
    --step)    STEP="${2:?Missing value for --step}"; shift 2 ;;
    --upgrade-node)      UPGRADE_NODE="true"; shift ;;
    --backup-configs)    ACTION="backup"; shift ;;
    --backup-dir)        CUSTOM_BACKUP_DIR="${2:?Missing value for --backup-dir}"; shift 2 ;;
    --open-backup-dir)   OPEN_BACKUP_EXPLORER="true"; shift ;;
    --disable-automount) ACTION="disable-automount"; shift ;;
    --restore-configs)   ACTION="restore"; shift ;;
    --uninstall)         ACTION="uninstall"; shift ;;
    --purge-toolchains)  PURGE_TOOLCHAINS="true"; shift ;;
    --skip-restore)      SKIP_RESTORE_ON_UNINSTALL="true"; shift ;;
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
MANIFEST_FILE="$CONFIG_ROOT/provision-manifest.json"
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

file_sha256() {
  local f="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$f" 2>/dev/null | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$f" 2>/dev/null | awk '{print $1}'
  else
    wc -c < "$f" 2>/dev/null | tr -d ' '
  fi
}

# Writes `.orig` once (0400), skips creating duplicate `.bak` if SHA-256 matches latest snapshot,
# and rotates rolling `.bak` snapshots to at most 5 (unlocking 0400 before deleting old `.bak`).
save_deduped_backup_series() {
  local src_file="$1"
  local orig_name="$2"
  local prefix="$3"
  local ext="$4"
  local ts="$5"
  local orig_path="$BACKUP_DIR/$orig_name"

  if [[ ! -f "$orig_path" ]]; then
    save_readonly_file "$src_file" "$orig_path"
    echo "[backup] Saved pristine read-only $orig_name -> $orig_path"
  fi

  local latest_rolling=""
  latest_rolling="$(ls -1 "$BACKUP_DIR/${prefix}."*".""$ext" 2>/dev/null | grep -v -F "/$orig_name" | sort | tail -n 1 || true)"
  local compare_file="${latest_rolling:-$orig_path}"

  if [[ -f "$compare_file" ]]; then
    local cur_hash prev_hash
    cur_hash="$(file_sha256 "$src_file")"
    prev_hash="$(file_sha256 "$compare_file")"
    if [[ -n "$cur_hash" && "$cur_hash" == "$prev_hash" ]]; then
      return 0
    fi
  fi

  save_readonly_file "$src_file" "$BACKUP_DIR/${prefix}.${ts}.${ext}"

  # Keep at most 5 rolling snapshots (never touch .orig)
  local old_file
  while IFS= read -r old_file; do
    [[ -z "$old_file" ]] && continue
    chmod u+w "$old_file" 2>/dev/null || true
    rm -f "$old_file" 2>/dev/null || true
  done < <(ls -1 "$BACKUP_DIR/${prefix}."*".""$ext" 2>/dev/null | grep -v -F "/$orig_name" | sort -r | tail -n +6 || true)
}

backup_original_wsl_configs() {
  local ts
  ts="$(date +%Y%m%d-%H%M%S)"
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] mkdir -p -m 700 $BACKUP_DIR && snapshot /etc/wsl.conf, /etc/fstab, /proc/mounts (read-only 0400, SHA-256 deduplicated)"
    return 0
  fi
  mkdir -p "$CONFIG_ROOT"
  chmod 700 "$CONFIG_ROOT"
  mkdir -p "$BACKUP_DIR"
  chmod 700 "$BACKUP_DIR"

  if [[ -f /etc/wsl.conf ]]; then
    save_deduped_backup_series /etc/wsl.conf "wsl.conf.orig" "wsl.conf" "bak" "$ts"
  else
    if [[ ! -f "$BACKUP_DIR/wsl.conf.orig" && ! -f "$BACKUP_DIR/wsl.conf.orig.absent" ]]; then
      write_readonly_text "$BACKUP_DIR/wsl.conf.orig.absent" "# /etc/wsl.conf did not exist prior to dsh-wsl-sandbox setup (${ts})"
      echo "[backup] Recorded pristine state (no /etc/wsl.conf) -> $BACKUP_DIR/wsl.conf.orig.absent"
    fi
  fi

  if [[ -f /etc/fstab ]]; then
    save_deduped_backup_series /etc/fstab "fstab.orig" "fstab" "bak" "$ts"
  fi

  if [[ -r /proc/mounts ]]; then
    local mount_tmp
    mount_tmp="$(mktemp)"
    grep -E 'drvfs|9p|/mnt/' /proc/mounts > "$mount_tmp" 2>/dev/null || true
    save_deduped_backup_series "$mount_tmp" "drvfs-mounts.orig.txt" "drvfs-mounts" "txt" "$ts"
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
  local remove_apt_bak="${1:-false}"
  echo "=== [restore] Restoring original WSL configuration from $BACKUP_DIR ==="
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] Restore /etc/wsl.conf and package mirror sources from $BACKUP_DIR"
    return 0
  fi
  if [[ -f "$BACKUP_DIR/wsl.conf.orig" ]]; then
    if ! cmp -s "$BACKUP_DIR/wsl.conf.orig" /etc/wsl.conf 2>/dev/null; then
      sudo cp "$BACKUP_DIR/wsl.conf.orig" /etc/wsl.conf
      sudo chmod 644 /etc/wsl.conf
      echo "[ok] Restored /etc/wsl.conf from $BACKUP_DIR/wsl.conf.orig"
    else
      echo "[ok] /etc/wsl.conf already matches pristine $BACKUP_DIR/wsl.conf.orig"
    fi
  elif [[ -f "$BACKUP_DIR/wsl.conf.orig.absent" ]]; then
    if [[ -f /etc/wsl.conf ]]; then
      sudo rm -f /etc/wsl.conf
      echo "[ok] Removed /etc/wsl.conf (system originally had no /etc/wsl.conf)"
    fi
  else
    echo "[info] No /etc/wsl.conf backup marker found in $BACKUP_DIR; left untouched."
  fi

  local src
  for src in /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list.d/debian.sources /etc/apt/sources.list; do
    if [[ -f "${src}.bak" ]]; then
      sudo cp "${src}.bak" "$src"
      echo "[ok] Restored $src from ${src}.bak"
      if [[ "$remove_apt_bak" == "true" ]]; then
        sudo rm -f "${src}.bak"
      fi
    fi
  done
  echo "[next] Run 'wsl.exe --terminate ${CURRENT_WSL_DISTRO}' in Windows PowerShell if /etc/wsl.conf was changed (avoids killing other distros)."
}

uninstall_wsl_sandbox() {
  echo "=== [uninstall] Removing dsh-wsl-sandbox WSL artifacts (purgeToolchains=${PURGE_TOOLCHAINS}, dryRun=${DRY_RUN}) ==="

  if [[ "$SKIP_RESTORE_ON_UNINSTALL" != "true" ]]; then
    restore_original_wsl_configs "true"
  fi

  # 1. Strip shell RC hooks & remove ~/.dsh-wsl-env.sh
  local rc
  for rc in "$HOME/.bashrc" "$HOME/.profile" "$HOME/.bash_profile" "$HOME/.zshrc"; do
    if [[ -f "$rc" ]] && grep -Fq '.dsh-wsl-env.sh' "$rc"; then
      if [[ "$DRY_RUN" == "true" ]]; then
        echo "[dry-run] Strip .dsh-wsl-env.sh source line from $rc"
      else
        local tmp_rc
        tmp_rc="$(mktemp)"
        grep -Fv '.dsh-wsl-env.sh' "$rc" > "$tmp_rc" || true
        cat "$tmp_rc" > "$rc"
        rm -f "$tmp_rc"
        echo "[ok] Cleaned shell hook from $rc"
      fi
    fi
  done

  if [[ -f "$HOME/.dsh-wsl-env.sh" ]]; then
    if [[ "$DRY_RUN" == "true" ]]; then
      echo "[dry-run] Remove $HOME/.dsh-wsl-env.sh"
    else
      rm -f "$HOME/.dsh-wsl-env.sh"
      echo "[ok] Removed $HOME/.dsh-wsl-env.sh"
    fi
  fi

  # 2. Optional toolchain delta rollback (from $MANIFEST_FILE)
  if [[ "$PURGE_TOOLCHAINS" == "true" ]]; then
    if [[ -f "$MANIFEST_FILE" ]]; then
      echo "[uninstall] Rolling back newly installed toolchains & packages recorded in $MANIFEST_FILE ..."
      local uv_tools=() npm_globals=() created_paths=() installed_pkgs=()
      while IFS= read -r line; do [[ -n "$line" ]] && uv_tools+=("$line"); done < <(grep -o '"uv:[^"]*"' "$MANIFEST_FILE" 2>/dev/null | sed 's/"uv://;s/"$//' || true)
      while IFS= read -r line; do [[ -n "$line" ]] && npm_globals+=("$line"); done < <(grep -o '"npm:[^"]*"' "$MANIFEST_FILE" 2>/dev/null | sed 's/"npm://;s/"$//' || true)
      while IFS= read -r line; do [[ -n "$line" ]] && created_paths+=("$line"); done < <(grep -o '"path:[^"]*"' "$MANIFEST_FILE" 2>/dev/null | sed 's/"path://;s/"$//' || true)
      while IFS= read -r line; do [[ -n "$line" ]] && installed_pkgs+=("$line"); done < <(grep -o '"pkg:[^"]*"' "$MANIFEST_FILE" 2>/dev/null | sed 's/"pkg://;s/"$//' || true)

      if [[ ${#uv_tools[@]} -gt 0 ]] && command -v uv >/dev/null 2>&1; then
        for t in "${uv_tools[@]}"; do
          if [[ "$DRY_RUN" == "true" ]]; then echo "[dry-run] uv tool uninstall $t"; else uv tool uninstall "$t" 2>/dev/null || true; fi
        done
      fi
      if [[ ${#npm_globals[@]} -gt 0 ]] && command -v npm >/dev/null 2>&1; then
        if [[ "$DRY_RUN" == "true" ]]; then
          echo "[dry-run] npm uninstall -g --prefix $HOME/.local ${npm_globals[*]}"
        else
          npm uninstall -g --prefix "$HOME/.local" "${npm_globals[@]}" 2>/dev/null || true
        fi
      fi
      for p in "${created_paths[@]}"; do
        if [[ -e "$p" || -L "$p" ]]; then
          if [[ "$DRY_RUN" == "true" ]]; then
            echo "[dry-run] Remove newly installed toolchain path: $p"
          elif [[ "$p" == /usr/local/* || "$p" == /etc/* ]]; then
            sudo rm -rf "$p"
            echo "[ok] Removed $p"
          else
            chmod -R u+w "$p" 2>/dev/null || true
            rm -rf "$p"
            echo "[ok] Removed $p"
          fi
        fi
      done
      if [[ ${#installed_pkgs[@]} -gt 0 ]]; then
        if [[ "$DRY_RUN" == "true" ]]; then
          echo "[dry-run] Uninstall ${#installed_pkgs[@]} delta OS packages (${PKG_MGR}): ${installed_pkgs[*]}"
        else
          case "$PKG_MGR" in
            apt)    sudo env DEBIAN_FRONTEND=noninteractive apt-get purge -y --auto-remove "${installed_pkgs[@]}" || true ;;
            dnf)    sudo dnf remove -y "${installed_pkgs[@]}" || true ;;
            pacman) sudo pacman -Rns --noconfirm "${installed_pkgs[@]}" || true ;;
            zypper) sudo zypper --non-interactive remove "${installed_pkgs[@]}" || true ;;
            apk)    sudo apk del "${installed_pkgs[@]}" || true ;;
          esac
        fi
      fi
    else
      echo "[info] $MANIFEST_FILE not found (was provision-wsl.sh run on v0.1.0 or skipped?); skipping automatic OS package purge."
    fi

    # Also clean legacy v0.1.0 NodeSource APT repo/keyring if present
    for legacy_ns in /etc/apt/sources.list.d/nodesource.list /etc/apt/keyrings/nodesource.gpg /usr/share/keyrings/nodesource.gpg; do
      if [[ -f "$legacy_ns" ]]; then
        if [[ "$DRY_RUN" == "true" ]]; then
          echo "[dry-run] Remove legacy NodeSource file: $legacy_ns"
        else
          sudo rm -f "$legacy_ns"
          echo "[ok] Removed legacy NodeSource file: $legacy_ns"
        fi
      fi
    done
  fi

  # 3. Sweep runtime temp dirs across /run/user/<uid>, /dev/shm, and /tmp (unlocking 0444 empty-mask first)
  local tmp_base d
  for tmp_base in "/run/user/$(id -u)" "/dev/shm" "/tmp"; do
    [[ -d "$tmp_base" ]] || continue
    for d in "$tmp_base"/dsh-wsl-runner-* "$tmp_base"/dsh-wsl-proxy-*; do
      [[ -e "$d" ]] || continue
      if [[ "$DRY_RUN" == "true" ]]; then
        echo "[dry-run] Remove runtime temp dir: $d"
      else
        chmod -R u+w "$d" 2>/dev/null || true
        rm -rf "$d" 2>/dev/null || true
      fi
    done
  done

  # 4. Remove workspace caches (~/.cache/dsh-wsl-sandbox) & staged runner/toolchains (~/.local/share/dsh-wsl-sandbox)
  local plugin_dir
  for plugin_dir in "$HOME/.cache/dsh-wsl-sandbox" "$HOME/.local/share/dsh-wsl-sandbox" "$CONFIG_ROOT"; do
    if [[ -e "$plugin_dir" ]]; then
      if [[ "$DRY_RUN" == "true" ]]; then
        echo "[dry-run] Unlock read-only files & remove directory: $plugin_dir"
      else
        chmod -R u+w "$plugin_dir" 2>/dev/null || true
        rm -rf "$plugin_dir"
        echo "[ok] Removed $plugin_dir"
      fi
    fi
  done

  # Clean isolated Node symlinks in ~/.dsh/runtime/bin if broken after removing ~/.local/share/dsh-wsl-sandbox
  if [[ -d "$HOME/.dsh/runtime/bin" ]]; then
    local link
    for link in "$HOME/.dsh/runtime/bin"/*; do
      if [[ -L "$link" && ! -e "$link" ]]; then
        [[ "$DRY_RUN" == "true" ]] && echo "[dry-run] Remove broken symlink $link" || rm -f "$link"
      fi
    done
    [[ "$DRY_RUN" != "true" ]] && rmdir "$HOME/.dsh/runtime/bin" "$HOME/.dsh/runtime" 2>/dev/null || true
  fi

  # 5. Remove default ~/workspace ONLY if completely empty (never delete user files!)
  if [[ -d "$HOME/workspace" ]]; then
    if [[ -z "$(ls -A "$HOME/workspace" 2>/dev/null)" ]]; then
      if [[ "$DRY_RUN" == "true" ]]; then
        echo "[dry-run] Remove empty default workspace directory: $HOME/workspace"
      else
        rmdir "$HOME/workspace" 2>/dev/null || true
        echo "[ok] Removed empty $HOME/workspace"
      fi
    else
      echo "[keep] Preserved non-empty $HOME/workspace (contains user files)."
    fi
  fi

  echo "[ok] WSL-side dsh-wsl-sandbox uninstall complete."
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
elif [[ "$ACTION" == "uninstall" ]]; then
  uninstall_wsl_sandbox
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

is_os_pkg_installed() {
  local pkg="$1"
  case "$PKG_MGR" in
    apt)    dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed" ;;
    dnf)    rpm -q "$pkg" >/dev/null 2>&1 ;;
    pacman) pacman -Qi "$pkg" >/dev/null 2>&1 ;;
    zypper) rpm -q "$pkg" >/dev/null 2>&1 ;;
    apk)    apk info -e "$pkg" >/dev/null 2>&1 ;;
    *)      return 1 ;;
  esac
}

record_manifest_entries() {
  if [[ "$DRY_RUN" == "true" || $# -eq 0 ]]; then
    return 0
  fi
  mkdir -p "$CONFIG_ROOT"
  chmod 700 "$CONFIG_ROOT"
  local existing=()
  if [[ -f "$MANIFEST_FILE" ]]; then
    while IFS= read -r item; do
      [[ -n "$item" ]] && existing+=("$item")
    done < <(grep -o '"[^"]*:[^"]*"' "$MANIFEST_FILE" 2>/dev/null | tr -d '"' || true)
  fi
  local item seen
  for item in "$@"; do
    seen="false"
    local ex
    for ex in "${existing[@]:-}"; do
      if [[ "$ex" == "$item" ]]; then seen="true"; break; fi
    done
    [[ "$seen" == "false" ]] && existing+=("$item")
  done

  local now_iso
  now_iso="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  {
    printf '{\n'
    printf '  "updatedAt": "%s",\n' "$now_iso"
    printf '  "profile": "%s",\n' "$PROFILE"
    printf '  "pkgManager": "%s",\n' "$PKG_MGR"
    printf '  "deltaEntries": [\n'
    local idx=0 total=${#existing[@]}
    for item in "${existing[@]:-}"; do
      idx=$((idx + 1))
      if [[ $idx -lt $total ]]; then
        printf '    "%s",\n' "$item"
      else
        printf '    "%s"\n' "$item"
      fi
    done
    printf '  ]\n'
    printf '}\n'
  } > "$MANIFEST_FILE"
  chmod 600 "$MANIFEST_FILE"
}

pkg_install() {
  if [[ $# -eq 0 ]]; then return 0; fi
  local newly_requested=()
  if [[ "$DRY_RUN" != "true" ]]; then
    local p
    for p in "$@"; do
      if ! is_os_pkg_installed "$p"; then
        newly_requested+=("pkg:$p")
      fi
    done
  fi

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

  if [[ ${#newly_requested[@]} -gt 0 ]]; then
    record_manifest_entries "${newly_requested[@]}"
  fi
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
export PATH="\$HOME/.dsh/runtime/bin:\$HOME/.local/share/dsh/node/bin:\$HOME/.local/share/dsh-wsl-sandbox/toolchains/node/bin:\$HOME/.local/share/mise/shims:\$HOME/.local/bin:\$HOME/.nvm/current/bin:\$HOME/.volta/bin:\$HOME/.cargo/bin:\$HOME/.bun/bin:/usr/local/go/bin:\$PATH"
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
  # If ~/.bash_profile already exists, bash -lc reads it instead of ~/.profile — hook it WITHOUT creating it if absent!
  if [[ -f "$HOME/.bash_profile" ]] && ! grep -Fq '.dsh-wsl-env.sh' "$HOME/.bash_profile"; then
    printf '\n[ -f "$HOME/.dsh-wsl-env.sh" ] && . "$HOME/.dsh-wsl-env.sh"\n' >> "$HOME/.bash_profile"
  fi

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

# Ensures curl, ca-certificates, tar, unzip, xz exist even when a single step (--step node/python/go/rust) runs standalone!
ensure_step_prereqs() {
  if [[ "$DRY_RUN" == "true" ]]; then return 0; fi
  local missing="false"
  for bin in curl tar unzip xz; do
    if ! command -v "$bin" >/dev/null 2>&1; then
      missing="true"
      break
    fi
  done
  if [[ "$missing" == "true" ]]; then
    pkg_update
    case "$PKG_MGR" in
      apt)    pkg_install ca-certificates curl tar unzip xz-utils gnupg ;;
      dnf)    pkg_install ca-certificates curl tar unzip xz gnupg2 ;;
      pacman) pkg_install ca-certificates curl tar unzip xz gnupg ;;
      zypper) pkg_install ca-certificates curl tar unzip xz gpg2 ;;
      apk)    pkg_install ca-certificates curl tar unzip xz gnupg ;;
    esac
  fi
}

# Discovers any Linux Node.js (>=22) already installed by DSH remote/headless, peer plugins, mise, nvm, fnm, volta, or OS
find_shared_wsl_node() {
  local cand
  local search_dirs=(
    "$HOME/.dsh/runtime/bin"
    "$HOME/.local/share/dsh/node/bin"
    "$HOME/.local/share/dsh-wsl-sandbox/toolchains/node/bin"
    "$HOME/.local/share/mise/shims"
    "$HOME/.local/bin"
    "$HOME/.nvm/current/bin"
    "$HOME/.local/share/fnm/aliases/default/bin"
    "$HOME/.volta/bin"
    "/opt/dsh-toolchain/shims"
    "/opt/dsh-toolchain/bin"
    "/usr/local/bin"
    "/usr/bin"
    "/bin"
  )
  for d in "$HOME"/.nvm/versions/node/v*/bin; do
    [[ -d "$d" ]] && search_dirs+=("$d")
  done
  for dir in "${search_dirs[@]}"; do
    [[ "$dir" == /mnt/* ]] && continue
    cand="$dir/node"
    if [[ -x "$cand" && ! -d "$cand" ]]; then
      local ver major
      ver="$("$cand" -v 2>/dev/null || true)"
      major="$(echo "$ver" | sed -E 's/^v([0-9]+).*/\1/')"
      if [[ "$major" =~ ^[0-9]+$ ]] && [[ "$major" -ge 22 ]]; then
        printf '%s\t%s\t%s\n' "$cand" "$ver" "$major"
        return 0
      fi
    fi
  done
  return 1
}

# Installs official prebuilt Node.js 24 Active LTS into $HOME/.local/share/dsh-wsl-sandbox/toolchains/node
# verified via official SHASUMS256.txt — ZERO `curl | sudo bash`, ZERO root APT repo/keyring pollution!
install_verified_prebuilt_node24() {
  local node_arch="x64"
  [[ "$ARCH" == "aarch64" ]] && node_arch="arm64"
  local dist_base="https://nodejs.org/dist/latest-v24.x"
  [[ "$MIRROR" == "cn" ]] && dist_base="https://npmmirror.com/mirrors/node/latest-v24.x"

  local tmp_dir
  tmp_dir="$(mktemp -d)"
  curl -fsSL "${dist_base}/SHASUMS256.txt" -o "$tmp_dir/SHASUMS256.txt"
  local tarball_line tarball_name expected_sha
  tarball_line="$(grep -E "  node-v24\.[0-9]+\.[0-9]+-linux-${node_arch}\.tar\.xz$" "$tmp_dir/SHASUMS256.txt" | head -n 1)"
  if [[ -z "$tarball_line" ]]; then
    rm -rf "$tmp_dir"
    echo "[ERROR] Failed to locate linux-${node_arch} tarball in ${dist_base}/SHASUMS256.txt" >&2
    exit 1
  fi
  expected_sha="$(echo "$tarball_line" | awk '{print $1}')"
  tarball_name="$(echo "$tarball_line" | awk '{print $2}')"

  echo "[step:node] Downloading verified ${tarball_name} (SHA-256=${expected_sha:0:12}...)..."
  curl -fsSL "${dist_base}/${tarball_name}" -o "$tmp_dir/${tarball_name}"
  local actual_sha
  actual_sha="$(file_sha256 "$tmp_dir/${tarball_name}")"
  if [[ "$actual_sha" != "$expected_sha" ]]; then
    rm -rf "$tmp_dir"
    echo "[ERROR] SHA-256 mismatch for ${tarball_name}: expected ${expected_sha}, got ${actual_sha}" >&2
    exit 1
  fi

  local dest_root="$HOME/.local/share/dsh-wsl-sandbox/toolchains/node"
  rm -rf "$dest_root"
  mkdir -p "$dest_root"
  chmod 700 "$HOME/.local/share/dsh-wsl-sandbox" "$HOME/.local/share/dsh-wsl-sandbox/toolchains"
  tar -xJf "$tmp_dir/${tarball_name}" --strip-components=1 -C "$dest_root"
  rm -rf "$tmp_dir"

  mkdir -p "$HOME/.dsh/runtime/bin" "$HOME/.local/bin"
  for b in node npm npx corepack; do
    if [[ -x "$dest_root/bin/$b" ]]; then
      ln -sf "$dest_root/bin/$b" "$HOME/.dsh/runtime/bin/$b"
      [[ ! -e "$HOME/.local/bin/$b" ]] && ln -sf "$dest_root/bin/$b" "$HOME/.local/bin/$b" && record_manifest_entries "path:$HOME/.local/bin/$b"
    fi
  done
  record_manifest_entries "path:$dest_root"
  echo "[step:node] Installed SHA-256 verified Node.js $("$dest_root/bin/node" -v) into $dest_root (zero root APT pollution)."
}

step_base() {
  echo "=== [step:base][profile=${PROFILE}] Installing mandatory sandbox primitives (bwrap, prlimit, socat) on ${DISTRO_PRETTY} (${PKG_MGR}) ==="
  persist_profile_and_env
  configure_pkg_cn_mirror
  pkg_update
  case "$PKG_MGR" in
    apt)
      pkg_install bubblewrap util-linux bash ca-certificates socat procps curl wget gnupg tar unzip xz-utils
      ;;
    dnf)
      pkg_install bubblewrap util-linux bash ca-certificates socat procps-ng curl wget gnupg2 tar unzip xz
      ;;
    pacman)
      pkg_install bubblewrap util-linux bash ca-certificates socat procps-ng curl wget gnupg tar unzip xz
      ;;
    zypper)
      pkg_install bubblewrap util-linux bash ca-certificates socat procps curl wget gpg2 tar unzip xz
      ;;
    apk)
      pkg_install bubblewrap util-linux bash ca-certificates socat procps curl wget gnupg tar unzip xz
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
    record_manifest_entries "path:$HOME/.local/bin/fd"
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
      record_manifest_entries "path:$HOME/.local/bin/bazelisk" "path:$HOME/.local/bin/bazel"
    else
      echo "[step:cli] bazelisk already installed: $(command -v bazelisk)"
    fi
  fi
}

step_node() {
  echo "=== [step:node][profile=${PROFILE}] Resolving shared Node.js runtime / Node 24 Active LTS ==="
  persist_profile_and_env
  ensure_step_prereqs

  # Reuse existing compatible Linux Node (>=22, or >=24 when --upgrade-node) shared with DSH / mise / nvm / distro!
  local need_node="true"
  local shared_info=""
  if shared_info="$(find_shared_wsl_node)"; then
    local shared_path shared_ver shared_major
    IFS=$'\t' read -r shared_path shared_ver shared_major <<< "$shared_info"
    if [[ "$UPGRADE_NODE" == "true" && "$shared_major" -lt 24 ]]; then
      echo "[step:node] Found Node ${shared_ver} at ${shared_path}; upgrading to Node 24 Active LTS (--upgrade-node)..."
    else
      echo "[step:node] Sharing existing Linux Node ${shared_ver} at ${shared_path} (zero duplicate Node install!)."
      need_node="false"
      if [[ "$DRY_RUN" != "true" ]] && ! command -v node >/dev/null 2>&1; then
        mkdir -p "$HOME/.local/bin"
        ln -sf "$shared_path" "$HOME/.local/bin/node"
        record_manifest_entries "path:$HOME/.local/bin/node"
      fi
    fi
  fi

  if [[ "$need_node" == "true" ]]; then
    if [[ "$DRY_RUN" == "true" ]]; then
      echo "[dry-run] Install SHA-256 verified prebuilt Node.js 24 Active LTS into \$HOME/.local/share/dsh-wsl-sandbox/toolchains/node (zero root repo pollution)"
    elif [[ "$PKG_MGR" == "apk" ]]; then
      # Alpine uses musl libc rather than glibc tarballs
      pkg_install nodejs npm
    else
      install_verified_prebuilt_node24
    fi
  fi

  if [[ "$PROFILE" == "core" ]]; then
    echo "[step:node][profile=core] Core profile stops at shared Node / Node.js 24 LTS (skipping mise/pnpm/yarn/bun/eslint)."
    return 0
  fi

  # Standard & Universal: mise + pnpm + yarn (corepack/npm) + bun + typescript + eslint + prettier
  echo "[step:node][profile=${PROFILE}] Installing mise, pnpm, yarn, bun, typescript, eslint, prettier..."
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] Ensure prebuilt mise binary (https://mise.run)"
    echo "[dry-run] Enable corepack (yarn/pnpm) and ensure global npm packages: pnpm yarn typescript eslint prettier"
    echo "[dry-run] Ensure prebuilt bun binary (https://bun.sh/install)"
  else
    export PATH="$HOME/.dsh/runtime/bin:$HOME/.local/share/dsh-wsl-sandbox/toolchains/node/bin:$HOME/.local/share/mise/shims:$HOME/.local/bin:$HOME/.bun/bin:$PATH"
    if ! command -v mise >/dev/null 2>&1; then
      local had_mise_dir="false"
      [[ -d "$HOME/.local/share/mise" ]] && had_mise_dir="true"
      curl -fsSL https://mise.run | sh
      record_manifest_entries "path:$HOME/.local/bin/mise"
      [[ "$had_mise_dir" == "false" ]] && record_manifest_entries "path:$HOME/.local/share/mise"
    fi

    if command -v corepack >/dev/null 2>&1; then
      mkdir -p "$HOME/.local/bin"
      corepack enable --install-directory "$HOME/.local/bin" 2>/dev/null || true
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
      local np
      for np in "${missing_npm_pkgs[@]}"; do
        record_manifest_entries "npm:$np"
      done
    fi

    if ! command -v bun >/dev/null 2>&1; then
      local had_bun="false"
      [[ -d "$HOME/.bun" ]] && had_bun="true"
      curl -fsSL https://bun.sh/install | bash
      [[ "$had_bun" == "false" ]] && record_manifest_entries "path:$HOME/.bun"
    fi
  fi

  # Universal only: multi-version Node 22 & 24 Active LTS prebuilt via mise (default global = node@24 aligned with DSH)
  if [[ "$PROFILE" == "universal" ]]; then
    echo "[step:node][profile=universal] Installing prebuilt Node 22 & 24 LTS via mise..."
    if [[ "$DRY_RUN" == "true" ]]; then
      echo "[dry-run] mise install node@22 node@24 && mise use -g node@24"
    else
      export PATH="$HOME/.local/share/mise/shims:$HOME/.local/bin:$PATH"
      mise install node@22 node@24
      mise use -g node@24
    fi
  fi
}

step_python() {
  echo "=== [step:python][profile=${PROFILE}] Installing Python 3 (binary-only, ZERO pyenv source compilation) ==="
  persist_profile_and_env
  ensure_step_prereqs
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
    record_manifest_entries "path:$HOME/.local/bin/uv" "path:$HOME/.local/bin/uvx"
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
      record_manifest_entries "uv:$t"
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
  ensure_step_prereqs

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
    local had_usr_go="false"
    [[ -d /usr/local/go ]] && had_usr_go="true"
    curl -fsSL "${go_base}/${tarball}" -o "/tmp/${tarball}"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "/tmp/${tarball}"
    rm -f "/tmp/${tarball}"
    [[ "$had_usr_go" == "false" ]] && record_manifest_entries "path:/usr/local/go"
  else
    echo "[step:go] Go already installed: $(go version)"
  fi

  if ! command -v golangci-lint >/dev/null 2>&1; then
    mkdir -p "$HOME/.local/bin"
    curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b "$HOME/.local/bin"
    record_manifest_entries "path:$HOME/.local/bin/golangci-lint"
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
  ensure_step_prereqs

  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] Install Rust minimal profile via rustup (--profile minimal --component rustfmt,clippy)"
    return 0
  fi

  if ! command -v rustc >/dev/null 2>&1; then
    local had_rustup="false" had_cargo="false"
    [[ -d "$HOME/.rustup" ]] && had_rustup="true"
    [[ -d "$HOME/.cargo" ]] && had_cargo="true"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --component rustfmt,clippy
    [[ "$had_rustup" == "false" ]] && record_manifest_entries "path:$HOME/.rustup"
    [[ "$had_cargo" == "false" ]] && record_manifest_entries "path:$HOME/.cargo"
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

# Bounded one-shot setup log (0600 inside 0700 logs/, keeps max 5 setup logs; skipped on --dry-run)
if [[ "$DRY_RUN" != "true" ]]; then
  PROVISION_LOG_DIR="$CONFIG_ROOT/logs"
  mkdir -p "$PROVISION_LOG_DIR"
  chmod 700 "$PROVISION_LOG_DIR"
  PROVISION_LOG_FILE="$PROVISION_LOG_DIR/provision-$(date +%Y%m%d-%H%M%S).log"
  touch "$PROVISION_LOG_FILE"
  chmod 600 "$PROVISION_LOG_FILE"
  # Prune older provision-*.log files beyond the 5 most recent
  ls -1t "$PROVISION_LOG_DIR"/provision-*.log 2>/dev/null | tail -n +6 | xargs -r rm -f 2>/dev/null || true
  exec > >(tee -a "$PROVISION_LOG_FILE") 2>&1
  echo "[log] Saving setup log to $PROVISION_LOG_FILE"
fi

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
