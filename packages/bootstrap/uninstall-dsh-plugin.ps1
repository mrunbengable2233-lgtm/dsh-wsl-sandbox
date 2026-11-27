#Requires -Version 5.1
<#
.SYNOPSIS
  Complete, manifest-driven uninstaller for `dsh-wsl-sandbox` across Windows Host, WSL 2, `AGENTS.md`, and DSH Profiles.

.DESCRIPTION
  Cleanly reverses all 13 installation & runtime artifacts without requiring Node.js on Windows:
    1. Unregisters `dsh-wsl-sandbox` from DSH CLI (`web` & `desktop` profiles).
    2. Removes `<!-- dsh-wsl-sandbox:start/begin --> ... <!-- dsh-wsl-sandbox:end -->` blocks from every
       `AGENTS.md` recorded in `install-manifest.json` (plus optional `-ProjectAgentsMdDir`), deleting
       plugin-created empty `AGENTS.md` files.
    3. Inside WSL 2 (`--cd ~`, zero `/mnt` lock):
       - Restores `/etc/wsl.conf` and `/etc/apt/sources.list.d/*.bak` from pristine backups (unless `-SkipRestoreConfigs`);
       - Strips `.dsh-wsl-env.sh` hooks from `~/.bashrc`, `~/.profile`, `~/.bash_profile`, `~/.zshrc`, and deletes `~/.dsh-wsl-env.sh`;
       - Sweeps `/run/user/<uid>/dsh-wsl-*`, `/dev/shm/dsh-wsl-*`, and `/tmp/dsh-wsl-*` (unlocking `0444` `empty-mask` first);
       - Removes `~/.cache/dsh-wsl-sandbox`, `~/.local/share/dsh-wsl-sandbox`, and `0400`-protected `~/.config/dsh-wsl-sandbox`;
       - With `-PurgeToolchains`: rolls back delta OS packages, `uv` tools, `npm -g` tools, and newly installed toolchain
         paths (`/usr/local/go`, `~/.rustup`, `~/.cargo`, `~/.bun`, `~/.local/share/mise`, legacy NodeSource repo) recorded in `provision-manifest.json`;
       - Removes default `~/workspace` ONLY if completely empty (never deletes user files).
    4. On Windows Host:
       - Unlocks `attrib +R` (`IsReadOnly = $false`) on all backup snapshots and removes `%DSH_HOME%\dsh-wsl-sandbox\`
         (or preserves `backups\*.orig*` when `-KeepBackups` is specified).
#>
[CmdletBinding()]
param(
  [string]$Distro = "",
  [string]$DshHome = "",
  [string[]]$ProjectAgentsMdDir = @(),
  [switch]$PurgeToolchains,
  [switch]$KeepBackups,
  [switch]$SkipRestoreConfigs,
  [switch]$RestoreHostWslConfig,
  [switch]$UnregisterPluginDistro,
  [switch]$DryRun,
  [switch]$Yes
)

$ErrorActionPreference = "Stop"

if (-not $DshHome) {
  $DshHome = if ($env:DSH_HOME) { $env:DSH_HOME } else { Join-Path $HOME ".dsh" }
}
$cfgDir = Join-Path $DshHome "dsh-wsl-sandbox"
$cfgPath = Join-Path $cfgDir "config.json"
$manifestPath = Join-Path $cfgDir "install-manifest.json"
$defaultBackupDir = Join-Path $cfgDir "backups"

$manifest = if (Test-Path -LiteralPath $manifestPath) {
  try { Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $null }
} else { $null }

$cfg = if (Test-Path -LiteralPath $cfgPath) {
  try { Get-Content -LiteralPath $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $null }
} else { $null }

if (-not $Distro) {
  if ($manifest -and $manifest.distro) { $Distro = [string]$manifest.distro }
  elseif ($cfg -and $cfg.distro) { $Distro = [string]$cfg.distro }
}

$linuxUser = if ($manifest -and $manifest.linuxUser) {
  [string]$manifest.linuxUser
} elseif ($cfg -and $cfg.username) {
  [string]$cfg.username
} else {
  ""
}

$workspaceRoot = if ($manifest -and $manifest.workspaceRoot) {
  [string]$manifest.workspaceRoot
} elseif ($cfg -and $cfg.workspaceRoot) {
  [string]$cfg.workspaceRoot
} else {
  ""
}

$createdDefaultWorkspace = if ($manifest -and $null -ne $manifest.createdDefaultWorkspace) {
  [bool]$manifest.createdDefaultWorkspace
} else {
  $false
}

$backupDir = if ($cfg -and $cfg.backupDir) {
  [string]$cfg.backupDir
} elseif ($manifest -and $manifest.backupDir) {
  [string]$manifest.backupDir
} else {
  $defaultBackupDir
}

$agentsMdTargets = New-Object System.Collections.Generic.List[string]
if ($manifest -and $manifest.agentsMdFiles) {
  foreach ($f in $manifest.agentsMdFiles) {
    if ($f -and -not $agentsMdTargets.Contains([string]$f)) { $agentsMdTargets.Add([string]$f) }
  }
}
foreach ($extraDir in $ProjectAgentsMdDir) {
  if (-not $extraDir) { continue }
  $cand = if ($extraDir -imatch 'AGENTS\.md$') { $extraDir } else { Join-Path $extraDir "AGENTS.md" }
  if (-not $agentsMdTargets.Contains($cand)) { $agentsMdTargets.Add($cand) }
}

Write-Host "`n=== dsh-wsl-sandbox Reversible Uninstaller (DryRun=$DryRun, PurgeToolchains=$PurgeToolchains) ===" -ForegroundColor Cyan
Write-Host "Host Config Dir  : $cfgDir (exists=$(Test-Path -LiteralPath $cfgDir))"
Write-Host "Host Backup Dir  : $backupDir (exists=$(Test-Path -LiteralPath $backupDir), KeepBackups=$KeepBackups)"
Write-Host "Target WSL Distro: $(if ($Distro) { $Distro } else { '(none configured)' })"
Write-Host "AGENTS.md Targets: $(if ($agentsMdTargets.Count -gt 0) { $agentsMdTargets -join ', ' } else { '(none recorded)' })"

if (-not $DryRun -and -not $Yes) {
  $promptMsg = if ($PurgeToolchains) {
    "Proceed with full uninstall INCLUDING delta WSL toolchains/packages in '$Distro'? [y/N]"
  } else {
    "Proceed with uninstalling dsh-wsl-sandbox state, caches, runner & configs (keeps existing WSL compilers)? [Y/n]"
  }
  $ans = Read-Host $promptMsg
  if ($PurgeToolchains) {
    if ($ans.Trim() -notmatch '^(?i:y|yes)$') { Write-Host "Aborted."; exit 0 }
  } else {
    if ($ans.Trim() -and $ans.Trim() -notmatch '^(?i:y|yes)$') { Write-Host "Aborted."; exit 0 }
  }
}

# 1. Remove plugin from DSH CLI profiles (`web`, `desktop`, and `headless`) if `dsh` CLI is available
$dshCmd = Get-Command dsh -ErrorAction SilentlyContinue
if ($dshCmd) {
  foreach ($prof in @("web", "desktop", "headless")) {
    if ($DryRun) {
      Write-Host "[dry-run] dsh plugin --profile $prof remove dsh-wsl-sandbox" -ForegroundColor DarkGray
    } else {
      Write-Host "[1/5] Removing dsh-wsl-sandbox from DSH '$prof' profile..." -ForegroundColor Cyan
      $prevEap = $ErrorActionPreference
      $ErrorActionPreference = "Continue"
      try {
        & dsh plugin --profile $prof remove dsh-wsl-sandbox 2>$null | Out-Null
      } catch {
      } finally {
        $ErrorActionPreference = $prevEap
      }
    }
  }
} else {
  Write-Host "[1/5] 'dsh' CLI not on PATH - if using DSH Desktop GUI, also click Remove on 'dsh-wsl-sandbox' in Settings -> Plugins." -ForegroundColor Yellow
}

# 2. Cleanly strip `<!-- dsh-wsl-sandbox:start/begin --> ... <!-- dsh-wsl-sandbox:end -->` from recorded AGENTS.md files
function Remove-AgentsMdSection([string]$FilePath) {
  if (-not (Test-Path -LiteralPath $FilePath)) {
    Write-Host "      [skip] AGENTS.md not found: $FilePath" -ForegroundColor DarkGray
    return
  }
  $raw = Get-Content -LiteralPath $FilePath -Raw -Encoding UTF8
  $pattern = '(?m)[ \t]*<!--\s*dsh-wsl-sandbox:(?:start|begin)\s*-->[\s\S]*?<!--\s*dsh-wsl-sandbox:end\s*-->[ \t]*\r?\n?'
  if ($raw -notmatch $pattern) {
    Write-Host "      [skip] No dsh-wsl-sandbox marker block in: $FilePath" -ForegroundColor DarkGray
    return
  }
  $stripped = ([regex]::Replace($raw, $pattern, '') -replace "(\r?\n){3,}", "`n`n").Trim()
  if ($stripped -eq "" -or $stripped -eq "# Project Agent Instructions") {
    if ($DryRun) {
      Write-Host "[dry-run] Delete plugin-created empty AGENTS.md: $FilePath" -ForegroundColor DarkGray
    } else {
      Remove-Item -Force -LiteralPath $FilePath
      Write-Host "      [ok] Deleted plugin-created empty AGENTS.md: $FilePath" -ForegroundColor Green
    }
  } else {
    if ($DryRun) {
      Write-Host "[dry-run] Strip dsh-wsl-sandbox marker block from: $FilePath" -ForegroundColor DarkGray
    } else {
      $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
      [System.IO.File]::WriteAllText($FilePath, "$stripped`n", $utf8NoBom)
      Write-Host "      [ok] Removed dsh-wsl-sandbox block from: $FilePath" -ForegroundColor Green
    }
  }
}

Write-Host "[2/5] Cleaning AGENTS.md marker blocks..." -ForegroundColor Cyan
foreach ($f in $agentsMdTargets) {
  Remove-AgentsMdSection -FilePath $f
}

# 3. Clean WSL 2 artifacts (via staged provision-wsl.sh --uninstall, with inline POSIX fallback if runner was already deleted)
$wslCleanupOk = $true
if ($Distro) {
  Write-Host "[3/5] Cleaning WSL 2 artifacts inside '$Distro'..." -ForegroundColor Cyan
  $wslFlags = @("--uninstall")
  if ($PurgeToolchains) { $wslFlags += "--purge-toolchains" }
  if ($SkipRestoreConfigs) { $wslFlags += "--skip-restore" }
  if ($DryRun) { $wslFlags += "--dry-run" }
  if ($workspaceRoot) { $wslFlags += @("--workspace-root", $workspaceRoot) }
  if ($createdDefaultWorkspace) { $wslFlags += "--created-default-workspace" }

  $inlineFallbackSh = @'
PROV="$HOME/.local/share/dsh-wsl-sandbox/runner/packages/bootstrap/provision-wsl.sh"
if [ -f "$PROV" ]; then
  exec bash "$PROV" "$@"
fi
DRY="false"
WS_ROOT=""
CREATED_WS="false"
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY="true"; shift ;;
    --workspace-root) WS_ROOT="$2"; shift 2 ;;
    --created-default-workspace) CREATED_WS="true"; shift ;;
    *) shift ;;
  esac
done
for rc in "$HOME/.bashrc" "$HOME/.profile" "$HOME/.bash_profile" "$HOME/.zshrc"; do
  if [ -f "$rc" ] && [ ! -L "$rc" ] && [ -w "$rc" ] && grep -Fq '.dsh-wsl-env.sh' "$rc"; then
    if [ "$DRY" = "true" ]; then echo "[dry-run] Strip hook from $rc"; else
      tmp="$(mktemp)"; grep -Fv '.dsh-wsl-env.sh' "$rc" > "$tmp" || true; cat "$tmp" > "$rc"; rm -f "$tmp"
    fi
  fi
done
TARGET_WS="${WS_ROOT:-$HOME/workspace}"
if [ "$DRY" = "true" ]; then
  echo "[dry-run] Remove ~/.dsh-wsl-env.sh, /tmp|/dev/shm|/run/user dsh-wsl-*, ~/.cache/dsh-wsl-sandbox, ~/.local/share/dsh-wsl-sandbox, ~/.config/dsh-wsl-sandbox, and empty $TARGET_WS"
else
  rm -f "$HOME/.dsh-wsl-env.sh"
  for tb in "/run/user/$(id -u)" "/dev/shm" "/tmp"; do
    [ -d "$tb" ] || continue
    for d in "$tb"/dsh-wsl-runner-* "$tb"/dsh-wsl-proxy-*; do
      [ -e "$d" ] || continue
      chmod -R u+w "$d" 2>/dev/null || true
      rm -rf "$d" 2>/dev/null || true
    done
  done
  for pd in "$HOME/.cache/dsh-wsl-sandbox" "$HOME/.local/share/dsh-wsl-sandbox" "$HOME/.config/dsh-wsl-sandbox"; do
    if [ -e "$pd" ]; then chmod -R u+w "$pd" 2>/dev/null || true; rm -rf "$pd"; fi
  done
  if [ "$CREATED_WS" = "true" ] || [ "$TARGET_WS" = "$HOME/workspace" ]; then
    [ -d "$TARGET_WS" ] && rmdir "$TARGET_WS" 2>/dev/null || true
  fi
fi
'@ -replace "`r`n", "`n"

  $wslArgs = @("-d", $Distro, "--cd", "~")
  if ($linuxUser -and $linuxUser -match '^[a-z_][a-z0-9_.-]{0,31}$') {
    $wslArgs += @("-u", $linuxUser)
  }
  $wslArgs += @("--", "sh", "-c", $inlineFallbackSh, "dsh-uninstall")
  $wslArgs += $wslFlags

  $prevEap = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    & wsl.exe @wslArgs
    if ($LASTEXITCODE -ne 0) {
      $wslCleanupOk = $false
      Write-Warning "WSL-side uninstall inside '$Distro' exited with code $LASTEXITCODE; preserving host backups so manual restore remains possible."
    }
  } catch {
    $wslCleanupOk = $false
    Write-Warning "Could not reach WSL distro '$Distro' ($($_.Exception.Message)); preserving host backups."
  } finally {
    $ErrorActionPreference = $prevEap
  }
} else {
  Write-Host "[3/5] No WSL distro recorded; skipping WSL-side cleanup." -ForegroundColor Yellow
}

# 4. Optional host %USERPROFILE%\.wslconfig restore + read-only attribute unlock & host directory removal
$wslConfigHostPath = Join-Path $HOME ".wslconfig"
$origWslConfigBackup = Join-Path $backupDir ".wslconfig.orig"
$absentWslConfigMarker = Join-Path $backupDir ".wslconfig.orig.absent"

if ($RestoreHostWslConfig -and -not $SkipRestoreConfigs) {
  if (Test-Path -LiteralPath $origWslConfigBackup) {
    if ($DryRun) {
      Write-Host "[dry-run] Restore $wslConfigHostPath from $origWslConfigBackup" -ForegroundColor DarkGray
    } else {
      $prevEap = $ErrorActionPreference
      $ErrorActionPreference = "Continue"
      try {
        if (Test-Path -LiteralPath $wslConfigHostPath) {
          & attrib.exe -R $wslConfigHostPath 2>$null | Out-Null
        }
        Copy-Item -Force -LiteralPath $origWslConfigBackup -Destination $wslConfigHostPath
        & attrib.exe -R $wslConfigHostPath 2>$null | Out-Null
      } finally {
        $ErrorActionPreference = $prevEap
      }
      Write-Host "[4/5] Restored $wslConfigHostPath from $origWslConfigBackup" -ForegroundColor Green
    }
  } elseif (Test-Path -LiteralPath $absentWslConfigMarker) {
    if (Test-Path -LiteralPath $wslConfigHostPath) {
      if ($DryRun) {
        Write-Host "[dry-run] Remove $wslConfigHostPath (host had no .wslconfig at initial snapshot)" -ForegroundColor DarkGray
      } else {
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
          & attrib.exe -R $wslConfigHostPath 2>$null | Out-Null
        } finally {
          $ErrorActionPreference = $prevEap
        }
        Remove-Item -Force -LiteralPath $wslConfigHostPath
        Write-Host "[4/5] Removed $wslConfigHostPath (host originally had no .wslconfig)" -ForegroundColor Green
      }
    }
  }
}

function Remove-ReadOnlyTree([string]$TargetDir) {
  if (-not (Test-Path -LiteralPath $TargetDir)) { return }
  if ($DryRun) {
    Write-Host "[dry-run] Clear ReadOnly attributes & remove directory: $TargetDir" -ForegroundColor DarkGray
    return
  }
  Get-ChildItem -LiteralPath $TargetDir -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
    try {
      if ($_.Attributes -band [System.IO.FileAttributes]::ReadOnly) {
        $_.Attributes = $_.Attributes -bxor [System.IO.FileAttributes]::ReadOnly
      }
    } catch {}
  }
  Remove-Item -LiteralPath $TargetDir -Recurse -Force -ErrorAction SilentlyContinue
  Write-Host "      [ok] Removed $TargetDir" -ForegroundColor Green
}

Write-Host "[4/5] Removing Windows host plugin state & backups..." -ForegroundColor Cyan
if ($KeepBackups -or (-not $wslCleanupOk)) {
  foreach ($sub in @("config.json", "install-manifest.json", "logs")) {
    $subPath = Join-Path $cfgDir $sub
    if (Test-Path -LiteralPath $subPath) {
      if ($DryRun) {
        Write-Host "[dry-run] Remove $subPath (preserving backups in $backupDir)" -ForegroundColor DarkGray
      } else {
        Remove-ReadOnlyTree -TargetDir $subPath
      }
    }
  }
  Write-Host "      [keep] Preserved backup snapshots under: $backupDir" -ForegroundColor Yellow
} else {
  if ($backupDir -ne $defaultBackupDir -and (Test-Path -LiteralPath $backupDir)) {
    Remove-ReadOnlyTree -TargetDir $backupDir
  }
  Remove-ReadOnlyTree -TargetDir $cfgDir
}

# 5. Optional plugin-installed WSL distro check (NEVER silently unregister a VM!)
$pluginInstalledDistro = if ($manifest -and $manifest.installedDistroByPlugin) { [string]$manifest.installedDistroByPlugin } else { "" }
if ($pluginInstalledDistro) {
  if ($UnregisterPluginDistro) {
    if ($DryRun) {
      Write-Host "[dry-run] wsl.exe --unregister $pluginInstalledDistro" -ForegroundColor DarkGray
    } else {
      Write-Warning "[5/5] Unregistering WSL distro '$pluginInstalledDistro' (recorded as installed by dsh-wsl-sandbox)..."
      & wsl.exe --unregister $pluginInstalledDistro
    }
  } else {
    Write-Host "[5/5] Note: WSL distro '$pluginInstalledDistro' was originally installed via install-dsh-plugin.ps1 and was preserved to protect any personal files inside it." -ForegroundColor Yellow
    Write-Host "      If you want to delete the entire '$pluginInstalledDistro' VM too, run: wsl.exe --unregister $pluginInstalledDistro"
  }
} else {
  Write-Host "[5/5] Preserved existing WSL 2 distribution '$Distro'." -ForegroundColor Green
}

Write-Host "`nDone! dsh-wsl-sandbox uninstall finished cleanly." -ForegroundColor Green
