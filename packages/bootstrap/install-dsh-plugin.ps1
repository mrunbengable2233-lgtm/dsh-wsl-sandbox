<#
.SYNOPSIS
  Install, stage, and optionally provision dsh-wsl-sandbox into DeepSeek Harness (DSH) on Windows.

  Key guarantees:
  - Zero hardcoded distro/user/path: dynamically discovers installed WSL 2 distros via `wsl.exe -l -v`
    AND read-only `HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss\*` (fully supports WSL Manager
    imported / moved VHDX instances even when absent from Windows Explorer's left "Linux" sidebar).
  - Default new-distro suggestion uses modern `Ubuntu-26.04` plus selectable alternatives
    (`Ubuntu-24.04`, `Debian`, `FedoraLinux-42`, `Arch`, `kali-linux`, or custom).
  - Stages the compiled runner & provision script directly into native WSL ext4
    (`$HOME/.local/share/dsh-wsl-sandbox/runner/`) via binary tar stream: ZERO `/mnt/c` dependency
    and ZERO Windows NTFS folder handle lock when disabling/uninstalling the plugin.
  - Locks private config/backup folders with owner-only ACLs (`icacls /inheritance:r`) and read-only
    backup snapshots (`attrib +R`), NEVER auto-mutates `%USERPROFILE%\.wslconfig` or `/etc/wsl.conf`
    (shared with Windows WSL Settings & WSL Manager), and NEVER recommends `wsl.exe --shutdown`.

.EXAMPLE
  .\install-dsh-plugin.ps1 -Provision -Profile standard -Mirror cn -UpsertAgentsMd

.EXAMPLE
  .\install-dsh-plugin.ps1 -Distro MyMovedDebian -Profile core

.EXAMPLE
  .\install-dsh-plugin.ps1 -BackupOnly -BackupDir D:\Backups\WSL-Orig -OpenBackupFolder

.EXAMPLE
  .\install-dsh-plugin.ps1 -Distro Ubuntu-26.04 -RestoreWslConfig
#>

[CmdletBinding()]
param(
  [string]$Distro = "",
  [string]$WorkspaceRoot = "",
  [ValidateSet("", "core", "standard", "universal")]
  [string]$Profile = "",
  [ValidateSet("global", "cn")]
  [string]$Mirror = "global",
  [string]$Proxy = "",
  [string]$DshHome = $(if ($env:DSH_HOME) { $env:DSH_HOME } else { Join-Path $HOME ".dsh" }),
  [string]$BackupDir = "",
  [string]$PluginRepoPath = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path,
  [switch]$Provision,
  [switch]$UpdateConfig,
  [switch]$NonInteractive,
  [switch]$UpsertAgentsMd,
  [switch]$BackupOnly,
  [switch]$OpenBackupFolder,
  [switch]$RestoreWslConfig,
  [string]$ProjectAgentsMdDir = (Get-Location).Path
)

$ErrorActionPreference = "Stop"

function Set-PrivateOwnerAcl {
  param(
    [Parameter(Mandatory = $true)][string]$TargetPath,
    [switch]$IsDirectory,
    [switch]$ReadOnlyFile
  )
  if (-not (Test-Path -LiteralPath $TargetPath)) { return }
  try {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    if ($IsDirectory) {
      & icacls.exe $TargetPath /inheritance:r /grant:r "${currentUser}:(OI)(CI)F" "SYSTEM:(OI)(CI)F" 2>$null | Out-Null
    } else {
      & icacls.exe $TargetPath /inheritance:r /grant:r "${currentUser}:F" "SYSTEM:F" 2>$null | Out-Null
      if ($ReadOnlyFile) {
        & attrib.exe +R $TargetPath 2>$null | Out-Null
      }
    }
  } catch {
    Write-Warning "Could not tighten ACL on $TargetPath : $_"
  }
}

function Get-LxssRegistryDistros {
  $map = @{}
  $lxssRoot = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss"
  if (-not (Test-Path $lxssRoot)) { return $map }
  foreach ($sub in Get-ChildItem -Path $lxssRoot -ErrorAction SilentlyContinue) {
    try {
      $props = Get-ItemProperty -Path $sub.PSPath -ErrorAction SilentlyContinue
      if ($props.DistributionName) {
        $bp = [string]$props.BasePath
        if ($bp.StartsWith("\\?\")) { $bp = $bp.Substring(4) }
        $defaultPkgRoot = Join-Path $env:LOCALAPPDATA "Packages"
        $isCustomMoved = ($bp -ne "") -and (-not $bp.StartsWith($defaultPkgRoot, [System.StringComparison]::OrdinalIgnoreCase))
        $map[$props.DistributionName] = [pscustomobject]@{
          Name          = [string]$props.DistributionName
          BasePath      = $bp
          Version       = [int]($props.Version)
          DefaultUid    = [int]($props.DefaultUid)
          IsCustomMoved = $isCustomMoved
        }
      }
    } catch { }
  }
  return $map
}

function Get-InstalledWslDistros {
  $lxssMap = Get-LxssRegistryDistros
  $results = @()
  $prevEnc = [Console]::OutputEncoding
  try {
    [Console]::OutputEncoding = [System.Text.Encoding]::Unicode
    $rawLines = & wsl.exe -l -v 2>$null
  } catch {
    $rawLines = @()
  } finally {
    [Console]::OutputEncoding = $prevEnc
  }

  $internalPattern = '^(docker-desktop|docker-desktop-data|rancher-desktop|rancher-desktop-data|podman-machine)'
  foreach ($line in $rawLines) {
    $clean = ([string]$line -replace "`0", "").TrimEnd()
    if (-not $clean.Trim()) { continue }
    if ($clean -match '^\s*\*?\s*(NAME|名称)\s+') { continue }
    if ($clean -match '^\s*(\*)?\s*(.+?)\s{2,}([A-Za-z]+)\s+(\d+)\s*$') {
      $isDef = $Matches[1] -eq "*"
      $name = $Matches[2].Trim()
      $state = $Matches[3].Trim()
      $ver = [int]$Matches[4]
      $isInternal = $name -imatch $internalPattern
      $reg = if ($lxssMap.ContainsKey($name)) { $lxssMap[$name] } else { $null }
      $results += [pscustomobject]@{
        Name          = $name
        State         = $state
        Version       = $ver
        IsDefault     = $isDef
        IsInternal    = $isInternal
        BasePath      = if ($reg) { $reg.BasePath } else { "" }
        IsCustomMoved = if ($reg) { $reg.IsCustomMoved } else { $false }
      }
    }
  }

  # Fallback: if wsl.exe -l -v returned nothing parseable, use Lxss registry directly
  if ($results.Count -eq 0 -and $lxssMap.Count -gt 0) {
    foreach ($entry in $lxssMap.Values) {
      $results += [pscustomobject]@{
        Name          = $entry.Name
        State         = "Unknown"
        Version       = if ($entry.Version -gt 0) { $entry.Version } else { 2 }
        IsDefault     = $false
        IsInternal    = $entry.Name -imatch $internalPattern
        BasePath      = $entry.BasePath
        IsCustomMoved = $entry.IsCustomMoved
      }
    }
  }
  return $results
}

function Assert-SafeBackupDir {
  param(
    [Parameter(Mandatory = $true)][string]$CandidateDir,
    [Parameter(Mandatory = $true)][string]$DshHomeDir,
    [Parameter(Mandatory = $true)][string]$CfgDir,
    [array]$AllDistros
  )
  $resolved = [System.IO.Path]::GetFullPath($CandidateDir).TrimEnd('\', '/')
  $homeResolved = [System.IO.Path]::GetFullPath($HOME).TrimEnd('\', '/')
  $dshResolved = [System.IO.Path]::GetFullPath($DshHomeDir).TrimEnd('\', '/')
  $cfgResolved = [System.IO.Path]::GetFullPath($CfgDir).TrimEnd('\', '/')

  if ($resolved -ieq $homeResolved -or $resolved -ieq $dshResolved -or $resolved -ieq $cfgResolved) {
    throw "Refusing to use live profile or config root as BackupDir: $resolved (choose a dedicated subfolder)."
  }
  if ($resolved -match '(?i)[\\/](?:\.ssh|\.gnupg|\.aws|\.kube|AppData[\\/]Local[\\/]Packages|AppData[\\/]Local[\\/]wsl)(?:[\\/]|$)') {
    throw "Refusing to write backups into credential or WSL VHDX storage directory: $resolved"
  }
  foreach ($d in $AllDistros) {
    if ($d.BasePath) {
      $bp = [System.IO.Path]::GetFullPath($d.BasePath).TrimEnd('\', '/')
      if ($resolved -ieq $bp -or $resolved.StartsWith("$bp\", [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to write backups inside WSL distro '$($d.Name)' VHDX BasePath ($bp)."
      }
    }
  }
  return $resolved
}

$cfgDir = Join-Path $DshHome "dsh-wsl-sandbox"
New-Item -ItemType Directory -Force -Path $cfgDir | Out-Null
Set-PrivateOwnerAcl -TargetPath $cfgDir -IsDirectory

$allDistros = @(Get-InstalledWslDistros)
$usableWsl2 = @($allDistros | Where-Object { -not $_.IsInternal -and $_.Version -eq 2 })

$rawBackupDir = if ($BackupDir -and $BackupDir.Trim() -ne "") { $BackupDir.Trim() } else { Join-Path $cfgDir "backups" }
$backupDir = Assert-SafeBackupDir -CandidateDir $rawBackupDir -DshHomeDir $DshHome -CfgDir $cfgDir -AllDistros $allDistros
New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
Set-PrivateOwnerAcl -TargetPath $backupDir -IsDirectory

# Resolve target WSL 2 distro dynamically (NEVER hardcoded to Ubuntu-24.04)
if (-not $Distro -or $Distro.Trim() -eq "") {
  if ($usableWsl2.Count -eq 0) {
    Write-Host "`n[INFO] No usable WSL 2 Linux distributions are currently installed." -ForegroundColor Yellow
    Write-Host "Recommended official distributions you can install (zero Docker, ~300MB rootfs):"
    Write-Host "  1) Ubuntu-26.04  (Recommended default Ubuntu LTS)"
    Write-Host "  2) Ubuntu-24.04"
    Write-Host "  3) Debian"
    Write-Host "  4) FedoraLinux-42"
    Write-Host "  5) Arch"
    Write-Host "  6) kali-linux"
    if ($NonInteractive) {
      throw "No WSL 2 distribution found. Install one first, e.g.: wsl.exe --install -d Ubuntu-26.04 (or Debian / FedoraLinux-42 / Arch), then re-run."
    }
    $choice = Read-Host "Choose a distro to install now [1-6, custom name, or press Enter to exit and install manually]"
    $selectedNew = switch ($choice.Trim()) {
      ""  { "" }
      "1" { "Ubuntu-26.04" }
      "2" { "Ubuntu-24.04" }
      "3" { "Debian" }
      "4" { "FedoraLinux-42" }
      "5" { "Arch" }
      "6" { "kali-linux" }
      default { $choice.Trim() }
    }
    if (-not $selectedNew) {
      Write-Host "Run 'wsl.exe --list --online' to inspect available distros, then 'wsl.exe --install -d Ubuntu-26.04' (or any distro you prefer)."
      exit 0
    }
    Write-Host "Installing official WSL 2 distro '$selectedNew'..." -ForegroundColor Cyan
    & wsl.exe --install -d $selectedNew
    Write-Host "After completing initial Linux non-root user creation in '$selectedNew', re-run this installer with -Distro $selectedNew." -ForegroundColor Green
    exit 0
  } elseif ($usableWsl2.Count -eq 1 -or $NonInteractive) {
    $picked = $usableWsl2 | Where-Object { $_.IsDefault } | Select-Object -First 1
    if (-not $picked) { $picked = $usableWsl2[0] }
    $Distro = $picked.Name
  } else {
    Write-Host "`nDiscovered WSL 2 distributions (including WSL Manager / imported instances):" -ForegroundColor Cyan
    $defaultIdx = 0
    for ($i = 0; $i -lt $usableWsl2.Count; $i++) {
      $d = $usableWsl2[$i]
      if ($d.IsDefault) { $defaultIdx = $i }
      $defTag = if ($d.IsDefault) { " [default]" } else { "" }
      $movedTag = if ($d.IsCustomMoved) { " [custom/WSL-Manager VHDX: $($d.BasePath)]" } elseif ($d.BasePath) { " [$($d.BasePath)]" } else { "" }
      Write-Host ("  {0}) {1} (WSL {2}, {3}){4}{5}" -f ($i + 1), $d.Name, $d.Version, $d.State, $defTag, $movedTag)
    }
    $ans = Read-Host ("Select WSL 2 distro [1-{0}] (Enter = {1}: {2})" -f $usableWsl2.Count, ($defaultIdx + 1), $usableWsl2[$defaultIdx].Name)
    if (-not $ans.Trim()) {
      $Distro = $usableWsl2[$defaultIdx].Name
    } elseif ($ans.Trim() -match '^\d+$' -and [int]$ans.Trim() -ge 1 -and [int]$ans.Trim() -le $usableWsl2.Count) {
      $Distro = $usableWsl2[[int]$ans.Trim() - 1].Name
    } else {
      $Distro = $ans.Trim()
    }
  }
}

$matchedDistro = $allDistros | Where-Object { $_.Name -ieq $Distro } | Select-Object -First 1
if ($matchedDistro) {
  $Distro = $matchedDistro.Name
  if ($matchedDistro.Version -ne 2) {
    throw "WSL distro '$Distro' is WSL $($matchedDistro.Version). dsh-wsl-sandbox requires WSL 2 (real Linux kernel namespaces + seccomp). Convert via: wsl.exe --set-version $Distro 2"
  }
} else {
  Write-Warning "Distro '$Distro' was not listed in wsl.exe -l -v; attempting direct probe..."
}

$wslConfigHostPath = Join-Path $HOME ".wslconfig"
$origWslConfigBackup = Join-Path $backupDir ".wslconfig.orig"
$absentWslConfigMarker = Join-Path $backupDir ".wslconfig.orig.absent"
$origDistroConfBackup = Join-Path $backupDir "wsl.conf.$Distro.orig"
$ts = Get-Date -Format "yyyyMMdd-HHmmss"

if ($RestoreWslConfig) {
  Write-Host "=== Restoring Original Windows .wslconfig & WSL /etc/wsl.conf ===" -ForegroundColor Cyan
  Write-Host "[note] %USERPROFILE%\.wslconfig and /etc/wsl.conf are shared with Windows WSL Settings & WSL Manager." -ForegroundColor Yellow
  if (Test-Path -LiteralPath $origWslConfigBackup) {
    Copy-Item -Force -LiteralPath $origWslConfigBackup -Destination $wslConfigHostPath
    Write-Host "[ok] Restored $wslConfigHostPath from $origWslConfigBackup" -ForegroundColor Green
  } elseif (Test-Path -LiteralPath $absentWslConfigMarker) {
    if (Test-Path -LiteralPath $wslConfigHostPath) { Remove-Item -Force -LiteralPath $wslConfigHostPath }
    Write-Host "[ok] Removed $wslConfigHostPath (host originally had no .wslconfig)" -ForegroundColor Green
  } else {
    Write-Host "[info] No host .wslconfig backup marker found under $backupDir" -ForegroundColor Yellow
  }
  Write-Host "Next: Inside WSL ($Distro), run 'bash ~/.local/share/dsh-wsl-sandbox/runner/packages/bootstrap/provision-wsl.sh --restore-configs'"
  Write-Host "      Then apply ONLY to this distro via: wsl.exe --terminate $Distro  (do NOT use wsl.exe --shutdown)."
  exit 0
}

# Resolve Environment Profile (core / standard / universal)
if (-not $Profile -or $Profile.Trim() -eq "") {
  if ($NonInteractive -or $BackupOnly) {
    $Profile = "standard"
  } else {
    Write-Host "`nChoose Codex-aligned WSL 2 toolchain profile (binary-only, zero Docker, zero kernel build):" -ForegroundColor Cyan
    Write-Host "  1) core      (~350MB, ~2 min) : sandbox base (bwrap/socat/prlimit) + Codex CLI + C/C++ base + python3 + Node 22"
    Write-Host "  2) standard  (~1.2GB, default): core + ccache/proto + mise + uv + pytest/ruff/mypy/pyright/black + pnpm/yarn/bun/ts/eslint/prettier + Go + golangci-lint + Rust minimal"
    Write-Host "  3) universal (~3.5GB)         : standard + clang/bazelisk + mise Node 20/22/24 + poetry/isort + OpenJDK 21/maven/gradle/ruby/php"
    $pAns = Read-Host "Select profile [1=core, 2=standard, 3=universal] (Enter = 2 standard)"
    $Profile = switch ($pAns.Trim()) {
      "1" { "core" }
      "core" { "core" }
      "3" { "universal" }
      "universal" { "universal" }
      default { "standard" }
    }
  }
}

Write-Host "`n=== dsh-wsl-sandbox Windows Installer (Multi-Distro + WSL Manager Safe + Zero NTFS Lock) ===" -ForegroundColor Cyan
Write-Host "Plugin repo  : $PluginRepoPath"
Write-Host "DSH_HOME     : $DshHome"
Write-Host "Backup dir   : $backupDir (owner-only ACL, read-only snapshots)"
Write-Host "WSL 2 Distro : $Distro"
if ($matchedDistro -and $matchedDistro.IsCustomMoved) {
  Write-Host "VHDX Path    : $($matchedDistro.BasePath) (custom/WSL-Manager location detected; zero Explorer or /mnt dependency!)" -ForegroundColor Green
}
Write-Host "Profile      : $Profile (mirror=$Mirror)"
Write-Host "[note] Windows WSL Settings and WSL Manager share %USERPROFILE%\.wslconfig and /etc/wsl.conf; this installer NEVER auto-edits either file." -ForegroundColor DarkGray

# 0. Non-destructive read-only backup of original Windows %USERPROFILE%\.wslconfig and WSL /etc/wsl.conf
if (Test-Path -LiteralPath $wslConfigHostPath) {
  if (-not (Test-Path -LiteralPath $origWslConfigBackup) -and -not (Test-Path -LiteralPath $absentWslConfigMarker)) {
    Copy-Item -LiteralPath $wslConfigHostPath -Destination $origWslConfigBackup -Force
    Set-PrivateOwnerAcl -TargetPath $origWslConfigBackup -ReadOnlyFile
    Write-Host "[0/5] Backed up original .wslconfig (read-only) -> $origWslConfigBackup" -ForegroundColor Green
  }
  $tsHostBak = Join-Path $backupDir ".wslconfig.$ts.bak"
  Copy-Item -LiteralPath $wslConfigHostPath -Destination $tsHostBak -Force
  Set-PrivateOwnerAcl -TargetPath $tsHostBak -ReadOnlyFile
} else {
  if (-not (Test-Path -LiteralPath $origWslConfigBackup) -and -not (Test-Path -LiteralPath $absentWslConfigMarker)) {
    Set-Content -LiteralPath $absentWslConfigMarker -Value "# Host had no %USERPROFILE%\.wslconfig at initial backup ($ts)`n# Shared by Windows WSL Settings & WSL Manager." -Encoding UTF8
    Set-PrivateOwnerAcl -TargetPath $absentWslConfigMarker -ReadOnlyFile
    Write-Host "[0/5] Recorded clean state (no prior %USERPROFILE%\.wslconfig) -> $absentWslConfigMarker" -ForegroundColor Green
  }
}

try {
  $distroWslConf = & wsl.exe -d $Distro --cd ~ -- sh -c "if [ -f /etc/wsl.conf ]; then cat /etc/wsl.conf; else echo '__ABSENT__'; fi" 2>$null
  if ($LASTEXITCODE -eq 0 -and $distroWslConf) {
    $joined = ($distroWslConf -join "`n").Trim()
    if ($joined -ne "__ABSENT__" -and -not (Test-Path -LiteralPath $origDistroConfBackup)) {
      Set-Content -LiteralPath $origDistroConfBackup -Value $joined -Encoding UTF8
      Set-PrivateOwnerAcl -TargetPath $origDistroConfBackup -ReadOnlyFile
      Write-Host "[0/5] Backed up WSL ($Distro) /etc/wsl.conf (read-only) -> $origDistroConfBackup" -ForegroundColor Green
    }
  }
} catch {
  Write-Host "[0/5] Could not snapshot WSL ($Distro) /etc/wsl.conf yet; provision-wsl.sh will back it up inside WSL." -ForegroundColor Yellow
}

if ($OpenBackupFolder) {
  Start-Process "explorer.exe" -ArgumentList @($backupDir)
}

if ($BackupOnly) {
  Write-Host "`nBackup complete (read-only snapshots) under: $backupDir" -ForegroundColor Green
  exit 0
}

# 1. Probe real non-root Linux user & $HOME inside target WSL 2 distro (using --cd ~ so Windows NTFS is NEVER locked)
$probeLine = (& wsl.exe -d $Distro --cd ~ -- sh -c 'printf "%s\t%s\t%s\n" "$(id -u)" "$(id -un)" "$HOME"').Trim()
if ($LASTEXITCODE -ne 0 -or -not $probeLine) {
  throw "Failed to probe default Linux user inside WSL 2 distro '$Distro'. Ensure the distro is initialized."
}
$parts = $probeLine -split "`t"
if ($parts.Length -lt 3) {
  throw "Unexpected user probe output from '$Distro': $probeLine"
}
$linuxUid = [int]$parts[0]
$linuxUser = $parts[1].Trim()
$linuxHome = $parts[2].Trim()
if ($linuxUid -eq 0) {
  throw "WSL distro '$Distro' default user is root (UID 0). Configure a non-root default user first; dsh-wsl-sandbox blocks UID 0."
}
if (-not $WorkspaceRoot -or $WorkspaceRoot.Trim() -eq "") {
  $WorkspaceRoot = "$linuxHome/workspace"
}
Write-Host "[1/5] Probed WSL user: $linuxUser (uid=$linuxUid, home=$linuxHome) -> workspaceRoot=$WorkspaceRoot" -ForegroundColor Green

# Ensure native ext4 workspace directory exists without touching /mnt
& wsl.exe -d $Distro --cd ~ -- sh -c 'mkdir -p "$1"' -- $WorkspaceRoot | Out-Null

# 2. Verify Node 22+, build dist/, and stage runner + provision-wsl.sh into native WSL ext4
$nodeVersion = & node -v
Write-Host "[2/5] Host Node.js: $nodeVersion — building dist/ & staging into native WSL ext4..."
Push-Location $PluginRepoPath
try {
  & node scripts/build.mjs
  $stagedJson = & node scripts/stage-wsl-runner.mjs --distro $Distro --json
  $staged = $stagedJson | ConvertFrom-Json
} finally {
  Pop-Location
}
Write-Host "      Staged $($staged.fileCount) files into native ext4: $($staged.runnerPath) (zero /mnt lock!)" -ForegroundColor Green

# 3. Write or update human-only config.json under $DSH_HOME\dsh-wsl-sandbox\config.json (owner-only ACL)
$cfgPath = Join-Path $cfgDir "config.json"
if (-not (Test-Path -LiteralPath $cfgPath)) {
  $cfg = [ordered]@{
    revision = "rev-1"
    enabled = $true
    transportMode = "wsl"
    distro = $Distro
    username = $linuxUser
    workspaceRoot = $WorkspaceRoot
    runnerPath = $staged.runnerPath
    environmentProfile = $Profile
    sandboxMode = "workspace-write"
    approvalPolicyMode = "balanced"
    networkMode = "allowlist-proxy"
    upstreamProxy = $Proxy
    mirrorCn = ($Mirror -eq "cn")
    cacheMode = "workspace-persistent"
    approvalTimeoutMs = 60000
    enablePwshGuard = $true
    enablePromptInjection = $true
    unmaskedEnvWorkspaces = @()
    backupDir = $backupDir
    advanced = [ordered]@{
      shares = @()
      deviceNodes = @()
      localLabCidrs = @()
      localLabPorts = @()
      customAllowedDomains = @()
    }
  }
  $cfg | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $cfgPath -Encoding UTF8
  Set-PrivateOwnerAcl -TargetPath $cfgPath
  Write-Host "[3/5] Created owner-only config: $cfgPath (profile=$Profile)" -ForegroundColor Green
} else {
  if ($UpdateConfig -or $Provision) {
    $existing = Get-Content -LiteralPath $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $existing | Add-Member -NotePropertyName distro -NotePropertyValue $Distro -Force
    $existing | Add-Member -NotePropertyName username -NotePropertyValue $linuxUser -Force
    $existing | Add-Member -NotePropertyName workspaceRoot -NotePropertyValue $WorkspaceRoot -Force
    $existing | Add-Member -NotePropertyName runnerPath -NotePropertyValue $staged.runnerPath -Force
    $existing | Add-Member -NotePropertyName environmentProfile -NotePropertyValue $Profile -Force
    $existing | Add-Member -NotePropertyName mirrorCn -NotePropertyValue ($Mirror -eq "cn") -Force
    if ($Proxy) { $existing | Add-Member -NotePropertyName upstreamProxy -NotePropertyValue $Proxy -Force }
    $existing | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $cfgPath -Encoding UTF8
    Set-PrivateOwnerAcl -TargetPath $cfgPath
    Write-Host "[3/5] Updated existing config with distro=$Distro, profile=$Profile, native ext4 runnerPath." -ForegroundColor Green
  } else {
    Write-Host "[3/5] Existing config preserved: $cfgPath (pass -UpdateConfig to overwrite distro/profile/runnerPath)" -ForegroundColor Yellow
  }
}

# 4. Provision WSL 2 toolchain inside chosen distro with selected profile (when -Provision is set or confirmed)
$doProvision = [bool]$Provision
if (-not $doProvision -and -not $NonInteractive) {
  $runProv = Read-Host "Run provision-wsl.sh inside '$Distro' now with --profile $Profile --mirror $Mirror? [y/N]"
  if ($runProv -match '^(y|yes)$') { $doProvision = $true }
}

if ($doProvision) {
  Write-Host "[4/5] Provisioning '$Distro' with profile='$Profile', mirror='$Mirror'..." -ForegroundColor Cyan
  $provArgs = @("-d", $Distro, "--cd", "~", "--", "bash", $staged.provisionScriptPath, "--profile", $Profile, "--mirror", $Mirror)
  if ($Proxy) { $provArgs += @("--proxy", $Proxy) }
  & wsl.exe @provArgs
  if ($LASTEXITCODE -ne 0) {
    throw "provision-wsl.sh exited with code $LASTEXITCODE inside '$Distro'"
  }
  Write-Host "      Running dsh-wsl-doctor --profile $Profile inside '$Distro'..." -ForegroundColor Cyan
  & wsl.exe -d $Distro --cd ~ -- bash -lc "node '$($staged.doctorPath)' --strict-wsl2 --profile '$Profile'"
} else {
  Write-Host "[4/5] Provisioning skipped for now. Run anytime without /mnt dependency:" -ForegroundColor Yellow
  Write-Host "      wsl.exe -d $Distro --cd ~ -- bash `"$($staged.provisionScriptPath)`" --profile $Profile --mirror $Mirror"
}

# 5. DSH CLI / Desktop registration hint & optional AGENTS.md upsert
$dshCmd = Get-Command dsh -ErrorAction SilentlyContinue
if ($dshCmd) {
  Write-Host "[5/5] Detected DSH CLI. Register plugin cleanly:" -ForegroundColor Cyan
  Write-Host "      CLI/Web : dsh plugin --profile web add `"$PluginRepoPath`""
  Write-Host "      Desktop : dsh plugin --profile desktop add `"$PluginRepoPath`""
} else {
  Write-Host "[5/5] 'dsh' CLI not on PATH (Desktop-only install?)." -ForegroundColor Yellow
  Write-Host "      Import '$PluginRepoPath' (or dsh-wsl-sandbox-0.1.0.tgz) in DSH Desktop Plugin Settings."
}

if ($UpsertAgentsMd) {
  Write-Host "      Upserting WSL-first routing block into $ProjectAgentsMdDir\AGENTS.md ..."
  $js = "import { upsertAgentsMdWslSection } from './dist/packages/dsh-plugin/src/prompt-injector.js'; console.log(JSON.stringify(upsertAgentsMdWslSection(process.argv[1], { distro: process.argv[2], workspaceRoot: process.argv[3] })));"
  Push-Location $PluginRepoPath
  try {
    & node --input-type=module -e $js $ProjectAgentsMdDir $Distro $WorkspaceRoot
  } finally {
    Pop-Location
  }
}

Write-Host "`nDone! Original WSL configs backed up (read-only) under: $backupDir" -ForegroundColor Green
Write-Host "Verify anytime: .\tests\windows-wsl-verify\verify-wsl2.ps1 -Distro $Distro -Profile $Profile"
