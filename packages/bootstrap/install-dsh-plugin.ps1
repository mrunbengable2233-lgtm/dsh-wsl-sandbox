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
  [string]$Username = "",
  [string]$WorkspaceRoot = "",
  [ValidateSet("", "core", "standard", "universal")]
  [string]$Profile = "",
  [ValidateSet("global", "cn")]
  [string]$Mirror = "global",
  [string]$Proxy = "",
  [string]$DshHome = $(if ($env:DSH_HOME) { $env:DSH_HOME } else { Join-Path $HOME ".dsh" }),
  [string]$BackupDir = "",
  [string]$PluginRepoPath = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path,
  [ValidateSet("all", "base", "cli", "node", "python", "go", "rust", "go-rust", "extra")]
  [string]$Step = "all",
  [switch]$DryRun,
  [switch]$Provision,
  [switch]$UpdateConfig,
  [switch]$NonInteractive,
  [switch]$UpsertAgentsMd,
  [switch]$BackupOnly,
  [switch]$OpenBackupFolder,
  [switch]$RestoreWslConfig,
  [switch]$RegisterDshPlugin,
  [string]$ProjectAgentsMdDir = (Get-Location).Path
)

$ErrorActionPreference = "Stop"
$isInputRedirected = $false
try { $isInputRedirected = [Console]::IsInputRedirected } catch { $isInputRedirected = $false }
$effectiveNonInteractive = [bool]$NonInteractive -or $isInputRedirected

function Get-FileSha256Hex([string]$FilePath) {
  if (-not (Test-Path -LiteralPath $FilePath)) { return "missing" }
  return (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Set-PrivateOwnerAcl {
  param(
    [Parameter(Mandatory = $true)][string]$TargetPath,
    [switch]$IsDirectory,
    [switch]$ReadOnlyFile
  )
  if (-not (Test-Path -LiteralPath $TargetPath)) { return }
  $prevEap = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    if ($IsDirectory) {
      & icacls.exe $TargetPath /inheritance:r /grant:r "${currentUser}:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" 2>$null | Out-Null
    } else {
      & icacls.exe $TargetPath /inheritance:r /grant:r "${currentUser}:F" "*S-1-5-18:F" 2>$null | Out-Null
      if ($ReadOnlyFile) {
        & attrib.exe +R $TargetPath 2>$null | Out-Null
      }
    }
  } catch {
    Write-Warning "Could not tighten ACL on $TargetPath : $_"
  } finally {
    $ErrorActionPreference = $prevEap
  }
}

function Get-LxssRegistryDistros {
  $map = [hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
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
        $map[[string]$props.DistributionName] = [pscustomobject]@{
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
  $prevEap = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    [Console]::OutputEncoding = [System.Text.Encoding]::Unicode
    $rawLines = & wsl.exe -l -v 2>$null
  } catch {
    $rawLines = @()
  } finally {
    $ErrorActionPreference = $prevEap
    [Console]::OutputEncoding = $prevEnc
  }

  $internalPattern = '^(docker-desktop|docker-desktop-data|rancher-desktop|rancher-desktop-data|podman-machine)'
  foreach ($line in $rawLines) {
    $clean = ([string]$line -replace "`0", "").TrimEnd()
    if (-not $clean.Trim()) { continue }
    if ($clean -match '^\s*\*?\s*NAME\s+') { continue }
    if ($clean -match '^\s*(\*)?\s*(.+?)\s{2,}(\S.*?)\s+(\d+)\s*$') {
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
$rawBackupDir = if ($BackupDir -and $BackupDir.Trim() -ne "") { $BackupDir.Trim() } else { Join-Path $cfgDir "backups" }

if ($DryRun) {
  $skipHostSpawn = ($env:DSH_WSL_NO_HOST_SPAWN -eq "1")
  $allDistros = if ($skipHostSpawn) { @() } else { @(Get-InstalledWslDistros) }
  $backupDir = Assert-SafeBackupDir -CandidateDir $rawBackupDir -DshHomeDir $DshHome -CfgDir $cfgDir -AllDistros $allDistros
  $previewDistro = if ($Distro -and $Distro.Trim() -ne "") { $Distro.Trim() } else {
    $usable = @($allDistros | Where-Object { -not $_.IsInternal -and $_.Version -eq 2 })
    $picked = $usable | Where-Object { $_.IsDefault } | Select-Object -First 1
    if (-not $picked -and $usable.Count -gt 0) { $picked = $usable[0] }
    if ($picked) { $picked.Name } else { "<discover-or-prompt>" }
  }
  $previewProfile = if ($Profile -and $Profile.Trim() -ne "") { $Profile } else { "standard" }
  $selfSha = Get-FileSha256Hex -FilePath $PSCommandPath
  $stagePath = Join-Path $PluginRepoPath "scripts\stage-wsl-runner.mjs"
  $provPath = Join-Path $PluginRepoPath "packages\bootstrap\provision-wsl.sh"
  Write-Host "`n=== [DRY-RUN PREVIEW] dsh-wsl-sandbox Windows Installer (ZERO writes, ZERO mutations) ===" -ForegroundColor Cyan
  Write-Host "[DRY-RUN] Host spawn lock (DSH_WSL_NO_HOST_SPAWN=1): $skipHostSpawn"
  Write-Host "[DRY-RUN] Target WSL 2 Distro : $previewDistro"
  Write-Host "[DRY-RUN] Profile / Mirror / Step : $previewProfile / $Mirror / $Step"
  Write-Host "[DRY-RUN] Upstream Proxy      : $(if ($Proxy) { $Proxy } else { '(none)' })"
  Write-Host "[DRY-RUN] Config target       : $(Join-Path $cfgDir 'config.json') (owner-only ACL, created only after probe/provision readiness)"
  Write-Host "[DRY-RUN] Backup snapshot dir : $backupDir (read-only .wslconfig.orig & wsl.conf.<distro>.orig, SHA-256 deduplicated)"
  Write-Host "[DRY-RUN] Native ext4 stage   : `$HOME/.local/share/dsh-wsl-sandbox/runner/ (via stage-wsl-runner.mjs --cd ~)"
  Write-Host "[DRY-RUN] Provision flag      : Provision=$([bool]$Provision), UpdateConfig=$([bool]$UpdateConfig), UpsertAgentsMd=$([bool]$UpsertAgentsMd), RestoreWslConfig=$([bool]$RestoreWslConfig)"
  Write-Host "[DRY-RUN] Script SHA-256 install-dsh-plugin.ps1 : $selfSha"
  Write-Host "[DRY-RUN] Script SHA-256 stage-wsl-runner.mjs   : $(Get-FileSha256Hex -FilePath $stagePath)"
  Write-Host "[DRY-RUN] Script SHA-256 provision-wsl.sh       : $(Get-FileSha256Hex -FilePath $provPath)"
  $proxyArgPreview = if ($Proxy) { " --proxy $Proxy" } else { "" }
  Write-Host "[DRY-RUN] Next planned command (after human approval):"
  Write-Host "          bash ~/.local/share/dsh-wsl-sandbox/runner/packages/bootstrap/provision-wsl.sh --profile $previewProfile --mirror $Mirror --step $Step$proxyArgPreview"
  exit 0
}

New-Item -ItemType Directory -Force -Path $cfgDir | Out-Null
Set-PrivateOwnerAcl -TargetPath $cfgDir -IsDirectory

$allDistros = @(Get-InstalledWslDistros)
$usableWsl2 = @($allDistros | Where-Object { -not $_.IsInternal -and $_.Version -eq 2 })

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
    Write-Host "  5) archlinux"
    Write-Host "  6) kali-linux"
    if ($effectiveNonInteractive) {
      throw "No WSL 2 distribution found. Install one first, e.g.: wsl.exe --install -d Ubuntu-26.04 (or Debian / FedoraLinux-42 / archlinux), then re-run."
    }
    $choice = Read-Host "Choose a distro to install now [1-6, custom name, or press Enter to exit and install manually]"
    $selectedNew = switch ($choice.Trim()) {
      ""  { "" }
      "1" { "Ubuntu-26.04" }
      "2" { "Ubuntu-24.04" }
      "3" { "Debian" }
      "4" { "FedoraLinux-42" }
      "5" { "archlinux" }
      "6" { "kali-linux" }
      default { $choice.Trim() }
    }
    if (-not $selectedNew) {
      Write-Host "Run 'wsl.exe --list --online' to inspect available distros, then 'wsl.exe --install -d Ubuntu-26.04' (or any distro you prefer)."
      exit 0
    }
    Write-Host "Installing official WSL 2 distro '$selectedNew'..." -ForegroundColor Cyan
    & wsl.exe --install -d $selectedNew
    if ($LASTEXITCODE -ne 0) {
      throw "wsl.exe --install -d $selectedNew failed with exit code $LASTEXITCODE"
    }
    $manifestEarlyPath = Join-Path $cfgDir "install-manifest.json"
    [ordered]@{
      installedDistroByPlugin = $selectedNew
      recordedAt = (Get-Date).ToString("o")
      agentsMdFiles = @()
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestEarlyPath -Encoding UTF8
    Set-PrivateOwnerAcl -TargetPath $manifestEarlyPath
    Write-Host "After completing initial Linux non-root user creation in '$selectedNew', re-run this installer with -Distro $selectedNew." -ForegroundColor Green
    exit 0
  } elseif ($usableWsl2.Count -eq 1 -or $effectiveNonInteractive) {
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
  if ($effectiveNonInteractive -or $BackupOnly) {
    $Profile = "standard"
  } else {
    Write-Host "`nChoose Codex-aligned WSL 2 toolchain profile (binary-only, zero Docker, zero kernel build):" -ForegroundColor Cyan
    Write-Host "  1) core      (~350MB, ~2 min) : sandbox base (bwrap/socat/prlimit) + Codex CLI + C/C++ base + python3 + shared Node / Node 24 LTS"
    Write-Host "  2) standard  (~1.2GB, default): core + ccache/proto + mise + uv + pytest/ruff/mypy/pyright/black + pnpm/yarn/bun/ts/eslint/prettier + Go + golangci-lint + Rust minimal"
    Write-Host "  3) universal (~3.5GB)         : standard + clang/bazelisk + mise Node 22 & 24 LTS + poetry/isort + OpenJDK 21/maven/gradle/ruby/php"
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

function Resolve-SharedHostNode {
  # 1. Explicit override
  if ($env:DSH_NODE_PATH -and (Test-Path -LiteralPath $env:DSH_NODE_PATH)) {
    return [pscustomobject]@{ Exe = $env:DSH_NODE_PATH; ElectronRunAsNode = $false; Label = "DSH_NODE_PATH ($($env:DSH_NODE_PATH))" }
  }
  # 2. System / PATH node.exe
  $pathNode = Get-Command node -ErrorAction SilentlyContinue
  if ($pathNode -and $pathNode.Source) {
    return [pscustomobject]@{ Exe = $pathNode.Source; ElectronRunAsNode = $false; Label = "PATH ($($pathNode.Source))" }
  }
  # 3. Shared DSH runtime or common Windows Node version managers (mise, volta, fnm, nvm)
  $candidates = @(
    (Join-Path $DshHome "runtime\node.exe"),
    (Join-Path $HOME ".local\share\mise\shims\node.exe"),
    (Join-Path $HOME ".volta\bin\node.exe"),
    (Join-Path $env:ProgramFiles "nodejs\node.exe")
  )
  if ($env:APPDATA) {
    $candidates += (Join-Path $env:APPDATA "nvm\current\node.exe")
  }
  foreach ($c in $candidates) {
    if ($c -and (Test-Path -LiteralPath $c)) {
      return [pscustomobject]@{ Exe = $c; ElectronRunAsNode = $false; Label = "Shared Node ($c)" }
    }
  }
  # 4. Reuse DSH Desktop Electron carrier via ELECTRON_RUN_AS_NODE=1 (zero standalone Node install required!)
  $electronGlobs = @(
    (Join-Path $env:LOCALAPPDATA "Programs\dsh*\*.exe"),
    (Join-Path $env:LOCALAPPDATA "Programs\DeepSeek*\*.exe"),
    (Join-Path $env:ProgramFiles "DeepSeek*\*.exe")
  )
  foreach ($g in $electronGlobs) {
    $foundExe = Get-Item -Path $g -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -notmatch 'unins|update|crash|elevate' } |
      Select-Object -First 1
    if ($foundExe) {
      return [pscustomobject]@{ Exe = $foundExe.FullName; ElectronRunAsNode = $true; Label = "Shared DSH Desktop Carrier ($($foundExe.FullName), ELECTRON_RUN_AS_NODE=1)" }
    }
  }
  return $null
}

function Invoke-SharedHostNode {
  param(
    [Parameter(Mandatory = $true)]$Runtime,
    [Parameter(Mandatory = $true)][string[]]$Arguments
  )
  $prevElectron = $env:ELECTRON_RUN_AS_NODE
  $prevNodeOpts = $env:NODE_OPTIONS
  try {
    $env:NODE_OPTIONS = $null
    if ($Runtime.ElectronRunAsNode) {
      $env:ELECTRON_RUN_AS_NODE = "1"
    }
    & $Runtime.Exe @Arguments
    if ($LASTEXITCODE -ne 0) {
      throw "Host Node command failed with exit code $LASTEXITCODE ($($Runtime.Exe) $($Arguments -join ' '))"
    }
  } finally {
    $env:ELECTRON_RUN_AS_NODE = $prevElectron
    $env:NODE_OPTIONS = $prevNodeOpts
  }
}

$logDir = Join-Path $cfgDir "logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
Set-PrivateOwnerAcl -TargetPath $logDir -IsDirectory
$installLogLines = New-Object System.Collections.Generic.List[string]
function Add-InstallLog([string]$msg) {
  $installLogLines.Add(("{0} {1}" -f (Get-Date -Format "yyyy-MM-ddTHH:mm:ssK"), $msg))
}
Add-InstallLog "Starting install-dsh-plugin.ps1 (distro=$Distro, profile=$Profile, mirror=$Mirror)"

Write-Host "`n=== dsh-wsl-sandbox Windows Installer (Shared Node + Multi-Distro + Zero NTFS Lock) ===" -ForegroundColor Cyan
Write-Host "Plugin repo  : $PluginRepoPath"
Write-Host "DSH_HOME     : $DshHome"
Write-Host "Backup dir   : $backupDir (owner-only ACL, read-only snapshots)"
Write-Host "WSL 2 Distro : $Distro"
if ($matchedDistro -and $matchedDistro.IsCustomMoved) {
  Write-Host "VHDX Path    : $($matchedDistro.BasePath) (custom/WSL-Manager location detected; zero Explorer or /mnt dependency!)" -ForegroundColor Green
}
Write-Host "Profile      : $Profile (mirror=$Mirror)"
Write-Host "[note] Windows WSL Settings and WSL Manager share %USERPROFILE%\.wslconfig and /etc/wsl.conf; this installer NEVER auto-edits either file." -ForegroundColor DarkGray

# 0. Non-destructive read-only backup of original Windows %USERPROFILE%\.wslconfig and WSL /etc/wsl.conf (SHA-256 deduplicated, max 5 rolling .bak)
if (Test-Path -LiteralPath $wslConfigHostPath) {
  if (-not (Test-Path -LiteralPath $origWslConfigBackup) -and -not (Test-Path -LiteralPath $absentWslConfigMarker)) {
    Copy-Item -LiteralPath $wslConfigHostPath -Destination $origWslConfigBackup -Force
    Set-PrivateOwnerAcl -TargetPath $origWslConfigBackup -ReadOnlyFile
    Write-Host "[0/5] Backed up original .wslconfig (read-only) -> $origWslConfigBackup" -ForegroundColor Green
  }
  $curHash = (Get-FileHash -LiteralPath $wslConfigHostPath -Algorithm SHA256).Hash
  $existingRolling = @(Get-ChildItem -LiteralPath $backupDir -Filter ".wslconfig.*.bak" -ErrorAction SilentlyContinue | Sort-Object Name)
  $compareFile = if ($existingRolling.Count -gt 0) { $existingRolling[-1].FullName } else { $origWslConfigBackup }
  $prevHash = if (Test-Path -LiteralPath $compareFile) { (Get-FileHash -LiteralPath $compareFile -Algorithm SHA256).Hash } else { "" }
  if ($curHash -ne $prevHash) {
    $tsHostBak = Join-Path $backupDir ".wslconfig.$ts.bak"
    Copy-Item -LiteralPath $wslConfigHostPath -Destination $tsHostBak -Force
    Set-PrivateOwnerAcl -TargetPath $tsHostBak -ReadOnlyFile
    $allRolling = @(Get-ChildItem -LiteralPath $backupDir -Filter ".wslconfig.*.bak" -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
    foreach ($oldBak in ($allRolling | Select-Object -Skip 5)) {
      try { $oldBak.IsReadOnly = $false } catch {}
      Remove-Item -Force -LiteralPath $oldBak.FullName -ErrorAction SilentlyContinue
    }
  }
} else {
  if (-not (Test-Path -LiteralPath $origWslConfigBackup) -and -not (Test-Path -LiteralPath $absentWslConfigMarker)) {
    Set-Content -LiteralPath $absentWslConfigMarker -Value "# Host had no %USERPROFILE%\.wslconfig at initial backup ($ts)`n# Shared by Windows WSL Settings & WSL Manager." -Encoding UTF8
    Set-PrivateOwnerAcl -TargetPath $absentWslConfigMarker -ReadOnlyFile
    Write-Host "[0/5] Recorded clean state (no prior %USERPROFILE%\.wslconfig) -> $absentWslConfigMarker" -ForegroundColor Green
  }
}

$prevEap = $ErrorActionPreference
$ErrorActionPreference = "Continue"
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
} finally {
  $ErrorActionPreference = $prevEap
}

if ($OpenBackupFolder) {
  Start-Process "explorer.exe" -ArgumentList @($backupDir)
}

if ($BackupOnly) {
  Write-Host "`nBackup complete (read-only snapshots, SHA-256 deduplicated) under: $backupDir" -ForegroundColor Green
  exit 0
}

# 1. Probe real non-root Linux user & $HOME inside target WSL 2 distro (using --cd ~ so Windows NTFS is NEVER locked)
$probeArgs = @("-d", $Distro, "--cd", "~")
$hasExplicitUser = -not [string]::IsNullOrWhiteSpace($Username)
if ($hasExplicitUser) {
  $Username = $Username.Trim()
  if ($Username -notmatch '^[a-z_][a-z0-9_.-]{0,31}$') {
    throw "Invalid Linux username: $Username"
  }
  $probeArgs += @("-u", $Username)
}
$probeUserSh = @'
u_uid="$(id -u)"; u_name="$(id -un)"; u_home="$HOME"
if [ -z "$1" ] && [ "$u_uid" = "0" ] && [ -r /etc/passwd ]; then
  pw="$(awk -F: '$3 >= 1000 && $3 < 65534 && $1 != "nobody" && $6 ~ /^\// { print $3 "\t" $1 "\t" $6; exit }' /etc/passwd 2>/dev/null || true)"
  if [ -n "$pw" ]; then
    u_uid="$(printf "%s\n" "$pw" | cut -f1)"
    u_name="$(printf "%s\n" "$pw" | cut -f2)"
    u_home="$(printf "%s\n" "$pw" | cut -f3)"
  fi
fi
printf "%s\t%s\t%s\n" "$u_uid" "$u_name" "$u_home"
'@ -replace "`r`n", "`n"
$probeArgs += @("--", "sh", "-c", $probeUserSh, "dsh-probe", $(if ($hasExplicitUser) { $Username } else { "" }))
$probeOut = & wsl.exe @probeArgs
$probeLine = if ($probeOut) { (($probeOut -join "`n").Trim() -split "`r?`n" | Select-Object -Last 1).Trim() } else { "" }
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
  throw "WSL distro '$Distro' default user is root (UID 0). Create a non-root user or pass -Username <user>; dsh-wsl-sandbox blocks UID 0."
}
if (-not $WorkspaceRoot -or $WorkspaceRoot.Trim() -eq "") {
  $WorkspaceRoot = "$linuxHome/workspace"
}
Write-Host "[1/5] Probed WSL user: $linuxUser (uid=$linuxUid, home=$linuxHome) -> workspaceRoot=$WorkspaceRoot" -ForegroundColor Green
Add-InstallLog "Probed WSL user=$linuxUser uid=$linuxUid home=$linuxHome workspace=$WorkspaceRoot"

# Check if workspace directory existed prior to setup (so uninstaller only removes an empty plugin-created ~/workspace)
$prevEap = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
  $wsCheckOut = & wsl.exe -d $Distro --cd ~ -u $linuxUser -- sh -c '[ -d "$1" ] && echo 1 || echo 0' dsh-ws-check $WorkspaceRoot 2>$null
} finally {
  $ErrorActionPreference = $prevEap
}
$wsExistedBefore = if ($wsCheckOut) { ($wsCheckOut | Select-Object -Last 1).Trim() } else { "0" }
$createdDefaultWorkspace = ($wsExistedBefore -ne "1")
& wsl.exe -d $Distro --cd ~ -u $linuxUser -- sh -c 'mkdir -p "$1"' dsh-ws-mkdir $WorkspaceRoot | Out-Null
if ($LASTEXITCODE -ne 0) {
  throw "Failed creating workspace directory '$WorkspaceRoot' inside '$Distro' (exit $LASTEXITCODE)"
}

# 2. Resolve shared Host Node (or prebuilt tar fallback), build dist/ if needed, and stage into native WSL ext4
$hostNode = Resolve-SharedHostNode
$prebuiltMain = Join-Path $PluginRepoPath "dist\packages\wsl-runner\src\main.js"
if ($hostNode) {
  $nodeVer = (Invoke-SharedHostNode -Runtime $hostNode -Arguments @("-v") | Select-Object -Last 1).Trim()
  Write-Host "[2/5] Using Host Node runtime: $nodeVer via $($hostNode.Label)"
  Add-InstallLog "Host Node=$nodeVer via $($hostNode.Label)"
  Push-Location $PluginRepoPath
  try {
    Invoke-SharedHostNode -Runtime $hostNode -Arguments @("scripts/build.mjs")
    $stagedJson = Invoke-SharedHostNode -Runtime $hostNode -Arguments @("scripts/stage-wsl-runner.mjs", "--distro", $Distro, "--username", $linuxUser, "--json")
    $staged = ($stagedJson -join "`n") | ConvertFrom-Json
  } finally {
    Pop-Location
  }
} elseif (Test-Path -LiteralPath $prebuiltMain) {
  Write-Host "[2/5] No standalone Windows node.exe needed - staging prebuilt dist/ directly into WSL native ext4..." -ForegroundColor Cyan
  $tmpTar = Join-Path ([System.IO.Path]::GetTempPath()) ("dsh-wsl-stage-{0}.tar" -f $PID)
  try {
    & tar.exe -cf $tmpTar -C $PluginRepoPath dist package.json packages/bootstrap/provision-wsl.sh
    if ($LASTEXITCODE -ne 0) { throw "tar.exe failed creating staging archive" }
    $tarBytes = [System.IO.File]::ReadAllBytes($tmpTar)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "wsl.exe"
    $psi.Arguments = "-d `"$Distro`" --cd ~ -u `"$linuxUser`" -- sh -c `"umask 077 && TARGET=`\`"`$HOME/.local/share/dsh-wsl-sandbox/runner`\`" && rm -rf `\`"`$TARGET`\`" && mkdir -p `\`"`$TARGET`\`" && chmod 700 `\`"`$HOME/.local/share/dsh-wsl-sandbox`\`" `\`"`$TARGET`\`" && tar -xf - -C `\`"`$TARGET`\`" && sed -i 's/\r$//' `\`"`$TARGET/packages/bootstrap/provision-wsl.sh`\`" && chmod 700 `\`"`$TARGET/packages/bootstrap/provision-wsl.sh`\`"`""
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $p.StandardInput.BaseStream.Write($tarBytes, 0, $tarBytes.Length)
    $p.StandardInput.Close()
    $p.WaitForExit()
    if ($p.ExitCode -ne 0) { throw "WSL staging tar extraction failed with exit $($p.ExitCode)" }
    $stagedRoot = "$linuxHome/.local/share/dsh-wsl-sandbox/runner"
    $staged = [pscustomobject]@{
      fileCount = "prebuilt"
      stagedRoot = $stagedRoot
      runnerPath = "$stagedRoot/dist/packages/wsl-runner/src/main.js"
      doctorPath = "$stagedRoot/dist/packages/bootstrap/src/doctor.js"
      provisionScriptPath = "$stagedRoot/packages/bootstrap/provision-wsl.sh"
    }
  } finally {
    if (Test-Path -LiteralPath $tmpTar) { Remove-Item -Force -LiteralPath $tmpTar -ErrorAction SilentlyContinue }
  }
} else {
  throw "Neither Windows/DSH Node runtime nor prebuilt dist/ was found under $PluginRepoPath."
}
Write-Host "      Staged $($staged.fileCount) files into native ext4: $($staged.runnerPath) (zero /mnt lock!)" -ForegroundColor Green
Add-InstallLog "Staged runnerPath=$($staged.runnerPath)"

# 3. Probe WSL sandbox & shared Linux Node readiness BEFORE enabling config.json (correct startup sequence!)
$wslReadinessCheck = (@'
cd "$HOME" 2>/dev/null || true
[ -f "$HOME/.dsh-wsl-env.sh" ] && . "$HOME/.dsh-wsl-env.sh" >/dev/null 2>&1 || true
NIX_USER="${USER:-${HOME##*/}}"
CLEAN_PATH=""
OLD_IFS="$IFS"; IFS=":"
for p in $PATH; do
  case "$p" in /mnt/*|"") ;; *) CLEAN_PATH="${CLEAN_PATH:+$CLEAN_PATH:}$p" ;; esac
done
IFS="$OLD_IFS"
export PATH="$HOME/.dsh/runtime/bin:$HOME/.local/share/dsh/node/bin:$HOME/.local/share/dsh-wsl-sandbox/toolchains/node/bin:$HOME/.local/share/dsh-wsl-sandbox/toolchains/go/bin:$HOME/.local/share/mise/shims:$HOME/.local/bin:$HOME/.nvm/current/bin:$HOME/.volta/bin:$HOME/.nix-profile/bin:/etc/profiles/per-user/$NIX_USER/bin:/run/current-system/sw/bin:/nix/var/nix/profiles/default/bin:/usr/local/bin:/usr/bin:/bin${CLEAN_PATH:+:$CLEAN_PATH}"
MISS=""
for bin in bwrap prlimit socat node; do
  command -v "$bin" >/dev/null 2>&1 || MISS="${MISS:+$MISS,}$bin"
done
printf "%s\n" "${MISS:-READY}"
'@) -replace "`r`n", "`n"
$prevEap = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
  $missOut = & wsl.exe -d $Distro --cd ~ -u $linuxUser -- sh -c $wslReadinessCheck 2>$null
  $missExit = $LASTEXITCODE
} finally {
  $ErrorActionPreference = $prevEap
}
$missingBins = if ($missExit -eq 0 -and $missOut) { ($missOut | Select-Object -Last 1).Trim() } else { "probe-failed" }

$doProvision = [bool]$Provision
if (-not $doProvision -and -not $effectiveNonInteractive) {
  if ($missingBins -ne "READY") {
    Write-Host "      Detected missing WSL sandbox/runtime binaries ($missingBins) in '$Distro'." -ForegroundColor Yellow
    $runProv = Read-Host "Provision '$Distro' now with --profile $Profile --mirror $Mirror --step $Step (shares existing Node or installs verified Node 24 LTS)? [Y/n]"
    if (-not $runProv.Trim() -or $runProv.Trim() -imatch '^(y|yes)$') { $doProvision = $true }
  } else {
    $runProv = Read-Host "Sandbox primitives & shared Node already ready in '$Distro'. Re-run provision-wsl.sh (--profile $Profile --mirror $Mirror --step $Step) anyway? [y/N]"
    if ($runProv.Trim() -imatch '^(y|yes)$') { $doProvision = $true }
  }
}

$wslDoctorExecSh = 'cd "$HOME" 2>/dev/null || true; [ -f "$HOME/.dsh-wsl-env.sh" ] && . "$HOME/.dsh-wsl-env.sh" >/dev/null 2>&1 || true; NIX_USER="${USER:-${HOME##*/}}"; CLEAN_PATH=""; OLD_IFS="$IFS"; IFS=":"; for p in $PATH; do case "$p" in /mnt/*|"") ;; *) CLEAN_PATH="${CLEAN_PATH:+$CLEAN_PATH:}$p" ;; esac; done; IFS="$OLD_IFS"; export PATH="$HOME/.dsh/runtime/bin:$HOME/.local/share/dsh/node/bin:$HOME/.local/share/dsh-wsl-sandbox/toolchains/node/bin:$HOME/.local/share/dsh-wsl-sandbox/toolchains/go/bin:$HOME/.local/share/mise/shims:$HOME/.local/bin:$HOME/.nvm/current/bin:$HOME/.volta/bin:$HOME/.nix-profile/bin:/etc/profiles/per-user/$NIX_USER/bin:/run/current-system/sw/bin:/nix/var/nix/profiles/default/bin:/usr/local/bin:/usr/bin:/bin${CLEAN_PATH:+:$CLEAN_PATH}"; exec node "$1" --strict-wsl2 --profile "$2"'

if ($doProvision) {
  Write-Host "[3/5] Provisioning '$Distro' with profile='$Profile', mirror='$Mirror', step='$Step'..." -ForegroundColor Cyan
  $provArgs = @("-d", $Distro, "--cd", "~", "-u", $linuxUser, "--", "bash", $staged.provisionScriptPath, "--profile", $Profile, "--mirror", $Mirror, "--step", $Step)
  if ($Proxy) { $provArgs += @("--proxy", $Proxy) }
  $needSudoPrompt = $false
  if ($isInputRedirected) {
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
      & wsl.exe -d $Distro --cd ~ -u $linuxUser -- sh -c 'sudo -n true >/dev/null 2>&1' 2>$null
      $needSudoPrompt = ($LASTEXITCODE -ne 0)
    } finally {
      $ErrorActionPreference = $prevEap
    }
  }
  if ($needSudoPrompt) {
    Write-Host "      Detected redirected non-TTY stdin and sudo password required; opening interactive WSL console window for sudo auth..." -ForegroundColor Yellow
    $provProc = Start-Process -FilePath "wsl.exe" -ArgumentList $provArgs -Wait -PassThru
    $provExit = $provProc.ExitCode
  } else {
    & wsl.exe @provArgs
    $provExit = $LASTEXITCODE
  }
  if ($provExit -ne 0) {
    Add-InstallLog "ERROR: provision-wsl.sh exited with $provExit"
    throw "provision-wsl.sh exited with code $provExit inside '$Distro'"
  }
  $prevEap = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    $missOutAfter = & wsl.exe -d $Distro --cd ~ -u $linuxUser -- sh -c $wslReadinessCheck 2>$null
    $missExitAfter = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $prevEap
  }
  $missingBins = if ($missExitAfter -eq 0 -and $missOutAfter) { ($missOutAfter | Select-Object -Last 1).Trim() } else { "probe-failed" }
  Add-InstallLog "Provisioning completed for profile=$Profile step=$Step readiness=$missingBins"
} else {
  Write-Host "[3/5] Provisioning skipped (readiness=$missingBins). Run anytime without /mnt dependency:" -ForegroundColor Yellow
  Write-Host "      wsl.exe -d $Distro --cd ~ -u $linuxUser -- bash `"$($staged.provisionScriptPath)`" --profile $Profile --mirror $Mirror --step $Step"
}

$sandboxEnabled = ($missingBins -eq "READY")

# 4. Write or update human-only config.json under $DSH_HOME\dsh-wsl-sandbox\config.json (owner-only ACL) AFTER provisioning check
$cfgPath = Join-Path $cfgDir "config.json"
if (-not (Test-Path -LiteralPath $cfgPath)) {
  $cfg = [ordered]@{
    revision = "rev-1"
    enabled = $sandboxEnabled
    transportMode = "wsl"
    distro = $Distro
    username = $linuxUser
    workspaceRoot = $WorkspaceRoot
    runnerPath = $staged.runnerPath
    wslNodePath = "auto"
    environmentProfile = $Profile
    sandboxMode = "workspace-write"
    approvalPolicyMode = "balanced"
    networkMode = "allowlist-proxy"
    upstreamProxy = $Proxy
    mirrorCn = ($Mirror -eq "cn")
    cacheMode = "workspace-persistent"
    logLevel = "info"
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
  Write-Host "[4/5] Created owner-only config: $cfgPath (enabled=$sandboxEnabled, profile=$Profile, wslNodePath=auto, logLevel=info)" -ForegroundColor Green
  Add-InstallLog "Created config.json at $cfgPath (enabled=$sandboxEnabled)"
} else {
  if ($UpdateConfig -or $Provision) {
    $existing = Get-Content -LiteralPath $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $existing | Add-Member -NotePropertyName enabled -NotePropertyValue $sandboxEnabled -Force
    $existing | Add-Member -NotePropertyName distro -NotePropertyValue $Distro -Force
    $existing | Add-Member -NotePropertyName username -NotePropertyValue $linuxUser -Force
    $existing | Add-Member -NotePropertyName workspaceRoot -NotePropertyValue $WorkspaceRoot -Force
    $existing | Add-Member -NotePropertyName runnerPath -NotePropertyValue $staged.runnerPath -Force
    $existing | Add-Member -NotePropertyName wslNodePath -NotePropertyValue "auto" -Force
    $existing | Add-Member -NotePropertyName environmentProfile -NotePropertyValue $Profile -Force
    $existing | Add-Member -NotePropertyName mirrorCn -NotePropertyValue ($Mirror -eq "cn") -Force
    if (-not $existing.PSObject.Properties["logLevel"]) {
      $existing | Add-Member -NotePropertyName logLevel -NotePropertyValue "info" -Force
    }
    if ($Proxy) { $existing | Add-Member -NotePropertyName upstreamProxy -NotePropertyValue $Proxy -Force }
    $existing | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $cfgPath -Encoding UTF8
    Set-PrivateOwnerAcl -TargetPath $cfgPath
    Write-Host "[4/5] Updated existing config with enabled=$sandboxEnabled, distro=$Distro, profile=$Profile, native ext4 runnerPath." -ForegroundColor Green
    Add-InstallLog "Updated config.json at $cfgPath (enabled=$sandboxEnabled)"
  } else {
    Write-Host "[4/5] Existing config preserved: $cfgPath (pass -UpdateConfig to overwrite distro/profile/runnerPath)" -ForegroundColor Yellow
  }
}

# 5. Run dsh-wsl-doctor when ready + DSH CLI / Desktop registration & optional AGENTS.md upsert
if ($missingBins -eq "READY") {
  Write-Host "[5/5] Running dsh-wsl-doctor --profile $Profile inside '$Distro'..." -ForegroundColor Cyan
  & wsl.exe -d $Distro --cd ~ -u $linuxUser -- sh -c $wslDoctorExecSh dsh-doctor $staged.doctorPath $Profile
  if ($LASTEXITCODE -ne 0) {
    Add-InstallLog "ERROR: dsh-wsl-doctor exited with $LASTEXITCODE"
    throw "dsh-wsl-doctor reported BLOCKED or failed inside '$Distro' (exit $LASTEXITCODE)"
  }
}

$dshCmd = Get-Command dsh -ErrorAction SilentlyContinue
if ($dshCmd) {
  if ($RegisterDshPlugin) {
    foreach ($dshProf in @("web", "desktop", "headless")) {
      Write-Host "      Registering dsh-wsl-sandbox in DSH '$dshProf' profile..." -ForegroundColor Cyan
      & dsh plugin --profile $dshProf add $PluginRepoPath
      if ($LASTEXITCODE -ne 0) {
        Write-Warning "dsh plugin --profile $dshProf add exited with $LASTEXITCODE"
      } else {
        Add-InstallLog "Registered plugin in DSH profile '$dshProf'"
      }
    }
  } else {
    Write-Host "      Detected DSH CLI (plugin shares DSH's Node runtime in-process). Register plugin (or pass -RegisterDshPlugin):" -ForegroundColor Cyan
    Write-Host "      CLI/Web  : dsh plugin --profile web add `"$PluginRepoPath`""
    Write-Host "      Desktop  : dsh plugin --profile desktop add `"$PluginRepoPath`""
    Write-Host "      Headless : dsh plugin --profile headless add `"$PluginRepoPath`""
  }
} else {
  Write-Host "      'dsh' CLI not on PATH (Desktop-only install?)." -ForegroundColor Yellow
  Write-Host "      Import '$PluginRepoPath' (or dsh-wsl-sandbox-0.3.0.tgz) in DSH Desktop Plugin Settings."
}

$manifestPath = Join-Path $cfgDir "install-manifest.json"
$prevManifest = if (Test-Path -LiteralPath $manifestPath) {
  try { Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $null }
} else { $null }
$recordedAgentsMd = New-Object System.Collections.Generic.List[string]
if ($prevManifest -and $prevManifest.agentsMdFiles) {
  foreach ($f in $prevManifest.agentsMdFiles) {
    if ($f -and -not $recordedAgentsMd.Contains([string]$f)) { $recordedAgentsMd.Add([string]$f) }
  }
}

if ($UpsertAgentsMd) {
  $targetAgentsFile = Join-Path (Resolve-Path -LiteralPath $ProjectAgentsMdDir).Path "AGENTS.md"
  Write-Host "      Upserting WSL-first routing block into $targetAgentsFile ..."
  if ($hostNode) {
    $js = "import { upsertAgentsMdWslSection } from './dist/packages/dsh-plugin/src/prompt-injector.js'; console.log(JSON.stringify(upsertAgentsMdWslSection(process.argv[1], { distro: process.argv[2], workspaceRoot: process.argv[3] })));"
    Push-Location $PluginRepoPath
    try {
      Invoke-SharedHostNode -Runtime $hostNode -Arguments @("--input-type=module", "-e", $js, $ProjectAgentsMdDir, $Distro, $WorkspaceRoot)
    } finally {
      Pop-Location
    }
  } else {
    $block = @(
      "<!-- dsh-wsl-sandbox:start -->",
      "## WSL 2 Sandbox Tool Routing (Managed by dsh-wsl-sandbox)",
      "",
      "- Default Linux sandbox distro: ``$Distro`` (workspace: ``$WorkspaceRoot``).",
      "- **Always prefer ``wsl_*`` tools** (``wsl_bash``, ``wsl_read``, ``wsl_write``, ``wsl_edit``, ``wsl_glob``, ``wsl_grep``, ``wsl_terminal``) for repository work, builds, tests, git, and Linux workflows.",
      "<!-- dsh-wsl-sandbox:end -->"
    ) -join "`n"
    if (-not (Test-Path -LiteralPath $targetAgentsFile)) {
      Set-Content -LiteralPath $targetAgentsFile -Value "# Project Agent Instructions`n`n$block`n" -Encoding UTF8
    } else {
      $raw = Get-Content -LiteralPath $targetAgentsFile -Raw -Encoding UTF8
      if ($raw -match '<!--\s*dsh-wsl-sandbox:(?:start|begin)\s*-->[\s\S]*?<!--\s*dsh-wsl-sandbox:end\s*-->') {
        $updated = [regex]::Replace($raw, '<!--\s*dsh-wsl-sandbox:(?:start|begin)\s*-->[\s\S]*?<!--\s*dsh-wsl-sandbox:end\s*-->', $block)
        Set-Content -LiteralPath $targetAgentsFile -Value $updated -Encoding UTF8
      } else {
        Add-Content -LiteralPath $targetAgentsFile -Value "`n$block`n" -Encoding UTF8
      }
    }
  }
  if (-not $recordedAgentsMd.Contains($targetAgentsFile)) {
    $recordedAgentsMd.Add($targetAgentsFile)
  }
}

# Persist complete install-manifest.json so `uninstall-dsh-plugin.ps1` knows every touched path without digging logs!
$installedDistroByPlugin = if ($prevManifest -and $prevManifest.installedDistroByPlugin) { $prevManifest.installedDistroByPlugin } else { $null }
$prevCreatedWs = if ($prevManifest -and $prevManifest.createdDefaultWorkspace) { [bool]$prevManifest.createdDefaultWorkspace } else { $false }
$manifestDoc = [ordered]@{
  version = "0.3.0"
  updatedAt = (Get-Date).ToString("o")
  distro = $Distro
  installedDistroByPlugin = $installedDistroByPlugin
  linuxUser = $linuxUser
  linuxHome = $linuxHome
  workspaceRoot = $WorkspaceRoot
  createdDefaultWorkspace = ($createdDefaultWorkspace -or $prevCreatedWs)
  profile = $Profile
  mirror = $Mirror
  hostConfigDir = $cfgDir
  backupDir = $backupDir
  logDir = $logDir
  wslPaths = [ordered]@{
    stagedRoot = "$linuxHome/.local/share/dsh-wsl-sandbox"
    configRoot = "$linuxHome/.config/dsh-wsl-sandbox"
    cacheRoot = "$linuxHome/.cache/dsh-wsl-sandbox"
    envSh = "$linuxHome/.dsh-wsl-env.sh"
  }
  agentsMdFiles = @($recordedAgentsMd)
}
$manifestDoc | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
Set-PrivateOwnerAcl -TargetPath $manifestPath

# Single-write bounded install log (keeps max 5 setup logs, zero ongoing disk churn)
$installLogFile = Join-Path $logDir "install-$ts.log"
Add-InstallLog "Installer completed successfully."
Set-Content -LiteralPath $installLogFile -Value ($installLogLines -join "`r`n") -Encoding UTF8
Set-PrivateOwnerAcl -TargetPath $installLogFile
Get-ChildItem -LiteralPath $logDir -Filter "install-*.log" -ErrorAction SilentlyContinue |
  Sort-Object LastWriteTime -Descending |
  Select-Object -Skip 5 |
  Remove-Item -Force -ErrorAction SilentlyContinue

Write-Host "`nDone! Original WSL configs backed up (read-only) under: $backupDir" -ForegroundColor Green
Write-Host "Verify anytime   : .\tests\windows-wsl-verify\verify-wsl2.ps1 -Distro $Distro -Profile $Profile"
Write-Host "Clean uninstall  : .\packages\bootstrap\uninstall-dsh-plugin.ps1 [-DryRun] [-PurgeToolchains]"

