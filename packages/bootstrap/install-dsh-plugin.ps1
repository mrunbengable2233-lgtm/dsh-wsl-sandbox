<#
.SYNOPSIS
  Install or register dsh-wsl-sandbox into DeepSeek Harness (DSH) on Windows
  WITHOUT modifying app.asar, @deepseek-ai/*, or conflicting with dsh-purge / dshmarket.
  Automatically backs up original %USERPROFILE%\.wslconfig and WSL /etc/wsl.conf before setup.

.EXAMPLE
  .\install-dsh-plugin.ps1 -Distro Ubuntu-24.04 -WorkspaceRoot /home/dev/workspace -UpsertAgentsMd

.EXAMPLE
  .\install-dsh-plugin.ps1 -Distro Ubuntu-24.04 -BackupOnly

.EXAMPLE
  .\install-dsh-plugin.ps1 -Distro Ubuntu-24.04 -RestoreWslConfig
#>

[CmdletBinding()]
param(
  [string]$Distro = "Ubuntu-24.04",
  [string]$WorkspaceRoot = "/home/$($env:USERNAME.ToLower())/workspace",
  [string]$DshHome = $(if ($env:DSH_HOME) { $env:DSH_HOME } else { Join-Path $HOME ".dsh" }),
  [string]$BackupDir = "",
  [string]$PluginRepoPath = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path,
  [switch]$UpsertAgentsMd,
  [switch]$BackupOnly,
  [switch]$OpenBackupFolder,
  [switch]$RestoreWslConfig,
  [string]$ProjectAgentsMdDir = (Get-Location).Path
)

$ErrorActionPreference = "Stop"

$cfgDir = Join-Path $DshHome "dsh-wsl-sandbox"
New-Item -ItemType Directory -Force -Path $cfgDir | Out-Null
$backupDir = if ($BackupDir -and $BackupDir.Trim() -ne "") { $BackupDir.Trim() } else { Join-Path $cfgDir "backups" }
New-Item -ItemType Directory -Force -Path $backupDir | Out-Null

$wslConfigHostPath = Join-Path $HOME ".wslconfig"
$origWslConfigBackup = Join-Path $backupDir ".wslconfig.orig"
$absentWslConfigMarker = Join-Path $backupDir ".wslconfig.orig.absent"
$origDistroConfBackup = Join-Path $backupDir "wsl.conf.$Distro.orig"
$ts = Get-Date -Format "yyyyMMdd-HHmmss"

if ($RestoreWslConfig) {
  Write-Host "=== Restoring Original Windows .wslconfig & WSL /etc/wsl.conf ===" -ForegroundColor Cyan
  if (Test-Path $origWslConfigBackup) {
    Copy-Item -Force -Path $origWslConfigBackup -Destination $wslConfigHostPath
    Write-Host "[ok] Restored $wslConfigHostPath from $origWslConfigBackup" -ForegroundColor Green
  } elseif (Test-Path $absentWslConfigMarker) {
    if (Test-Path $wslConfigHostPath) { Remove-Item -Force $wslConfigHostPath }
    Write-Host "[ok] Removed $wslConfigHostPath (host originally had no .wslconfig)" -ForegroundColor Green
  } else {
    Write-Host "[info] No host .wslconfig backup marker found under $backupDir" -ForegroundColor Yellow
  }
  & wsl.exe -d $Distro -- bash -lc "if [ -f ~/.config/dsh-wsl-sandbox/backups/wsl.conf.orig ] || [ -f ~/.config/dsh-wsl-sandbox/backups/wsl.conf.orig.absent ]; then bash '$(($PluginRepoPath.Replace('\','/')))' 2>/dev/null || true; fi" 2>$null
  Write-Host "Tip: Inside WSL ($Distro), run 'bash packages/bootstrap/provision-wsl.sh --restore-configs' and then 'wsl.exe --shutdown'."
  exit 0
}

Write-Host "=== dsh-wsl-sandbox Windows Installer (Coexistence-Safe + Auto Backup) ===" -ForegroundColor Cyan
Write-Host "Plugin repo : $PluginRepoPath"
Write-Host "DSH_HOME    : $DshHome"
Write-Host "Backup dir  : $backupDir"
Write-Host "WSL Distro  : $Distro"

# 0. Non-destructive backup of original Windows %USERPROFILE%\.wslconfig and WSL /etc/wsl.conf
if (Test-Path $wslConfigHostPath) {
  if (-not (Test-Path $origWslConfigBackup) -and -not (Test-Path $absentWslConfigMarker)) {
    Copy-Item -Path $wslConfigHostPath -Destination $origWslConfigBackup -Force
    Write-Host "[0/4] Backed up original .wslconfig -> $origWslConfigBackup" -ForegroundColor Green
  }
  Copy-Item -Path $wslConfigHostPath -Destination (Join-Path $backupDir ".wslconfig.$ts.bak") -Force
} else {
  if (-not (Test-Path $origWslConfigBackup) -and -not (Test-Path $absentWslConfigMarker)) {
    Set-Content -Path $absentWslConfigMarker -Value "# Host had no %USERPROFILE%\.wslconfig at initial backup ($ts)" -Encoding UTF8
    Write-Host "[0/4] Recorded clean state (no prior %USERPROFILE%\.wslconfig) -> $absentWslConfigMarker" -ForegroundColor Green
  }
}

try {
  $distroWslConf = & wsl.exe -d $Distro -- sh -c "if [ -f /etc/wsl.conf ]; then cat /etc/wsl.conf; else echo '__ABSENT__'; fi" 2>$null
  if ($LASTEXITCODE -eq 0 -and $distroWslConf) {
    $joined = ($distroWslConf -join "`n").Trim()
    if ($joined -ne "__ABSENT__" -and -not (Test-Path $origDistroConfBackup)) {
      Set-Content -Path $origDistroConfBackup -Value $joined -Encoding UTF8
      Write-Host "[0/4] Backed up WSL ($Distro) /etc/wsl.conf -> $origDistroConfBackup" -ForegroundColor Green
    }
  }
} catch {
  Write-Host "[0/4] Could not snapshot WSL ($Distro) /etc/wsl.conf yet (distro not booted); provision-wsl.sh will back it up inside WSL." -ForegroundColor Yellow
}

if ($OpenBackupFolder) {
  Start-Process "explorer.exe" -ArgumentList @($backupDir)
}

if ($BackupOnly) {
  Write-Host "`nBackup complete under: $backupDir" -ForegroundColor Green
  exit 0
}

# 1. Verify Node 22+ and build dist/
$nodeVersion = & node -v
Write-Host "[1/4] Host Node.js: $nodeVersion"
Push-Location $PluginRepoPath
try {
  & node scripts/build.mjs
} finally {
  Pop-Location
}

# 2. Write initial human-only config.json under $DSH_HOME\dsh-wsl-sandbox\config.json
$cfgPath = Join-Path $cfgDir "config.json"
$runnerLinuxPath = (& wsl.exe -d $Distro -- wslpath -a ($PluginRepoPath.Replace('\', '/'))).Trim() + "/dist/packages/wsl-runner/src/main.js"

if (-not (Test-Path $cfgPath)) {
  $cfg = [ordered]@{
    revision = "rev-1"
    enabled = $true
    transportMode = "wsl"
    distro = $Distro
    workspaceRoot = $WorkspaceRoot
    runnerPath = $runnerLinuxPath
    sandboxMode = "workspace-write"
    approvalPolicyMode = "balanced"
    networkMode = "allowlist-proxy"
    upstreamProxy = ""
    mirrorCn = $false
    cacheMode = "workspace-persistent"
    approvalTimeoutMs = 60000
    enablePwshGuard = $true
    enablePromptInjection = $true
    unmaskedEnvWorkspaces = @()
    advanced = [ordered]@{
      shares = @()
      deviceNodes = @()
      localLabCidrs = @()
      localLabPorts = @()
      customAllowedDomains = @()
    }
  }
  $cfg | ConvertTo-Json -Depth 6 | Set-Content -Path $cfgPath -Encoding UTF8
  Write-Host "[2/4] Created initial config: $cfgPath" -ForegroundColor Green
} else {
  Write-Host "[2/4] Existing config preserved: $cfgPath" -ForegroundColor Yellow
}

# 3. Register with DSH CLI (supports web, desktop, headless profiles without touching app.asar or dsh-purge)
$dshCmd = Get-Command dsh -ErrorAction SilentlyContinue
if ($dshCmd) {
  Write-Host "[3/4] Detected DSH CLI. Registering plugin..." -ForegroundColor Cyan
  Write-Host "      Run for CLI/Web : dsh plugin --profile web add `"$PluginRepoPath`""
  Write-Host "      Run for Desktop : dsh plugin --profile desktop add `"$PluginRepoPath`""
} else {
  Write-Host "[3/4] 'dsh' CLI not on PATH (Desktop-only install?)." -ForegroundColor Yellow
  Write-Host "      Import '$PluginRepoPath' (or dsh-wsl-sandbox-0.1.0.tgz) in DSH Desktop Plugin Settings; cordis.patch.yml only inserts id: dsh-wsl-sandbox."
}

# 4. Optional AGENTS.md WSL-first block upsert
if ($UpsertAgentsMd) {
  Write-Host "[4/4] Upserting WSL-first routing block into $ProjectAgentsMdDir\AGENTS.md ..."
  $js = "import { upsertAgentsMdWslSection } from './dist/packages/dsh-plugin/src/prompt-injector.js'; console.log(JSON.stringify(upsertAgentsMdWslSection(process.argv[1], { distro: process.argv[2], workspaceRoot: process.argv[3] })));"
  Push-Location $PluginRepoPath
  try {
    & node --input-type=module -e $js $ProjectAgentsMdDir $Distro $WorkspaceRoot
  } finally {
    Pop-Location
  }
} else {
  Write-Host "[4/4] Skipped AGENTS.md upsert (pass -UpsertAgentsMd to add WSL-first guidance)."
}

Write-Host "`nDone! Original WSL configs backed up under: $backupDir" -ForegroundColor Green
Write-Host "Next steps:"
Write-Host "  1) Inside WSL ($Distro): bash packages/bootstrap/provision-wsl.sh --profile standard --mirror cn"
Write-Host "  2) Verify kernel isolation: .\tests\windows-wsl-verify\verify-wsl2.ps1 -Distro $Distro"
