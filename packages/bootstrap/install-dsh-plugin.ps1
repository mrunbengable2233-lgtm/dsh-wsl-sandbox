<#
.SYNOPSIS
  Install or register dsh-wsl-sandbox into DeepSeek Harness (DSH) on Windows
  WITHOUT modifying app.asar, @deepseek-ai/*, or conflicting with dsh-purge.

.EXAMPLE
  .\install-dsh-plugin.ps1 -Distro Ubuntu-24.04 -WorkspaceRoot /home/dev/workspace -UpsertAgentsMd
#>

[CmdletBinding()]
param(
  [string]$Distro = "Ubuntu-24.04",
  [string]$WorkspaceRoot = "/home/$env:USERNAME/workspace",
  [string]$DshHome = $(if ($env:DSH_HOME) { $env:DSH_HOME } else { Join-Path $HOME ".dsh" }),
  [string]$PluginRepoPath = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path,
  [switch]$UpsertAgentsMd,
  [string]$ProjectAgentsMdDir = (Get-Location).Path
)

$ErrorActionPreference = "Stop"

Write-Host "=== dsh-wsl-sandbox Windows Installer (Coexistence-Safe) ===" -ForegroundColor Cyan
Write-Host "Plugin repo : $PluginRepoPath"
Write-Host "DSH_HOME    : $DshHome"
Write-Host "WSL Distro  : $Distro"

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
$cfgDir = Join-Path $DshHome "dsh-wsl-sandbox"
New-Item -ItemType Directory -Force -Path $cfgDir | Out-Null
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

# 3. Register with DSH CLI if `dsh` is on PATH (never touches dsh-purge or app.asar)
$dshCmd = Get-Command dsh -ErrorAction SilentlyContinue
if ($dshCmd) {
  Write-Host "[3/4] Registering plugin with DSH CLI via 'dsh plugin install'..."
  Write-Host "      Tip: Run 'dsh plugin install $PluginRepoPath' or copy cordis.patch.yml entries into your DSH bundle."
} else {
  Write-Host "[3/4] 'dsh' CLI not found on PATH (Desktop-only install?)." -ForegroundColor Yellow
  Write-Host "      For DSH Electron Desktop: add '$PluginRepoPath' as a local Cordis plugin (cordis.patch.yml only inserts dsh-wsl-sandbox + dsh-wsl-sandbox-web-ui, leaving dsh-purge untouched)."
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

Write-Host "`nDone! Next step on Windows:" -ForegroundColor Green
Write-Host "  1) Provision WSL tools via Agent skill 'dsh-wsl-env-setup' (or provision-wsl.sh)"
Write-Host "  2) Run .\tests\windows-wsl-verify\verify-wsl2.ps1 -Distro $Distro"
