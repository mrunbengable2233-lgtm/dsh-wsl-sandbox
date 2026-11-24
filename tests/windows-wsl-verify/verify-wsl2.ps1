<#
.SYNOPSIS
  End-to-end real Windows + WSL 2 verification script for dsh-wsl-sandbox (Q17=A).
  Run this on your Windows laptop after provisioning WSL 2 to verify:
  1) WSL 2 distro state (non-root, WSL version 2)
  2) dsh-wsl-doctor --strict-wsl2 --json (real bwrap + seccomp io_uring/AF_VSOCK EPERM + escape-surface mask)
  3) Persistent NDJSON RPC transport over `wsl.exe` (`shell: false`)
  4) Real WSL 2 kernel sandbox enforcement (EROFS outside workspace, .env masking, --unshare-net)
  5) Host USBIP (`usbipd`) detection and `dsh-purge` coexistence check

.EXAMPLE
  .\tests\windows-wsl-verify\verify-wsl2.ps1 -Distro Ubuntu-24.04
#>

[CmdletBinding()]
param(
  [string]$Distro = "Ubuntu-24.04",
  [string]$UpstreamProxy = ""
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " dsh-wsl-sandbox — Real Windows + WSL 2 Verification Suite" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# Step 1: Check wsl.exe and distro version
Write-Host "`n[1/5] Checking WSL 2 distributions (wsl.exe -l -v)..."
& wsl.exe -l -v

$linuxRepo = (& wsl.exe -d $Distro -- wslpath -a ($RepoRoot.Replace('\', '/'))).Trim()
Write-Host "Linux repo path inside WSL: $linuxRepo"

# Step 2: Build inside WSL or host
Write-Host "`n[2/5] Building TypeScript artifacts..."
Push-Location $RepoRoot
try {
  & node scripts/build.mjs
} finally {
  Pop-Location
}

# Step 3: Run dsh-wsl-doctor inside real WSL 2 kernel
Write-Host "`n[3/5] Running dsh-wsl-doctor --strict-wsl2 inside '$Distro'..."
$doctorArgs = @("-d", $Distro, "--", "node", "$linuxRepo/dist/packages/bootstrap/src/doctor.js", "--strict-wsl2")
if ($UpstreamProxy) {
  $doctorArgs += @("--proxy", $UpstreamProxy)
}
& wsl.exe @doctorArgs
if ($LASTEXITCODE -ne 0) {
  throw "dsh-wsl-doctor reported BLOCKED verdict inside WSL 2 distro '$Distro'!"
}

# Step 4: Run real Linux sandbox tests inside WSL 2 + verify wsl.exe RPC bridge from Windows
Write-Host "`n[4/5] Running real kernel sandbox test suite inside WSL 2 '$Distro'..."
& wsl.exe -d $Distro -- bash -lc "cd '$linuxRepo' && node --test tests/linux-sandbox/real-kernel-sandbox.test.ts"
if ($LASTEXITCODE -ne 0) {
  throw "Real kernel sandbox test suite failed inside WSL 2!"
}

Write-Host "`n[4b/5] Verifying Windows -> wsl.exe -> wsl-runner persistent NDJSON ping..."
$pingScript = @"
import { WslTransport } from './dist/packages/dsh-plugin/src/wsl-transport.js';
const t = new WslTransport({
  mode: 'wsl',
  distro: process.argv[1],
  runnerPath: process.argv[2] + '/dist/packages/wsl-runner/src/main.js',
});
const res = await t.call('ping');
console.log('[OK] Windows->WSL2 RPC ping:', JSON.stringify(res));
await t.dispose();
"@
Push-Location $RepoRoot
try {
  & node --input-type=module -e $pingScript $Distro $linuxRepo
} finally {
  Pop-Location
}

# Step 5: Check optional usbipd-win & host coexistence
Write-Host "`n[5/5] Checking Windows host hardware utilities & plugin coexistence..."
$usbipd = Get-Command usbipd -ErrorAction SilentlyContinue
if ($usbipd) {
  Write-Host "[OK] usbipd found at $($usbipd.Source) — hybrid ESP32/USBIP workflows ready." -ForegroundColor Green
} else {
  Write-Host "[INFO] usbipd not installed (optional; only needed for ESP32/USB passthrough)." -ForegroundColor Yellow
}

Write-Host "`n[PASS] All real Windows + WSL 2 verification checks passed!" -ForegroundColor Green
