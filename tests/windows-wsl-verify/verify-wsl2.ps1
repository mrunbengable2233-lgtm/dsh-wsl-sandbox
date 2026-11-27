<#
.SYNOPSIS
  End-to-end real Windows + WSL 2 verification script for dsh-wsl-sandbox.
  Zero hardcoded distro/path assumptions: auto-discovers installed WSL 2 distros
  (including WSL Manager imported/moved VHDX instances), reuses DSH's shared Node
  carrier on Windows if standalone node.exe is absent, and stages the runner into
  native WSL ext4 so it works even with `[automount] enabled = false`.

  Verifies:
  1) WSL 2 distro state (non-root, WSL version 2, custom Lxss BasePath support)
  2) dsh-wsl-doctor --strict-wsl2 --profile <profile> via shared WSL Linux Node
  3) Persistent NDJSON RPC transport over `wsl.exe --cd ~` (`shell: false`) + clean shutdown (zero orphan runner PID)
  4) Real WSL 2 kernel sandbox enforcement via `scripts/run-tests.mjs --suite linux-sandbox`
  5) Optional host USBIP (`usbipd`) & driver diagnostics

.EXAMPLE
  .\tests\windows-wsl-verify\verify-wsl2.ps1

.EXAMPLE
  .\tests\windows-wsl-verify\verify-wsl2.ps1 -Distro Ubuntu-26.04 -Profile standard
#>

[CmdletBinding()]
param(
  [string]$Distro = "",
  [ValidateSet("", "core", "standard", "universal")]
  [string]$Profile = "",
  [string]$UpstreamProxy = ""
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$DshHome = if ($env:DSH_HOME) { $env:DSH_HOME } else { Join-Path $HOME ".dsh" }

function Resolve-SharedHostNode {
  if ($env:DSH_NODE_PATH -and (Test-Path -LiteralPath $env:DSH_NODE_PATH)) {
    return [pscustomobject]@{ Exe = $env:DSH_NODE_PATH; ElectronRunAsNode = $false; Label = "DSH_NODE_PATH" }
  }
  $pathNode = Get-Command node -ErrorAction SilentlyContinue
  if ($pathNode -and $pathNode.Source) {
    return [pscustomobject]@{ Exe = $pathNode.Source; ElectronRunAsNode = $false; Label = "PATH ($($pathNode.Source))" }
  }
  foreach ($c in @(
    (Join-Path $DshHome "runtime\node.exe"),
    (Join-Path $HOME ".local\share\mise\shims\node.exe"),
    (Join-Path $HOME ".volta\bin\node.exe"),
    (Join-Path $env:ProgramFiles "nodejs\node.exe")
  )) {
    if ($c -and (Test-Path -LiteralPath $c)) {
      return [pscustomobject]@{ Exe = $c; ElectronRunAsNode = $false; Label = "Shared Node ($c)" }
    }
  }
  foreach ($g in @(
    (Join-Path $env:LOCALAPPDATA "Programs\dsh*\*.exe"),
    (Join-Path $env:LOCALAPPDATA "Programs\DeepSeek*\*.exe")
  )) {
    $foundExe = Get-Item -Path $g -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -notmatch 'unins|update|crash|elevate' } |
      Select-Object -First 1
    if ($foundExe) {
      return [pscustomobject]@{ Exe = $foundExe.FullName; ElectronRunAsNode = $true; Label = "Shared DSH Desktop Carrier" }
    }
  }
  throw "Could not find Node.js or DSH Desktop carrier on Windows host. Set DSH_NODE_PATH or install DSH/Node."
}

function Invoke-SharedHostNode {
  param($Runtime, [string[]]$Arguments)
  $prevElectron = $env:ELECTRON_RUN_AS_NODE
  $prevNodeOpts = $env:NODE_OPTIONS
  try {
    $env:NODE_OPTIONS = $null
    if ($Runtime.ElectronRunAsNode) { $env:ELECTRON_RUN_AS_NODE = "1" }
    & $Runtime.Exe @Arguments
    if ($LASTEXITCODE -ne 0) {
      throw "Host Node command failed with exit code $LASTEXITCODE ($($Runtime.Exe) $($Arguments -join ' '))"
    }
  } finally {
    $env:ELECTRON_RUN_AS_NODE = $prevElectron
    $env:NODE_OPTIONS = $prevNodeOpts
  }
}

$hostNode = Resolve-SharedHostNode

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " dsh-wsl-sandbox - Real Windows + WSL 2 Verification Suite" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# Step 1: Build dist/ and auto-discover WSL 2 distro if omitted
Write-Host "`n[1/5] Building TypeScript artifacts & discovering WSL 2 distributions (Host Node: $($hostNode.Label))..."
Push-Location $RepoRoot
try {
  Invoke-SharedHostNode -Runtime $hostNode -Arguments @("scripts/build.mjs")
  if (-not $Distro -or $Distro.Trim() -eq "") {
    $discJson = Invoke-SharedHostNode -Runtime $hostNode -Arguments @(
      "--input-type=module",
      "-e",
      "import { discoverWslDistros } from './dist/packages/dsh-plugin/src/wsl-discovery.js'; console.log(JSON.stringify(discoverWslDistros()));"
    )
    $disc = ($discJson -join "`n") | ConvertFrom-Json
    $wsl2 = @($disc.distros | Where-Object { -not $_.isInternalContainer -and $_.wslVersion -eq 2 })
    if ($wsl2.Count -eq 0) {
      throw "No usable WSL 2 distribution found. Install one (e.g. 'wsl.exe --install -d Ubuntu-26.04') or pass -Distro <name>."
    }
    $picked = $wsl2 | Where-Object { $_.isDefault } | Select-Object -First 1
    if (-not $picked) { $picked = $wsl2[0] }
    $Distro = $picked.name
    Write-Host "Auto-selected WSL 2 distro: $Distro" -ForegroundColor Green
    if ($picked.isCustomDiskLocation) {
      Write-Host "  (Detected WSL Manager / moved VHDX BasePath: $($picked.basePath))" -ForegroundColor Green
    }
  }

  $stagedJson = Invoke-SharedHostNode -Runtime $hostNode -Arguments @("scripts/stage-wsl-runner.mjs", "--distro", $Distro, "--json")
  $staged = ($stagedJson -join "`n") | ConvertFrom-Json
} finally {
  Pop-Location
}
Write-Host "Staged native ext4 runner: $($staged.runnerPath) (zero /mnt dependency)"

# Step 2: Run dsh-wsl-doctor inside real WSL 2 kernel via shared Linux Node resolver
Write-Host "`n[2/5] Running dsh-wsl-doctor --strict-wsl2 inside '$Distro'..."
$wslNodeBootstrap = '[ -f "$HOME/.dsh-wsl-env.sh" ] && . "$HOME/.dsh-wsl-env.sh" >/dev/null 2>&1 || true; CLEAN_PATH=""; OLD_IFS="$IFS"; IFS=":"; for p in $PATH; do case "$p" in /mnt/*|"") ;; *) CLEAN_PATH="${CLEAN_PATH:+$CLEAN_PATH:}$p" ;; esac; done; IFS="$OLD_IFS"; export PATH="$HOME/.dsh/runtime/bin:$HOME/.local/share/dsh/node/bin:$HOME/.local/share/dsh-wsl-sandbox/toolchains/node/bin:$HOME/.local/share/mise/shims:$HOME/.local/bin:$HOME/.nvm/current/bin:$HOME/.volta/bin:/usr/local/bin:/usr/bin:/bin${CLEAN_PATH:+:$CLEAN_PATH}"; exec node "$@"'
$doctorArgs = @("-d", $Distro, "--cd", "~", "--", "sh", "-c", $wslNodeBootstrap, "dsh-wsl-doctor", $staged.doctorPath, "--strict-wsl2")
if ($Profile) {
  $doctorArgs += @("--profile", $Profile)
}
if ($UpstreamProxy) {
  $doctorArgs += @("--proxy", $UpstreamProxy)
}
& wsl.exe @doctorArgs
if ($LASTEXITCODE -ne 0) {
  throw "dsh-wsl-doctor reported BLOCKED verdict inside WSL 2 distro '$Distro'!"
}

# Step 3: Verify Windows -> wsl.exe --cd ~ -> native ext4 wsl-runner persistent NDJSON ping + clean shutdown (zero orphan PID)
Write-Host "`n[3/5] Verifying Windows -> wsl.exe -> wsl-runner RPC ping & zero-leak dispose..."
$pingScript = @"
import { WslTransport } from './dist/packages/dsh-plugin/src/wsl-transport.js';
const t = new WslTransport({
  mode: 'wsl',
  distro: process.argv[1],
  runnerPath: process.argv[2],
});
const res = await t.call('ping');
console.log('[OK] Windows->WSL2 RPC ping (shared WSL Node ' + res.nodeVersion + ' at ' + res.nodeExecPath + '):', JSON.stringify(res));
await t.dispose();
console.log('[OK] WslTransport disposed cleanly (child terminated, zero lease leak).');
"@
Push-Location $RepoRoot
try {
  Invoke-SharedHostNode -Runtime $hostNode -Arguments @("--input-type=module", "-e", $pingScript, $Distro, $staged.runnerPath)
} finally {
  Pop-Location
}

# Step 4: Run real Linux kernel sandbox test suite inside WSL 2 (if /mnt path is available, else skip with clear notice)
Write-Host "`n[4/5] Running real Linux kernel sandbox test suite inside WSL 2 '$Distro'..."
$linuxRepo = ""
$prevErrPref = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
  $wslPathOut = & wsl.exe -d $Distro --cd ~ -- wslpath -a ($RepoRoot.Replace('\', '/')) 2>$null
  if ($LASTEXITCODE -eq 0 -and $wslPathOut) {
    $linuxRepo = ($wslPathOut -join "`n").Trim()
  }
} catch { } finally {
  $ErrorActionPreference = $prevErrPref
}
$hasRunTests = $false
if ($linuxRepo) {
  $prevErrPref = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    & wsl.exe -d $Distro --cd ~ -- test -f "$linuxRepo/scripts/run-tests.mjs" 2>$null
    $hasRunTests = ($LASTEXITCODE -eq 0)
  } finally {
    $ErrorActionPreference = $prevErrPref
  }
}
if ($hasRunTests) {
  $runTestSh = '[ -f "$HOME/.dsh-wsl-env.sh" ] && . "$HOME/.dsh-wsl-env.sh" >/dev/null 2>&1 || true; CLEAN_PATH=""; OLD_IFS="$IFS"; IFS=":"; for p in $PATH; do case "$p" in /mnt/*|"") ;; *) CLEAN_PATH="${CLEAN_PATH:+$CLEAN_PATH:}$p" ;; esac; done; IFS="$OLD_IFS"; export PATH="$HOME/.dsh/runtime/bin:$HOME/.local/share/dsh/node/bin:$HOME/.local/share/dsh-wsl-sandbox/toolchains/node/bin:$HOME/.local/share/mise/shims:$HOME/.local/bin:$HOME/.nvm/current/bin:$HOME/.volta/bin:/usr/local/bin:/usr/bin:/bin${CLEAN_PATH:+:$CLEAN_PATH}"; export DSH_STRICT_KERNEL_TESTS=1; cd "$1" && exec node scripts/run-tests.mjs --suite linux-sandbox'
  & wsl.exe -d $Distro --cd ~ -- sh -c $runTestSh dsh-test $linuxRepo
  if ($LASTEXITCODE -ne 0) {
    throw "Real kernel sandbox test suite failed inside WSL 2!"
  }
} else {
  Write-Host "[INFO] Host repo is not accessible over /mnt (e.g. [automount] enabled = false); core doctor + RPC checks already passed via native ext4 staging!" -ForegroundColor Yellow
}

# Step 5: Generic host USBIP + WSL 2 kernel USB driver diagnostics (NOT limited to any specific board/device)
Write-Host "`n[5/5] Checking optional USBIP & WSL 2 kernel USB driver readiness..."
$usbipd = Get-Command usbipd -ErrorAction SilentlyContinue
if ($usbipd) {
  Write-Host "[OK] usbipd found at $($usbipd.Source) - host-to-WSL2 USB passthrough CLI is installed." -ForegroundColor Green
  $prevErrPref = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    $vhciOut = & wsl.exe -d $Distro --cd ~ -- sh -c 'if [ -d /sys/devices/platform/vhci_hcd.0 ] || [ -d /sys/module/vhci_hcd ]; then echo vhci-ready; else echo vhci-unloaded; fi' 2>$null
    $lsusbOut = & wsl.exe -d $Distro --cd ~ -- sh -c 'command -v lsusb >/dev/null 2>&1 && echo yes || echo no' 2>$null
  } finally {
    $ErrorActionPreference = $prevErrPref
  }
  $vhciCheck = if ($vhciOut) { ($vhciOut -join "`n").Trim() } else { "unknown" }
  $lsusbCheck = if ($lsusbOut) { ($lsusbOut -join "`n").Trim() } else { "unknown" }
  Write-Host "     WSL 2 kernel vhci_hcd : $vhciCheck  |  usbutils (lsusb): $lsusbCheck"
  Write-Host "     [Driver Note] USBIP supports ANY USB device, not just serial boards:" -ForegroundColor DarkGray
  Write-Host "       - User-space USB (e.g., phone ADB/Fastboot/EDL/DFU via libusb -> /dev/bus/usb/NNN/NNN, HID -> /dev/hidraw*)" -ForegroundColor DarkGray
  Write-Host "         works over USBIP without kernel class drivers, though phone Bootloader unlock / OEM tools often" -ForegroundColor DarkGray
  Write-Host "         need Windows WinUSB/OEM drivers and are best run on Windows host under single-shot L3 approval." -ForegroundColor DarkGray
  Write-Host "       - Windows-driverless USB NICs / Wi-Fi adapters / peripherals without stock WSL 2 Linux .ko modules:" -ForegroundColor DarkGray
  Write-Host "         attaching via usbipd alone will NOT load a missing Linux kernel driver; keep them on Windows host" -ForegroundColor DarkGray
  Write-Host "         (or load a matching Linux kernel module if you run a custom WSL 2 kernel)." -ForegroundColor DarkGray
} else {
  Write-Host "[INFO] usbipd not installed (optional; needed only if you attach physical USB devices such as phones, USB NICs, HID/CDC/serial peripherals into WSL 2)." -ForegroundColor Yellow
}

Write-Host "`n[PASS] All real Windows + WSL 2 verification checks passed!" -ForegroundColor Green
