# `packages/core` — Executable Code-Spec Contracts

## 1. Error Vocabulary (`src/errors.ts`)

Every controlled failure throws `SandboxError` with a stable `code: SandboxErrorCode`:

```ts
export type SandboxErrorCode =
  | 'INVALID_SETUP'
  | 'INVALID_ACTION'
  | 'BACKEND_UNAVAILABLE'
  | 'SANDBOX_UNAVAILABLE'
  | 'SANDBOX_PREPARATION_FAILED'
  | 'POLICY_BLOCK'
  | 'STALE_BINDING'
  | 'REVIEW_DENIED'
  | 'REVIEW_TIMEOUT'
  | 'REVIEW_CANCELLED'
  | 'REVIEW_UNAVAILABLE'
  | 'REVIEW_INVALID'
  | 'REVIEW_ERROR'
  | 'GRANT_CONSUMED'
  | 'COMMAND_NOT_FOUND'
  | 'PROCESS_EXIT'
  | 'TIMEOUT'
  | 'CANCELLED'
  | 'OUTPUT_LIMIT';
```

## 2. Session Binding (`src/binding.ts`)

### Signatures & Validation Matrix
- `validateProbeAndCreateBinding(probe: WslProbeResult, generation: number): SessionBinding`
- `validateWorkspaceRoot(linuxPath: string, username?: string): string`

| Condition | Error Code |
| :--- | :--- |
| `backend !== 'wsl'` or `wslVersion !== 2` | `BACKEND_UNAVAILABLE` |
| `uid <= 0` or non-integer | `BACKEND_UNAVAILABLE` |
| `sandboxReady !== true` | `SANDBOX_UNAVAILABLE` |
| `cwd` or `workspaceRoot` is `/`, `/mnt*`, `/etc*`, `/usr*`, `/var*`, `/proc*`, `/sys*`, `/dev*`, `/run*`, `/home/<user>` (entire home), contains `\0`, relative, or `..` | `POLICY_BLOCK` |
| `cwd` outside `workspaceRoot` or under `/mnt/wslg/distro` | `POLICY_BLOCK` |
| `distribution` matches internal container distro (`docker-desktop`, `docker-desktop-data`, `rancher-desktop*`, `podman-machine*`) | `BACKEND_UNAVAILABLE` |

## 3. Environment Sanitizer (`src/env-sanitizer.ts`)

- Strips all dangerous injection variables (`WSL_INTEROP`, `WSLENV`, `DISPLAY`, `WAYLAND_DISPLAY`, `PULSE_SERVER`, `SSH_AUTH_SOCK`, `SSH_AGENT_PID`, `GPG_AGENT_INFO`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `BASH_ENV`, `ENV`, `PROMPT_COMMAND`, `CDPATH`, `NODE_OPTIONS`, `PYTHONSTARTUP`, `PYTHONPATH`, `GIT_SSH_COMMAND`, `GIT_EXEC_PATH`, `PERL5OPT`, `RUBYOPT`) plus all ambient `DSH_*`.
- Builds clean allowlisted environment (`PATH`, `HOME`, `TMPDIR=/tmp`, `LANG=C.UTF-8`, `LC_ALL=C.UTF-8`, `TERM`, `TZ`, optional cache vars pointing to workspace cache or `/tmp`, optional UDS proxy shim env `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`, then fresh managed `dshEnv` last).

## 4. Checklist B & `.env*` Masking (`src/dangerous-paths.ts`)

- `DANGEROUS_FILES`: `.gitconfig`, `.gitmodules`, `.bashrc`, `.bash_profile`, `.zshrc`, `.zprofile`, `.profile`, `.ripgreprc`, `.mcp.json`.
- `DANGEROUS_DIRECTORIES`: `.git/hooks`, `.git/config`, `.git/HEAD`, `.vscode`, `.idea`, `.claude/commands`, `.claude/agents`, `.agents`, `.codex`, `.gemini`, `.dsh`.
- `isProtectedWritePath(workspaceRoot, targetPath)`: returns `{ blocked: true, reason }` for any path equal to or nested inside `DANGEROUS_FILES` or `DANGEROUS_DIRECTORIES` (case-sensitive POSIX + symlink-resolved canonical path).
- `isEnvSecretPath(relPath)`: matches `.env` and `.env.*` (excluding `.env.example`, `.env.sample`, `.env.template`), scanned to depth ≤ 3 skipping `.git`, `node_modules`, `.venv`, `__pycache__`, `dist`, `build`, `target`.

## 5. `bwrap` Builder (`src/bwrap-builder.ts`)

### Mount Precedence (STRICT ORDER — Verified on Linux 6.18 / `bubblewrap 0.9.0`)
1. Namespace flags: `--unshare-user`, `--disable-userns` (when supported), `--unshare-pid`, `--unshare-ipc`, `--unshare-net`, `--new-session`, `--die-with-parent`.
2. **Base filesystem over implicit tmpfs `/`**: Instead of `--ro-bind / /` (which causes `EROFS` when `bwrap` tries to `mkdir /shares` or `/run/dsh-proxy` on read-only `/` or `/run`), enumerate top-level entries of `/` (excluding `dev`, `proc`, `sys`, `tmp`, `run`, `mnt`, `shares`) and bind each via `--ro-bind` (or recreate top-level symlinks via `--symlink`), then mount `--dev /dev`, `--proc /proc`, `--ro-bind /sys /sys`, `--tmpfs /tmp`, `--tmpfs /var/tmp`, `--tmpfs /run`, `--tmpfs /mnt`.
3. **Atomic WSL 2 & socket escape masking**: `--tmpfs /run` atomically hides `/run/WSL`, `/run/dbus`, `/run/docker.sock`, `/run/podman`, `/run/containerd`, `/run/crio`, `/run/k3s`, `/run/user/*` (and `/var/run` via symlink). `--tmpfs /mnt` atomically hides `/mnt/c`, `/mnt/wsl`, `/mnt/wslg/distro`, WSLg X11 & PulseAudio. Any additional non-`/run`/non-`/tmp`/non-`/mnt` sockets (`$SSH_AUTH_SOCK`, `$GPG_AGENT_INFO`) are masked with `--ro-bind /dev/null <resolvedSocketPath>`.
4. **Controlled UDS proxy socket mount** (when `networkMode === 'allowlist-proxy'`): `--tmpfs /run/dsh-proxy` + `--bind <proxySocketPath> /run/dsh-proxy/proxy.sock`.
5. **Advanced single-directory shares**: `--tmpfs /shares` + `--ro-bind` (default) or `--bind` (`rw`) to `/shares/<alias>`.
6. **Root lock**: `--remount-ro /` immediately after top-level mountpoints so `/` itself is read-only (`touch /evil` → `EROFS`).
7. **Workspace & cache mounts** (`workspace-write` only): `--bind <workspaceRoot> <workspaceRoot>`, optional `--bind <cacheDir> <cacheDir>`.
8. **Checklist B read-only overlays** (applied AFTER `--bind <workspaceRoot>`): `--ro-bind <existing>` for existing dangerous files/dirs; `--ro-bind /dev/null <nonexistent>` for missing dangerous files/dirs (returned in `BwrapBuildResult.createdPlaceholders` so `ConfinedProcManager` refcounts & unlinks the 0-byte mountpoint files on exit with zero `git status` pollution); `--ro-bind <emptyMaskFile> <envFile>` for masked `.env*` files.
9. **Optional Advanced physical device mounts**: `--dev-bind <devicePath> <devicePath>` ONLY for explicit `/dev/ttyUSB*`, `/dev/ttyACM*`, `/dev/bus/usb/*` paths approved by human.
10. `--seccomp <fd>` + `--chdir <cwd>` + `--` + `prlimit --nproc=... --nofile=... --fsize=... --` + `argv`.

## 6. Pure-TS `seccomp-bpf` Compiler (`src/seccomp-bpf.ts`)

### Signatures
- `compileSeccompBpf(options: { arch: 'x86_64' | 'aarch64'; blockNetworkSockets: boolean }): Buffer`

### Syscall Numbers (Verified Linux Kernel ABI)
- **`x86_64` (`AUDIT_ARCH_X86_64 = 0xc000003e`)**:
  - Reject x32 ABI: `nr >= 0x40000000` → `EPERM`
  - `ptrace=101`, `mount=165`, `umount2=166`, `swapon=167`, `swapoff=168`, `reboot=169`, `chroot=161`, `pivot_root=155`, `init_module=175`, `delete_module=176`, `kexec_load=246`, `add_key=248`, `request_key=249`, `keyctl=250`, `unshare=272`, `setns=308`, `process_vm_readv=310`, `process_vm_writev=311`, `kcmp=312`, `finit_module=313`, `kexec_file_load=320`, `bpf=321`, `io_uring_setup=425`, `io_uring_enter=426`, `io_uring_register=427`, `open_tree=428`, `move_mount=429`, `fsopen=430`, `fsmount=432`
  - `socket=41`, `socketpair=53`: always block `arg0 == 40 (AF_VSOCK)`; when `blockNetworkSockets === true`, allow ONLY `arg0 == 1 (AF_UNIX)` (and return `EACCES` for all others).
- **`aarch64` (`AUDIT_ARCH_AARCH64 = 0xc00000b7`)**:
  - `ptrace=117`, `mount=40`, `umount2=39`, `swapon=224`, `swapoff=225`, `reboot=142`, `chroot=51`, `pivot_root=41`, `init_module=105`, `delete_module=106`, `kexec_load=104`, `add_key=217`, `request_key=218`, `keyctl=219`, `unshare=97`, `setns=268`, `process_vm_readv=270`, `process_vm_writev=271`, `kcmp=272`, `finit_module=273`, `kexec_file_load=294`, `bpf=280`, `io_uring_setup=425`, `io_uring_enter=426`, `io_uring_register=427`, `open_tree=428`, `move_mount=429`, `fsopen=430`, `fsmount=432`
  - `socket=198`, `socketpair=199`: same `AF_VSOCK` / `AF_UNIX` arg0 filtering.

## 7. Bash AST Guard (`src/bash-ast-guard.ts`) & PowerShell Guard (`src/pwsh-guard.ts`)

- Both return a unified `GuardEvaluation`:
  ```ts
  export interface GuardEvaluation {
    decision: 'allow' | 'ask' | 'deny';
    riskLevel: 'safe' | 'elevated' | 'high' | 'critical';
    code?: 'POLICY_BLOCK';
    reasons: string[];
    unwrappedCommands: string[][];
    touchesPhysicalDevice: boolean;      // true => forces allow-once manual approval!
    requiresSessionRuleBlocked: boolean; // true => banned prefix or hardware op
    suggestedPrefix?: string[];          // undefined if banned!
    externalPaths: string[];
  }
  ```
- **Bash Guard**: `$IFS` normalization, `MAX_GUARD_CHARS = 65536`, `MAX_WRAPPER_DEPTH = 8`, quote-aware lexer splitting `;`/`&`/`&&`/`||`/`|`/`\n`, command substitution `$()` / backtick / process substitution `<()`/`>()` extraction, redirection target extraction, wrapper peeling (`sudo`, `doas`, `env`, `trap`, `command`, `exec`, `nohup`, `nice`, `ionice`, `time`, `timeout`, `stdbuf`, `setsid`, `xargs`, `runuser`, nested `sh/bash/dash/zsh/ksh/ash/busybox/eval`), Checklist A L0/L3 rules, physical device tool & `/dev/tty*`/`/dev/bus/usb` detection.
- **PowerShell Guard (`PwshGuard`)**:
  - Decodes `-EncodedCommand` / `-enc` / `-e` / `-ec` (UTF-16LE Base64) and recursively re-evaluates!
  - Normalizes backtick obfuscation (e.g. `` i`ex `` → `iex`, `` w`sl.exe `` → `wsl.exe`).
  - Peels wrappers (`powershell`/`pwsh -c`, `cmd /c`, `&`, `.`, `Start-Process`, `iex`/`Invoke-Expression`).
  - **L0 Hard Deny**: `Format-Volume`, `Clear-Disk`, `Initialize-Disk`, `Remove-Partition`, `diskpart`, `format.com`, `bcdedit`, `cipher /w`, `Stop-Computer`, `Restart-Computer`, `shutdown /s|/r|/p`, `Set-MpPreference -DisableRealtimeMonitoring`, `Add-MpPreference -ExclusionPath`, `vssadmin delete shadows`, `wevtutil cl`, `reg save HKLM\SAM|SYSTEM|SECURITY`, editing `.wslconfig` or `\\wsl.localhost\...\etc\wsl.conf|fstab`, `wsl --import|--unregister|--shutdown|--set-default`, `wsl -u root`.
  - **L3 Approval**: invoking `wsl.exe` / `bash.exe` (sandbox bypass prevention), `Remove-Item`/`rm`/`ri`/`del`/`rd`/`rmdir` with `-Recurse` or `-Force`, `cmd /c rd /s /q`, `reg delete`, `Set-ExecutionPolicy Bypass|Unrestricted`, `Start-Process -Verb RunAs`, `schtasks /create`, `Register-ScheduledTask`, `New-Service`/`sc create|delete|config`, `icacls`/`takeown`/`Set-Acl`, `iwr`/`irm`/`curl ... | iex`, `certutil -urlcache`, `bitsadmin /transfer`.
  - **Hardware Device Downgrade (Q13)**: `usbipd bind|attach|detach|unbind` → `ask` with `touchesPhysicalDevice: true` (always `allow-once`); `usbipd list|state` & `Get-PnpDevice` → `allow` (non-disruptive!).

## 8. Concurrent Approval Controller (`src/approval-controller.ts`)

- Stores concurrent pending approvals in `Map<ApprovalRequestId, PendingApprovalEntry>` (zero `REVIEW_BUSY`).
- Computes canonical SHA-256 `actionHash` over `{ binding, action }`.
- Decisions: `'allow-once' | 'allow-session-rule' | 'deny' | 'deny-with-guidance'`.
- Enforces `BANNED_PREFIX_SUGGESTIONS` (both POSIX and PowerShell) AND `touchesPhysicalDevice === true` → silently downgrades/rejects session caching so only single-shot `allow-once` executes.
- `invalidate()` increments `generation`, clears active binding, clears session rules, and aborts EVERY entry in the pending `Map`.

## 9. UDS Outbound Allowlist Proxy (`src/uds-proxy.ts`)

- Listens on a private Unix Domain Socket (`0600`) mounted into `bwrap` at `/run/dsh-proxy/proxy.sock`.
- Supports HTTP proxy requests and HTTPS `CONNECT host:port`.
- Checks target host against default dev registry allowlist + user custom allowlist + dynamic session-approved hosts.
- Resolves target IP via DNS (unless forwarded through an authenticated upstream proxy, in which case literal IP & hostname checks still run before upstream delegation) and blocks all private/loopback/link-local/metadata IPs UNLESS matched by human-configured Advanced `localLabCidrs` / `localLabPorts`.
- Supports upstream proxy chaining (`http://` CONNECT tunneling to Clash/Mihomo/v2rayN and `socks5://` RFC 1928 handshake).

## 10. Good / Base / Bad Cases & Wrong vs Correct
- **Good**: `git status`, `pytest`, `cat <<EOF > /tmp/a`, `usbipd list` → allowed cleanly.
- **Base**: `rm -rf ./dist`, `git reset --hard`, `usbipd attach --wsl --busid 1-2` → `ask` (and `usbipd attach` forces `allow-once`, never session-cached).
- **Bad**: `mkfs.ext4 /dev/sda`, `wsl.exe -u root`, `pwsh -enc <base64 of Remove-Item -Recurse -Force C:\>`, `socket(AF_VSOCK)` → `deny` / kernel `EPERM`.
- **Wrong**: Matching `argv[0] === 'rm'` only, or caching `['bash', '-c']` in session rules.
- **Correct**: Recursively peel wrappers up to depth 8, decode Base64 PowerShell `-enc`, and enforce `BANNED_PREFIX_SUGGESTIONS` on both request suggestion AND approval persistence.
