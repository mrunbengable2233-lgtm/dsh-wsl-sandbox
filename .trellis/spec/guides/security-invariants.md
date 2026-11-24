# Security Invariants Thinking Guide

Before implementing or modifying any code in `core`, `wsl-runner`, `dsh-plugin`, or `bootstrap`, check every invariant below:

## 1. Zero Silent Fallback (Fail-Closed Everywhere)
- Never fall back from WSL 2 to Windows `pwsh`, never switch to a default distro, and never launch unconfined when `bwrap`, `seccomp`, unprivileged userns, or socket probes fail.
- Never silently treat exit code `0` as sandbox verification; functional synthetic probes must verify both **allowed workspace writes succeed** AND **disallowed writes/syscalls fail**.

## 2. Trust Boundary Separation (Human Control Plane vs. Model Execution)
- Directory authorizations (`/shares/<alias>`), hardware device passthrough (`/dev/ttyUSB*`, `/dev/ttyACM*`, `/dev/bus/usb/*`), network allowlists, local lab CIDRs, `.env*` unmask toggles, and approval policy tiers live ONLY in the human config store / Web API.
- **Never** register config mutations as model tools or accept model-generated `confirmed: true`.
- Basic settings UI MUST hide any `/mnt` full-drive mount option; `/shares/<alias>` and physical device passthrough belong strictly under **Advanced**, off by default, and revocable with immediate `generation++` + process-tree termination.

## 3. WSL 2 Escape Surface Checklist
Every confined execution in `bwrap` MUST address all of:
1. `--unshare-user`, `--disable-userns`, `--unshare-pid`, `--unshare-ipc`, `--unshare-net`, `--new-session`, `--die-with-parent`.
2. Private `--tmpfs /tmp` and `--tmpfs /var/tmp` (NEVER deny `/tmp` — breaks `<<EOF`, compilers, `pytest`, `mktemp`).
3. WSL 2 overlays: `--tmpfs /run/WSL`, `--tmpfs /mnt`, `--tmpfs /mnt/wsl`, `--tmpfs /mnt/wslg/distro`, plus X11/PulseAudio sockets (`/tmp/.X11-unix`, `/mnt/wslg/.X11-unix`, `/mnt/wslg/PulseServer`).
4. High-risk host/container/agent sockets (`readlink -f` + `--ro-bind /dev/null`, fail-closed on probe error): D-Bus, systemd private bus, Docker, Podman, containerd, cri-o, k3s, `$SSH_AUTH_SOCK`, `$GPG_AGENT_INFO`.
5. `seccomp-bpf` (`x86_64` & `aarch64`): block `io_uring_*`, `AF_VSOCK (40)`, x32 ABI (`nr >= 0x4000_0000`), `ptrace`, `process_vm_*`, `mount*`, `unshare`/`setns`, `bpf`, `kexec*`, `*_module`, `*_key`/`keyctl`, and non-`AF_UNIX` sockets when `--unshare-net` is active.
6. Checklist B workspace read-only locks (applied AFTER `--bind <workspace>`) + nonexistent placeholder binds + depth ≤ 3 `.env*` read masking (shared identically by `bwrap` and `wsl-runner` FS service).
7. Strict env scrubbing (`WSL_INTEROP`, `WSLENV`, `DISPLAY`, `LD_PRELOAD`, `BASH_ENV`, `PROMPT_COMMAND`, `NODE_OPTIONS`, `GIT_SSH_COMMAND`, `PYTHONPATH`, etc.).
8. `prlimit` quotas (`RLIMIT_NPROC`, `RLIMIT_NOFILE`, `RLIMIT_FSIZE`) + `PGID` TERM→KILL teardown.

## 4. Approval & Hardware Safety Invariants
- Never use a single global `pending` slot; always use `Map<ApprovalRequestId, PendingApprovalEntry>`.
- Every grant binds `requestId` + `actionHash` (SHA-256 over immutable binding + action) + `ttlMs` + single-use `consumed` flag + `assertCurrent()` pre-exec check.
- Never allow `BANNED_PREFIX_SUGGESTIONS` (POSIX shells/interpreters/git/env AND PowerShell `pwsh`/`powershell`/`cmd`/`wsl`/`iex`/`Start-Process`) to be saved as session auto-allow rules.
- **Physical Device Rule (Q13)**: Any execution involving enabled `--dev-bind` physical devices, flashing/serial tools (`esptool`, `idf.py flash`, `openocd`, `avrdude`, `st-flash`, `dfu-util`, `minicom`, `picocom`), or host `usbipd bind/attach/detach` MUST automatically downgrade to single-shot manual `allow-once` approval (session-prefix caching forbidden).

## 5. Network & SSRF Invariants (Q5 + Q16)
- Keep `--unshare-net` enabled even in default `allowlist-proxy` mode; bridge allowed outbound traffic strictly via a Unix Domain Socket (`UdsProxy`) into the trusted proxy outside the netns.
- Always resolve hostnames before connecting and block all private/loopback/link-local/metadata ranges (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `::1`, `fc00::/7`, `fe80::/10`) UNLESS matched by a human-configured Advanced local lab CIDR/port entry.
