# AGENTS.md — `dsh-wsl-sandbox`

## Trellis Project Memory & Portable Skills

This repository uses **Trellis**, **Grill-Me**, and **`dsh-wsl-env-setup`** to preserve architectural decisions, executable contracts, and security invariants across sessions:

- `.trellis/workflow.md` — Development phases, hard gates, and skill routing.
- `.trellis/spec/` — Package- and layer-scoped **executable code-specs** (read via `trellis-before-dev` BEFORE editing any code):
  - `.trellis/spec/guides/` — Security invariants & `dsh-purge` coexistence thinking guides.
  - `.trellis/spec/core/` — Core security kernel, `seccomp-bpf`, `bwrap`, `BashAstGuard`, `PwshGuard`, `ApprovalController`, `UdsProxy`.
  - `.trellis/spec/runner/` — In-distro persistent NDJSON runner & FS/process/PTY protocols.
  - `.trellis/spec/plugin/` — DSH Cordis bundle (`wsl_*` tools, prompt injection, host `pwsh` hook, approval bridge, Web UI).
  - `.trellis/spec/bootstrap/` — Zero-Docker/zero-kernel-build Agent-guided WSL environment provisioning & `dsh-wsl-doctor`.
- `.trellis/tasks/` — Active and archived task PRDs (`11-23-dsh-wsl-sandbox/prd.md`).
- `.trellis/workspace/` — Per-developer session journals.
- `.agents/skills/` — 10 portable skills (`trellis-*` × 8, `grill-me`, `dsh-wsl-env-setup`) usable across DSH, Codex, Claude Code, Cursor, OpenCode, and Antigravity.

## Non-Negotiable Rules

1. **Grill before building**: Never silently invent architectural or security-tradeoff decisions. Resolve the design tree with the user via `grill-me` and confirm shared understanding before implementing.
2. **Code-Spec before code**: Every cross-layer contract, IPC message, `seccomp-bpf` rule, `bwrap` mount order, approval state transition, and DSH plugin coexistence rule MUST live in `.trellis/spec/`.
3. **Zero silent fallback & zero host plugin breakage**: Never fall back from WSL 2 to Windows `pwsh`, never run unconfined on sandbox failure, and never overwrite DSH stock services or break host-installed plugins (`dsh-purge`).
4. **Zero Docker / Zero Kernel Build on Laptops**: Environment setup uses official prebuilt WSL 2 distros + binary-only Agent-guided steps (`dsh-wsl-env-setup`) verified by `dsh-wsl-doctor`.
5. **Honest verification**: Explicitly distinguish real Linux kernel `bwrap + seccomp-bpf` tests run locally from Windows + real WSL 2 verification scripts.
