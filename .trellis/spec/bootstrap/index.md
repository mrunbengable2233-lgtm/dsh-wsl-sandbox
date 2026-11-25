# `packages/bootstrap` Spec Index

Laptop-friendly, **zero-Docker / zero-kernel-build** WSL 2 environment provisioning driven by an **Agent-guided prompt/skill (`dsh-wsl-env-setup`)**, backed by idempotent step scripts (`provision-wsl.sh`) with China mirror/proxy support (`--mirror cn`, `--proxy`) and the `dsh-wsl-doctor` diagnostic CLI.

## Pre-Development Checklist
1. Read [toolchains.md](./toolchains.md) for the Agent-guided workflow, selectable Codex-aligned profiles (`core` / `standard` / `universal`), China mirror configs, and `dsh-wsl-doctor` checks.
2. **Hard Constraint (Q18)**: Do NOT require Docker Desktop image builds or Linux kernel compilation on the user's laptop. Rely strictly on official Microsoft Store / `wsl --install` Ubuntu 24.04 (or existing WSL 2 distro) + lightweight `apt` / `mise` / `uv` / `pnpm` binary installs executed step-by-step by the user or an approved setup Agent.
3. Never modify `/etc/wsl.conf` or `%USERPROFILE%\.wslconfig` automatically; only print read-only diagnostics if WSL 2 settings are suboptimal.

## Quality Check
- `bash -n packages/bootstrap/provision-wsl.sh` passes with zero errors.
- `dsh-wsl-env-setup/SKILL.md` provides deterministic, idempotent, human-approved step-by-step instructions with rollback/resume semantics.
- `node packages/bootstrap/src/doctor.ts --json` executes cleanly on Linux and outputs verified sandbox + toolchain diagnostics.
