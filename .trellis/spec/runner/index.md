# `packages/runner` Spec Index

In-distro persistent Node 22 ESM runner (`wsl-runner`) speaking framed NDJSON over stdio with zero 9P dependency and zero `systemd` hard requirement.

## Pre-Development Checklist
1. Read [protocol.md](./protocol.md) for NDJSON request/response schemas, TOCTOU-safe FS constraints, and process-group cleanup rules.
2. Read [../core/contracts.md](../core/contracts.md) and [../guides/security-invariants.md](../guides/security-invariants.md).

## Quality Check
- Real Linux integration tests (`tests/linux-sandbox/`) execute against the real `wsl-runner` child process spawning real `bwrap --seccomp <fd>` + `prlimit`.
- Closing stdin or sending `invalidate` terminates all active child process groups and empties tracked handles.
