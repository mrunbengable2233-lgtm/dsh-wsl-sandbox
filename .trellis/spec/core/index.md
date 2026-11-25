# `packages/core` Spec Index

Platform-neutral security kernel, AST & PowerShell guards, concurrent approval control plane, `bwrap` command builder, `seccomp-bpf` bytecode compiler, and UDS outbound proxy.

## Pre-Development Checklist
1. Read [contracts.md](./contracts.md) for all executable TypeScript interfaces, syscall numbers, error matrices, and Good/Base/Bad cases.
2. Read [../guides/security-invariants.md](../guides/security-invariants.md).
3. Ensure zero external runtime native dependencies (`node:*` stdlib only in `packages/core`).

## Quality Check
- `npm run typecheck` passes with strict mode (`exactOptionalPropertyTypes`, `noUncheckedIndexedAccess` / strict null checks).
- All unit tests under `tests/unit/` pass (`node --test`).
- Every new guard rule or error code has explicit Good / Base / Bad test cases.
