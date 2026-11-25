# Shared Thinking Guides Index

> Thinking guides tell AI **what to check and verify** before editing any package. Concrete TypeScript signatures, syscall tables, and error matrices live in `.trellis/spec/<layer>/`.

## Mandatory Guides (Read Before Any Non-Trivial Edit)

1. [security-invariants.md](./security-invariants.md) — Fail-closed rules, WSL 2 escape surfaces, TOCTOU protection, env scrubbing, approval binding, physical device auto-downgrade, and SSRF defense.
2. [host-plugin-coexistence.md](./host-plugin-coexistence.md) — Zero-conflict architecture guarantees for coexisting with `dsh-purge` and other host DSH Cordis plugins.

## Package Spec Layers

- [core/index.md](../core/index.md) — Control plane, `SessionBinding`, `BwrapBuilder`, `SeccompBpf`, `BashAstGuard`, `PwshGuard`, `ApprovalController`, `UdsProxy`.
- [runner/index.md](../runner/index.md) — In-distro persistent NDJSON runner, probes, TOCTOU-safe FS service, process & PTY manager.
- [plugin/index.md](../plugin/index.md) — DSH Cordis bundle (`wsl_*` tools, `ctx.systemPrompt` incremental section, `AGENTS.md` injector, host `pwsh` guard hook, approval bridge, Web UI/API).
- [bootstrap/index.md](../bootstrap/index.md) — Codex-aligned `core` / `standard` / `universal` toolchains, `--mirror cn`, upstream proxy, `dsh-wsl-doctor`.
