# `packages/dsh-plugin` Spec Index

DSH Cordis plugin bundle (`dsh-wsl-sandbox`) supporting both Electron Desktop App (`desktop` profile) and CLI (`dsh web` / `dsh headless`), designed for 100% peaceful coexistence with `dsh-purge` and all host plugins.

## Pre-Development Checklist
1. Read [coexistence.md](./coexistence.md) for Cordis bundle layout, tool registration, prompt injection, `PwshGuard` hook, approval bridge, and Web API/UI contracts.
2. Read [../guides/host-plugin-coexistence.md](../guides/host-plugin-coexistence.md).
3. Read [../core/contracts.md](../core/contracts.md) and [../runner/protocol.md](../runner/protocol.md).

## Quality Check
- `tests/plugin-coexistence/` passes with simulated `dsh-purge` (`system-prompt` override, `postPrompt`, `hooksDenyBypass: true`, custom tools/routes) co-installed.
- Zero overwrites of DSH stock service rows in `cordis.patch.yml`.
- Zero native `node-gyp` dependencies in `package.json`.
