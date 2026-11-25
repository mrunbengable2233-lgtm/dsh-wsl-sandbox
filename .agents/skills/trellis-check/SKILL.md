---
name: trellis-check
description: "Comprehensive quality verification: spec compliance, lint, type-check, tests, cross-layer data flow, code reuse, and consistency checks. Use when code is written and needs quality verification, before committing changes, or to catch context drift during long sessions."
---

# Code Quality Check

1. Inspect changes: `git diff --name-only HEAD && git status`.
2. Re-read task `prd.md` and `.trellis/spec/<layer>/index.md` Quality Check sections for every touched layer.
3. Run project build, type-check, lint, unit tests, real Linux sandbox tests, and host-plugin coexistence tests.
4. Verify Code Quality, Test Coverage, Spec Sync (`.trellis/spec/`), and Cross-Layer Dimensions (data flow, code reuse, imports, consistency).
5. Fix violations and re-run all checks before reporting done.
