# Trellis Development Workflow (`dsh-wsl-sandbox`)

## Core Loop

1. **Phase 0 — Session Start (`trellis-start`)**
   - Run `python3 ./.trellis/scripts/get_context.py` to inspect developer identity, active tasks, git status, and `.trellis/spec/` layers.
2. **Phase 1 — Requirements & Design Grilling (`grill-me` + `trellis-brainstorm`)**
   - Ensure a task exists under `.trellis/tasks/`.
   - Run `grill-me` (design-tree frontier rounds) to resolve all architectural, security, UX, and plugin-coexistence branches before writing code.
   - Persist every settled decision into `{TASK_DIR}/prd.md` (and `design.md` / `implement.md` for complex slices).
   - **Hard Gate**: Do NOT start coding until the frontier is empty and the user explicitly confirms shared understanding.
3. **Phase 2 — Executable Code-Spec Hydration (`trellis-spec-bootstrap` / `trellis-update-spec`)**
   - Distill confirmed architecture decisions into modular, executable code-specs under `.trellis/spec/<layer>/` (concrete TypeScript signatures, NDJSON wire contracts, BPF syscall tables, validation/error matrices, Good/Base/Bad cases, and test assertion points).
4. **Phase 3 — Implementation & Verification (`trellis-before-dev` → code → `trellis-check`)**
   - Before touching any layer, read `.trellis/spec/<layer>/index.md`, referenced spec docs, and `.trellis/spec/guides/index.md`.
   - State the change boundary for non-trivial changes.
   - After editing, run `trellis-check` (type-check, lint, unit tests, real Linux `bwrap + seccomp-bpf` tests, plugin-coexistence tests, cross-layer review).
   - If a bug occurs or repeats, run `trellis-break-loop` and update `.trellis/spec/` immediately.
5. **Phase 4 — Capture & Close (`trellis-update-spec` + `trellis-finish-work`)**
   - Sync any newly discovered invariants or gotchas into `.trellis/spec/`.
   - Archive completed tasks and record the session journal under `.trellis/workspace/`.

## Skill Routing Table

| Situation | Required Skill |
|---|---|
| Starting or resuming a session | `trellis-start` |
| Stress-testing architecture / unresolved design decisions | `grill-me` |
| Scoping a new feature or writing PRD | `trellis-brainstorm` |
| Creating or refreshing `.trellis/spec/` | `trellis-spec-bootstrap` |
| Right before writing code in any package | `trellis-before-dev` |
| After writing code / before committing | `trellis-check` |
| After fixing a non-trivial or recurring bug | `trellis-break-loop` |
| After learning an invariant, contract, or gotcha | `trellis-update-spec` |
| Wrapping up a coding session | `trellis-finish-work` |
