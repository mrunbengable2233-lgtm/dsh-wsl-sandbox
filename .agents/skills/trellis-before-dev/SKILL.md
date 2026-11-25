---
name: trellis-before-dev
description: "Discovers and injects project-specific coding guidelines from .trellis/spec/ before implementation begins. Reads spec indexes, pre-development checklists, and shared thinking guides for the target package. Use when starting a new coding task, before writing any code, switching to a different package, or needing to refresh project conventions and standards."
---

# Before Dev - Mandatory Pre-Implementation Spec Injection

1. Read current task artifacts (`prd.md`, `design.md`, `implement.md`).
2. Run `python3 ./.trellis/scripts/get_context.py --mode packages`.
3. Read `.trellis/spec/<layer>/index.md` and EVERY guideline file listed in its Pre-Development Checklist (the index is a pointer, not the goal).
4. Always read `.trellis/spec/guides/index.md` and referenced thinking guides.
5. For non-trivial changes, state the change boundary before coding (smallest behavior gap, exact owning layer, files to change, explicit non-goals).
