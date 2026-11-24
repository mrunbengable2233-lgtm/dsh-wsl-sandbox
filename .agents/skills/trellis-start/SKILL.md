---
name: trellis-start
description: "Initializes an AI development session by reading workflow guides, developer identity, git status, active tasks, and project guidelines from .trellis/. Classifies incoming tasks and routes to brainstorm, direct edit, or task workflow. Use when beginning a new coding session, resuming work, starting a new task, or re-establishing project context."
---

# Start Session

1. Run `python3 ./.trellis/scripts/get_context.py` for identity, git status, current task, and active tasks.
2. Run `python3 ./.trellis/scripts/get_context.py --mode phase` for workflow overview (full guide in `.trellis/workflow.md`).
3. Run `python3 ./.trellis/scripts/get_context.py --mode packages` and read `.trellis/spec/guides/index.md` plus relevant `.trellis/spec/<layer>/index.md`.
4. Route next action: active task with `prd.md` → `trellis-before-dev`; active task without `prd.md` → `trellis-brainstorm` / `grill-me`; no active multi-step task → answer directly.
