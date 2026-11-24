---
name: trellis-finish-work
description: "Wrap up the current session: verify quality gate passed, remind user to commit, archive completed tasks, and record session progress to the developer journal. Use when done coding and ready to end the session."
---

# Finish Work

1. Run `python3 ./.trellis/scripts/get_context.py --mode record`.
2. Classify dirty paths via `git status --porcelain` (ensure current-task code is verified & committed before archiving).
3. Archive completed tasks via `python3 ./.trellis/scripts/task.py archive <task-name>`.
4. Record session journal via `python3 ./.trellis/scripts/add_session.py --title "..." --commit "..." --summary "..."`.
