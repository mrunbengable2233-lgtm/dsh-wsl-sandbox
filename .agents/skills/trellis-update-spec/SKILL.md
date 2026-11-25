---
name: trellis-update-spec
description: "Captures executable contracts and coding conventions into .trellis/spec/ documents. Use when learning something valuable from debugging, implementing, or discussion that should be preserved for future sessions."
---

# Update Code-Spec - Capture Executable Contracts

**Code-Spec First Rule**: Every infra or cross-layer spec update MUST include concrete executable contracts (7 sections):
1. Scope / Trigger
2. Signatures (command / API / protocol)
3. Contracts (request / response / env)
4. Validation & Error Matrix
5. Good / Base / Bad Cases
6. Tests Required (with assertion points)
7. Wrong vs Correct

Keep "how to implement" in `.trellis/spec/<layer>/*.md` and "what to think about" checklists in `.trellis/spec/guides/*.md`. Always keep `index.md` synced.
