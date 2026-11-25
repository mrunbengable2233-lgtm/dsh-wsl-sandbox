---
name: trellis-brainstorm
description: "Guides collaborative requirements discovery before implementation. Creates task directory, seeds PRD, asks high-value questions one at a time, researches technical choices, and converges on MVP scope. Use when requirements are unclear, there are multiple valid approaches, or the user describes a new feature or complex task."
---

# Brainstorm - Requirements Discovery

1. **Task-first**: `python3 ./.trellis/scripts/task.py create "<goal>" --description "<summary>" --slug <auto>` and seed `prd.md`.
2. **Action before asking**: Inspect repo/specs/research first; never ask derivable or meta questions.
3. **Research-first**: For technical choices, compare 2–4 real patterns, map onto repo constraints, persist to `{TASK_DIR}/research/<topic>.md`.
4. **Diverge → Converge**: Run expansion sweep (future evolution, adjacent flows, failure/edge cases), converge via concrete options + ADR-lite decisions, confirm final plan before moving to `trellis-before-dev`.
