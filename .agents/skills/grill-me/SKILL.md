---
name: grill-me
description: "Interview the user relentlessly about a plan, design, or idea until reaching shared understanding, resolving every branch of the design tree in frontier rounds (or one question at a time if requested). Based on Matt Pocock's grill-me / grilling skills. Use when the user wants to stress-test a plan, align on architecture decisions, or says 'grill me'."
---

# Grill Me — Relentless Design Tree Interview

*(Combines Matt Pocock's `grill-me` front door and complete `grilling` primitive into a self-contained skill.)*

Interview the user relentlessly about every aspect of this plan, design, or idea until you reach a shared understanding.

## Core Concepts
1. **Design Tree**: Model the subject as a tree of decisions where every decision branches into the downstream decisions that hang off it.
2. **Frontier**: The set of open decisions whose prerequisites are ALREADY settled. Two questions NEVER share a round if one depends on the other.
3. **Rounds**: Ask the current frontier as a numbered pack (at most **10** highest-leverage questions per round; or 1 at a time if requested). Wait for answers, reshape the tree, recompute the frontier, and ask the next round.

## Question Format
```text
❓ **Q1** - **<简短决策标题>**: <清晰描述决策点、上下文与 2–3 个具体选项及其权衡>
➡️ **推荐**：<你推荐的选项及一句话理由>
```
Any question the user skips accepts the `➡️` recommendation (recapped explicitly next round).

## Facts vs. Decisions
- Finding facts is the Agent's job (inspect files/docs/web), never the user's.
- Decisions belong strictly to the user. Never answer your own design decisions.

## Confirmation Gate
The session ends ONLY when the frontier is empty. Present the settled Decision Log and STOP until the user confirms shared understanding before writing code.
