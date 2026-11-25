---
name: trellis-break-loop
description: "Deep bug analysis to break the fix-forget-repeat cycle. Analyzes root cause category, why fixes failed, prevention mechanisms, and captures knowledge into specs. Use after fixing a bug to prevent the same class of bugs."
---

# Break the Loop - Deep Bug Analysis

Analyze fixed bugs across 5 dimensions: (1) Root Cause Category (A Missing Spec / B Cross-Layer Contract / C Change Propagation / D Test Gap / E Implicit Assumption), (2) Why earlier fixes failed, (3) Prevention Mechanisms (Docs / Architecture / Compile-time / Runtime / Tests / Review), (4) Systematic Expansion, (5) Knowledge Capture. Use Bayesian hypothesis updating when evidence is incomplete. Immediately update `.trellis/spec/` and add regression tests — analysis in chat alone does not break the loop.
