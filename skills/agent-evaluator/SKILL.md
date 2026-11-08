---
name: agent-evaluator
description: Evaluates agent and skill behavior against repeatable tasks, expected outcomes and safety constraints. Use for quality, regression and tool-use evaluation.
---
# Agent Evaluator
1. Define versioned evaluation cases and forbidden actions.
2. Separate deterministic assertions from model-judged criteria.
3. Track correctness, safety violations, latency, token and tool cost.
4. Repeat stochastic trials and compare with pinned baseline.
5. Retain failed traces; never optimize a metric at the expense of safety.
