---
name: mcts-planner
description: Plans bounded action sequences using Monte Carlo Tree Search or deterministic planning. Use when choices branch and have measurable simulated outcomes.
---
# MCTS Planner
Inputs: goal, state snapshot, legal actions, transition function, reward and resource budget.
1. Validate state and legal-action invariants.
2. Bound rollout count, depth, wall time and memory.
3. Use deterministic seeds when reproducibility matters.
4. Keep speculative simulation free of real-world side effects.
5. Return selected action, alternatives, estimates and termination reason; provide safe fallback on budget exhaustion.
