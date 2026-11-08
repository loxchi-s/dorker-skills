---
name: systematic-debugging
description: Investigates failures and unexpected behavior through evidence, data-flow tracing and testable hypotheses before proposing fixes.
---
# Dorker Systematic Debugging

## Core rule
Do not propose a code fix until the failure has been localized sufficiently to support a root-cause hypothesis.

## Phase 1 — Establish evidence
1. Capture the exact error, stack trace, failing assertion and environment.
2. Reproduce using the smallest safe input. If it is not reproducible, state that and gather more evidence.
3. Inspect recent diffs, commits, dependency and configuration changes.
4. Trace the failing value or state backward through component boundaries.
5. For multi-component systems, record inputs and outputs at each boundary without exposing secrets.

## Phase 2 — Compare behavior
1. Find a working path in the same codebase.
2. Compare inputs, state transitions, configuration, dependencies and error handling.
3. List evidence-backed differences. Do not treat names or comments as proof of behavior.

## Phase 3 — Test a hypothesis
1. State one falsifiable hypothesis and the evidence supporting it.
2. Choose the smallest diagnostic or regression test.
3. Change one variable at a time.
4. Reject or revise the hypothesis when evidence contradicts it.

## Phase 4 — Correct and verify
1. Add a regression test where practical.
2. Fix the root cause with the smallest coherent change.
3. Run the focused test and relevant regression suite.
4. If repeated fixes fail or reveal cross-component coupling, stop patching and reassess the architecture with the user.

## Safety
- Never print, copy or include secret values in logs.
- Do not execute untrusted scripts or commands merely to gather diagnostics.
- Do not mutate production state during reproduction without approval.
- In GitHub-only mode, use repository evidence and GitHub Actions results; if runtime reproduction is unavailable, report the limitation.

## Output
Observed facts; reproduction status; root-cause hypothesis; evidence; attempted experiments; fix; verification results; remaining uncertainty.
