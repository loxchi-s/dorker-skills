---
name: verification-before-completion
description: Requires fresh, claim-matched evidence before reporting a change, test, build or task as complete.
---
# Dorker Verification Gate

## Invariant
Evidence must precede every claim of completion, correctness, test success or validation.

## Procedure
1. Translate each acceptance criterion into a concrete check.
2. Run the complete relevant check in the authorized environment.
3. Inspect the full output, exit status, failure count and skipped checks.
4. Confirm the evidence actually covers the claim. A syntax check does not prove runtime behavior; a focused test does not prove the full suite.
5. Inspect the final diff and ensure only intended files changed.
6. Record the exact commit and verification evidence when available.
7. Report unresolved checks and environmental limitations explicitly.

## Status vocabulary
- **Designed:** architecture or plan documented.
- **Implemented:** code or configuration committed.
- **Tested:** specified tests were executed; include observed results.
- **Validated:** all stated acceptance criteria have evidence.
- **Not run / blocked:** execution was unavailable or prevented.
- **Failed:** a check ran and did not meet its expected result.

## GitHub-only constraints
- A file write or commit is not evidence that CI passed.
- Do not infer a workflow run from the presence of a workflow YAML file.
- Do not claim tests passed unless the actual GitHub Actions run and relevant job results were inspected.
- Never fabricate logs, exit codes, screenshots or test counts.

## Output
Claim; evidence; commit/reference; checks passed; checks failed; checks not run; residual risks.
