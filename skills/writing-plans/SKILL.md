---
name: writing-plans
description: Produces bounded, file-specific implementation plans with dependencies and verification criteria before multi-step code changes.
---
# Dorker Implementation Planning

## When to use
Use for multi-file changes, architecture work, migrations, security-sensitive changes or tasks with meaningful dependencies. Skip for a small, fully specified edit.

## Procedure
1. Read the relevant repository files and current tests. Do not plan from filenames or summaries alone.
2. Define the execution model, concurrency model, state ownership, failure semantics and durability requirements where applicable.
3. List exact files to create or modify and the responsibility of each.
4. Break work into small steps. Each step must have an observable result and a verification method.
5. Define acceptance tests, negative tests, rollback/recovery behavior and resource limits.
6. Identify actions requiring explicit approval: destructive edits, secret access, network access, deployment, publishing, merges or account changes.
7. State what is not being implemented.
8. Execute only within the user's authorized scope. A plan is not permission for external side effects.

## GitHub-only mode
When the user says to work in GitHub only, use the connected GitHub repository as the workspace. Do not switch to Termux, local shell, a cloud sandbox or another provider.

## Output
- Goal and non-goals
- Architecture and key decisions
- File-by-file change list
- Ordered implementation steps
- Verification matrix
- Risks, rollback and approval gates
