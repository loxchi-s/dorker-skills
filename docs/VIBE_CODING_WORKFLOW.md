# Vibe Coding Workflow

This repository uses an issue-first, branch-based workflow. AI may propose and implement changes, but the repository owner remains responsible for reviewing and merging them.

## 1. Work intake

Create a GitHub Issue using the Bug Report or Feature Request template.

Before implementation, record:
- Goal and observable acceptance criteria
- Scope and explicit non-goals
- Relevant files and dependencies
- Security, privacy, and compatibility constraints
- Failure behavior, rollback plan, and resource limits where applicable

Do not start implementation when a requirement materially affecting correctness or safety is unresolved. Ask one focused clarification.

## 2. Plan before code

For non-trivial changes, write a short plan in the Issue or pull request:
- Execution and concurrency model
- State ownership and persistence
- Failure, cancellation, and recovery semantics
- External capabilities and permissions
- Tests and observable evidence

Separate **Designed**, **Implemented**, **Tested**, and **Validated**. Never report a stage as complete without evidence.

## 3. Branch and implementation

Use a branch from the latest `main`:
- `feature/<short-name>` for features
- `fix/<short-name>` for bug fixes
- `docs/<short-name>` for documentation
- `refactor/<short-name>` for behavior-preserving changes
- `test/<short-name>` for test-only changes

Keep changes small and focused. Do not commit directly to `main`.

AI-generated changes must:
- Follow existing repository conventions and dependency policy
- Avoid secrets, tokens, private data, and hard-coded credentials
- Avoid adding network, shell, filesystem, or privileged capabilities without explicit review
- Preserve backward compatibility unless the Issue explicitly authorizes a breaking change
- Include tests for changed behavior and failure paths
- Update documentation when behavior or interfaces change

## 4. Local or CI verification

Run the checks relevant to the changed paths. The GitHub Actions workflow currently runs registry validation, unit tests, Python compilation, and Docker integration tests.

Treat the required CI check named `test` as evidence only for the checks that actually ran. A passing CI run does not prove security, production readiness, or untested platform compatibility.

If a check cannot run, state why and mark it **Not tested**. Do not claim it passed.

## 5. Pull request

Open a PR targeting `main`. Use the repository PR template and include:
- Issue link and purpose
- Summary of behavior changes
- Tests run and their results
- Security and operational impact
- Known limitations and rollback steps

Keep the PR focused. Do not include unrelated formatting or generated files.

## 6. Review and merge

Before merge, inspect the complete diff and verify:
- Acceptance criteria are met
- No secrets or unexpected files are present
- Permissions and external capabilities are least-privilege
- Error handling, cancellation, and resource bounds are appropriate
- Tests cover success and relevant failure paths
- CI check `test` is successful

AI review is advisory, not an approval authority. The repository owner must make the final merge decision. Do not merge while required checks fail or material review findings remain unresolved.

## 7. After merge

Confirm the merged commit is on `main), check the resulting CI run, and record follow-up work as Issues. Delete the feature branch when it is no longer needed.

## Current enforcement limits

This document describes the intended workflow. GitHub Actions CI and PR-trigger behavior have been tested. Branch protection / required-review enforcement is not confirmed for this private repository, so this document does not claim that GitHub technically blocks direct pushes or merges. Until enforcement is enabled, follow the process manually.
