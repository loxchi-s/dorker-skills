---
name: git-manager
description: Manages Git repositories, branches, diffs and commits with explicit change review. Use when a task requires cloning, inspecting, branching, committing or synchronizing source code.
---
# Git Manager

## Workflow
1. Inspect repository status, remotes, branch and working-tree changes.
2. Never overwrite user changes; stop if the working tree has unexpected modifications.
3. Use a dedicated branch for proposed changes unless instructed otherwise.
4. Review diff and run relevant tests before committing.
5. Use focused commits with clear messages; report commit SHA and changed paths.

## Safety
- Never force-push, rewrite shared history or delete branches without explicit approval.
- Do not embed tokens in remote URLs.
- Verify remote owner/repository before push.
- Do not claim a push or commit succeeded without the Git result.
