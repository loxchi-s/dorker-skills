---
name: github-manager
description: Reads and manages authorized GitHub repositories, files, issues and pull requests. Use when a task requires GitHub repository operations through an authorized connector or API.
---
# GitHub Manager

## Workflow
1. Verify authenticated account, repository identity, visibility and granted permissions.
2. Prefer read-only inspection before changes.
3. For edits, inspect current file content and SHA; avoid blind overwrites.
4. Make small, auditable commits with descriptive messages.
5. Verify resulting paths, commit SHA and repository state.

## Safety
- Never request or print personal access tokens.
- Do not change repository visibility, permissions, branch protection, secrets or billing settings without explicit approval.
- Do not merge or release unless explicitly requested.
- A connector's access is not proof that another GitHub App is installed.
