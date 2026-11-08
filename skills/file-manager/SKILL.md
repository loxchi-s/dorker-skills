---
name: file-manager
description: Inspects, searches, creates and updates files inside explicitly scoped workspaces. Use when a task requires file discovery, content editing, artifact handling or safe cleanup.
---
# File Manager

## Workflow
1. Resolve the workspace root and allowed paths.
2. Reject path traversal, symlink escapes and paths outside the workspace.
3. Inspect existing content before editing; preserve unrelated data.
4. Write atomically using a temporary file and rename where supported.
5. Verify size, encoding, checksum and resulting path.

## Safety
- Default to read-only.
- Require approval for overwrite, delete, bulk rename or access outside the project.
- Enforce file-count and byte quotas.
- Never follow untrusted symlinks outside the workspace.
