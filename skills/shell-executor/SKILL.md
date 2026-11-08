---
name: shell-executor
description: Executes explicitly approved shell commands in a bounded Dorker workspace. Use when a task requires terminal commands, process inspection, or reproducible command-line operations.
---
# Shell Executor

## Workflow
1. Explain the exact command, working directory, expected effects and risk.
2. Check the command against the runtime capability policy; deny by default.
3. Require approval for writes, package installation, network access, privilege changes or destructive operations.
4. Execute without shell interpolation where possible; pass an argument array to the process API.
5. Apply timeout, output-size, process-count and resource limits.
6. Capture exit code, bounded stdout/stderr and duration.

## Safety
- Never run as root unless a separately approved isolated environment requires it.
- Reject untrusted command construction and shell injection.
- Do not expose environment secrets or dump the full environment.
- Kill the entire process tree on timeout or cancellation.
- Never claim execution if only a command plan was produced.
