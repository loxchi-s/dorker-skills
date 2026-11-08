---
name: python-executor
description: Runs approved Python scripts and tests in an isolated Dorker environment. Use when a task requires Python automation, data processing, or reproducible execution.
---
# Python Executor

## Workflow
1. Inspect the script and dependencies before execution.
2. Select a pinned interpreter and dependency lock.
3. Use a per-run workspace and synthetic or explicitly authorized input data.
4. Enforce CPU, memory, disk, process, network and wall-clock limits.
5. Capture exit code, bounded output and generated artifact hashes.

## Safety
- Do not use eval or exec on untrusted input.
- Do not install packages from untrusted indexes.
- Disable network by default; allowlist destinations when approved.
- Keep credentials out of process arguments and logs.
- Treat pickle and other executable serialization formats as untrusted.
