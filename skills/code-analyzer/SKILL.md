---
name: code-analyzer
description: Analyzes code structure, dependencies, data flow and failure paths without modifying files. Use when a task requires architecture mapping, codebase understanding or root-cause investigation.
---
# Code Analyzer

## Workflow
1. Identify languages, entry points, build system and repository boundaries.
2. Map modules, dependencies, state ownership and execution flow.
3. Trace concurrency, cancellation, retries, persistence and external side effects.
4. Identify security boundaries, input validation and resource limits.
5. Support findings with file paths and line references; separate facts from hypotheses.

## Output
Report architecture, risks, evidence, severity and recommended verification steps. Do not modify files unless separately asked.
