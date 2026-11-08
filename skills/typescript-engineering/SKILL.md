---
name: typescript-engineering
description: Builds robust TypeScript applications and services with strict typing and explicit failure handling. Use when a task involves TypeScript, Node.js, browser code, APIs or frontend integration.
---
# TypeScript Engineering

## Standards
- Enable strict mode and avoid any; validate external data at runtime.
- Model async loading, errors and cancellation explicitly.
- Use AbortSignal for cancellable requests and clean up subscriptions.
- Avoid leaking secrets into browser bundles or logs.
- Bound concurrency and validate URLs, paths and user-controlled inputs.

## Validation
Run typecheck, lint, unit tests and production build. Report each result separately.
