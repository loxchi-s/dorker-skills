---
name: rust-engineering
description: Designs, implements and reviews reliable Rust services and libraries. Use when a task involves Rust, Tokio, ownership, async concurrency, FFI or performance-sensitive systems code.
---
# Rust Engineering

## Standards
- Use explicit error types with thiserror for libraries and anyhow at application boundaries.
- Use Tokio only where asynchronous I/O or concurrency is required.
- Define cancellation, task ownership, backpressure and shutdown semantics.
- Avoid unbounded channels, detached tasks and blocking work on async executors.
- Prefer structured tracing over println; never log secrets.
- Use safe Rust by default; justify every unsafe block with invariants and tests.

## Validation
Run fmt, clippy with warnings denied where feasible, unit/integration tests and targeted concurrency tests. Report commands and actual outcomes.
