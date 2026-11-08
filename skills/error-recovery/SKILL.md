---
name: error-recovery
description: Diagnoses interrupted or failed Dorker jobs and coordinates safe recovery. Use when a task is stuck, a worker crashed, a lease expired or a retry may duplicate work.
---
# Error Recovery

## Workflow
1. Read durable task state and append-only execution history.
2. Classify failure: transient, permanent, cancelled, timed out or unknown.
3. Check lease owner, heartbeat, attempt count and idempotency key.
4. Recover only after confirming the previous worker cannot still commit.
5. Retry transient failures with bounded exponential backoff and jitter.
6. Verify post-recovery invariants and record the recovery decision.

## Safety
- Never blindly replay non-idempotent side effects.
- Use compare-and-swap or transactional state transitions.
- Bound attempts, queue depth and recovery concurrency.
- Preserve original error and recovery audit trail.
