---
name: workflow-orchestrator
description: Coordinates multi-step tasks and specialized skills using explicit state and dependency contracts. Use for sequencing, parallel work, retries and durable progress.
---
# Workflow Orchestrator
1. Convert goal into dependency DAG with typed inputs/outputs.
2. Assign one owner per mutable state item.
3. Bound parallelism, queue depth and total execution budget.
4. Persist transitions and idempotency keys before side effects.
5. Propagate cancellation; define compensation and recovery.
6. Verify terminal invariants before reporting completion.
