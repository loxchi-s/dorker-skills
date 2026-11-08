# Dorker Agent Lab

A safe development workspace inside the Dorker Skills repository.

## Components
- `dorker_agent/`: provider-agnostic agent scaffold, validated task envelope, default-deny capability policy, and optional framework adapters.
- `tests/`: unit tests for agent, task validation, capability policy, and framework adapters.
- `.github/ISSUE_TEMPLATE/`: structured bug and feature intake.
- `.github/pull_request_template.md`: change, verification and rollback checklist.
- `.github/workflows/agent-lab-ci.yml`: GitHub Actions CI.

## Run tests
```sh
python -m unittest discover -s agent-lab/tests -v
```

## Agent contract
The base agent accepts a task and an injected model adapter. It exposes no shell, filesystem, network, deployment, or secret access. Tool execution is not implemented.

## Framework adapters
- `CrewAIAdapter` accepts an injected object exposing `kickoff(inputs=...)`.
- `LangChainAdapter` accepts an injected Runnable exposing `invoke(input)`.
- Both adapters are synchronous, accept only `TaskRequest`, normalize plain-string responses or framework text fields (CrewAI `raw` / LangChain `content`), and wrap framework exceptions.
- Each adapter requires its own explicit capability: `framework:crewai` or `framework:langchain`. The default policy denies both.
- `InMemoryExecutionLedger` is process-local. `SQLiteExecutionStore` persists lifecycle state across restarts, uses SQLite transactions/WAL, enforces a record and result-size limit, and rejects duplicate execution IDs across store instances. Both implement the adapter ledger interface.
- Framework packages are not imported or installed by Agent Lab. The caller is responsible for constructing and configuring the injected object.
- Framework-native tools are not granted by these adapters. Do not pass a preconfigured crew/runnable with tools or external side effects unless separately reviewed and explicitly authorized.

## Execution boundaries
Execution control is cooperative: pass an `ExecutionControl` to an adapter and provide a context-aware port (`kickoff_with_context` or `invoke_with_context`) that polls `control.check()`. The control exposes thread-safe `cancel()`, `cancelled`, `remaining_seconds()`, and a monotonic deadline. A cancellation/deadline error is recorded as a failed execution. This does not forcibly interrupt a blocking call; hard timeouts require a separately isolated worker process with a kill/reap contract. The adapters do not implement asynchronous task cancellation, retries, distributed idempotency, sandboxing, or framework tool isolation. The SQLite store is single-host durability, not distributed exactly-once execution. Call `recover_interrupted()` once during controlled startup before accepting work; it marks all leftover `running` records as `failed/ProcessInterrupted` and never automatically replays them. Do not run this recovery concurrently with active workers. Results are persisted (up to the configured limit), so protect the database and WAL files with OS permissions and encrypted storage when outputs may contain sensitive data. There is no retention/compaction policy yet. Do not treat capability checks as a security boundary against arbitrary code inside an injected framework object. Keep framework objects trusted and runtime disabled until an isolated execution contract is implemented and tested.

## Status
- Implemented: synchronous injected ports, explicit capability gates, task mapping, response validation, exception wrapping, and fake-port unit tests.
- Implemented: process-local ledger plus durable SQLite store, transactional single-use execution IDs, bounded record/result sizes, interrupted-run marking, deterministic connection closing, and adapter integration.
- Implemented: multiprocessing tests for same-ID contention, concurrent distinct jobs, and abrupt worker termination followed by controlled recovery.
- Implemented: cooperative cancellation and monotonic deadline checks for context-aware injected ports; blocking calls are not forcibly interrupted.
- Not implemented: live framework integrations, dependency installation, tool execution, hard process-level timeouts, automatic retry/replay, distributed idempotency, multi-host coordination, retention/compaction, or sandbox integration.
- Validation: GitHub Actions pending for cooperative timeout/cancellation tests. Passing CI establishes test-suite success only; it does not establish hard timeout enforcement, multi-host coordination, or distributed exactly-once guarantees.
