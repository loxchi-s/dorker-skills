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
Execution control is cooperative: pass an `ExecutionControl` to an adapter and provide a context-aware port (`kickoff_with_context` or `invoke_with_context`) that polls `control.check()`. The control exposes thread-safe `cancel()`, `cancelled`, `remaining_seconds()`, and a monotonic deadline. A cancellation/deadline error is recorded as a failed execution. For hard wall-clock termination, `IsolatedWorkerRunner` starts a fresh `spawn` process, accepts only explicitly registered importable handlers, JSON-safe bounded payloads/results, and performs cooperative cancel → terminate → kill → join cleanup. On POSIX, the worker creates a new session/process group; the parent signals the group on exit so ordinary subprocess descendants are stopped. `ResourceLimits` can optionally apply POSIX `RLIMIT_CPU`, `RLIMIT_AS`, `RLIMIT_NOFILE`, and `RLIMIT_FSIZE` before handler execution. The parent owns optional ledger transitions; child processes never write the ledger. These controls are not a security sandbox: a handler can deliberately escape its process group (for example, by creating a new session), rlimits are platform-dependent and do not constrain every kernel resource, and filesystem/network/syscall access is not isolated. Windows supports worker termination but not these POSIX controls. Handlers are trusted code and must be top-level/importable for `spawn`; arbitrary dynamic imports and shell execution are not provided. The runner does not automatically wrap CrewAI/LangChain objects; framework integration needs an explicit serializable handler contract. The adapters do not implement asynchronous task cancellation, retries, distributed idempotency, sandboxing, or framework tool isolation. The SQLite store is single-host durability, not distributed exactly-once execution. Call `recover_interrupted()` once during controlled startup before accepting work; it marks all leftover `running` records as `failed/ProcessInterrupted` and never automatically replays them. Do not run this recovery concurrently with active workers. Results are persisted (up to the configured limit), so protect the database and WAL files with OS permissions and encrypted storage when outputs may contain sensitive data. There is no retention/compaction policy yet. Do not treat capability checks as a security boundary against arbitrary code inside an injected framework object. Keep framework objects trusted and runtime disabled until an isolated execution contract is implemented and tested.

## Status
- Implemented: synchronous injected ports, explicit capability gates, task mapping, response validation, exception wrapping, and fake-port unit tests.
- Implemented: process-local ledger plus durable SQLite store, transactional single-use execution IDs, bounded record/result sizes, interrupted-run marking, deterministic connection closing, and adapter integration.
- Implemented: multiprocessing tests for same-ID contention, concurrent distinct jobs, and abrupt worker termination followed by controlled recovery.
- Implemented: cooperative cancellation and monotonic deadline checks for context-aware injected ports; blocking calls are not forcibly interrupted.
- Implemented: `ContainerSandboxConfig`, explicit mount allowlisting, immutable image digest validation, non-root identity, bounded resource policy fields, and `ContainerSandboxRunner` with an injected `ContainerRuntime` contract plus fake-runtime tests. The contract requires the runtime adapter to enforce network isolation, read-only rootfs, dropped capabilities, no-new-privileges, CPU/memory/PID limits, timeout/cancellation, and streaming output bounds.
- Not implemented: concrete Docker/Podman runtime adapter, OCI integration tests, cgroup enforcement, seccomp profile distribution, Windows Job Objects, automatic retry/replay, distributed idempotency, multi-host coordination, retention/compaction, or proof of hostile-code containment. The injected runtime is trusted infrastructure and must not expose its control socket to agents.
- Validation: GitHub Actions tests the policy validation and runner contract with a fake runtime. This does not execute a real container and does not validate any OCI isolation property. The POSIX worker tests still establish only their behavior on the CI runner.
