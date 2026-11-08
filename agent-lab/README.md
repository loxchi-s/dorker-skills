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
- Both adapters are synchronous, accept only `TaskRequest`, normalize only plain-text responses (CrewAI `raw` or LangChain `content`), and wrap framework exceptions.
- Each adapter requires its own explicit capability: `framework:crewai` or `framework:langchain`. The default policy denies both.
- Framework packages are not imported or installed by Agent Lab. The caller is responsible for constructing and configuring the injected object.
- Framework-native tools are not granted by these adapters. Do not pass a preconfigured crew/runnable with tools or external side effects unless separately reviewed and explicitly authorized.

## Execution boundaries
These adapters do not implement timeout enforcement, asynchronous cancellation, retries, persistence, idempotency, sandboxing, or framework tool isolation. Do not treat capability checks as a security boundary against arbitrary code inside an injected framework object. Keep framework objects trusted and runtime disabled until an isolated execution contract is implemented and tested.

## Status
- Implemented: synchronous injected ports, explicit capability gates, task mapping, response validation, exception wrapping, and fake-port unit tests.
- Not implemented: live framework integrations, dependency installation, tool execution, timeout/cancellation, durable state, or sandbox integration.
- Validation: pending GitHub Actions for this change.
