---
name: langchain-engineering
description: Design, review, and integrate LangChain models, messages, prompt templates, runnables, structured output, and retrievers under Dorker's security and execution contracts.
---

# LangChain Engineering

## Purpose
Use LangChain when composing model calls, prompts, structured outputs, retrieval, and reusable runnable pipelines. Use LangGraph when the application needs explicit stateful agent orchestration, branching, persistence, interrupts, or resumable execution. Do not add an agent loop when a bounded Runnable pipeline is sufficient.

## Architecture rules
- Prefer the smallest abstraction: direct model call, Runnable composition, retrieval chain, then stateful graph only when required.
- Keep application state outside prompts and model objects. Define state ownership, persistence, replay, and migration explicitly.
- Validate all external inputs and model outputs against typed schemas; treat structured output as untrusted until validated.
- Bound prompt size, retrieved document count, output tokens, concurrency, retries, and wall-clock time.
- Make retry policy explicit. Retry transient, idempotent model requests only; do not blindly retry tool side effects.
- Use stable document IDs, source metadata, tenant filters, and provenance for retrieval.
- Apply authorization filters before retrieval, not only after generation. Prevent cross-tenant context leakage.
- Separate retrieval relevance evaluation from answer generation; cite source identifiers in outputs where required.

## Tool and security policy
- Do not expose arbitrary Python execution, shell, filesystem writes, or unrestricted HTTP tools to a model.
- Every tool call must pass through a Dorker capability adapter and validate arguments at invocation time.
- Treat prompt templates, retrieved documents, tool output, and model output as untrusted data; defend against indirect prompt injection.
- Keep API keys outside source code, prompts, callbacks, traces, and serialized chain state.
- Allowlist model endpoints and retriever destinations. Review outbound data and provider retention before enabling remote models.
- Do not log full prompts, retrieved private documents, secrets, or personal data by default.
- Disable or explicitly review callbacks, tracing, and telemetry that export content.
- Use least-privilege credentials and isolate any component that executes tools.

## Implementation workflow
1. Define input/output schemas, state lifecycle, trust boundaries, and failure semantics.
2. Select a model integration package explicitly; do not assume a provider is included in the base package.
3. Build a small Runnable pipeline with explicit prompt variables and output validation.
4. Add retrieval only with tenant-aware filtering, provenance, and bounded context assembly.
5. Add LangGraph only if durable state, conditional routing, interrupts, or multi-step recovery are requirements.
6. Test malformed model output, injection in retrieved content, empty retrieval, provider timeout, rate limits, cancellation, duplicate work, and state replay.
7. Benchmark latency, token usage, retrieval quality, and total cost against a direct model call.
8. Pin package versions and commit the dependency lockfile; review provider and integration packages separately.

## Dorker integration contract
- Dorker owns task intake, policy decisions, state, audit, cancellation, and approvals.
- LangChain components receive only validated inputs and scoped model/retriever/tool adapters.
- Runnable and graph outputs remain untrusted until schema validation and independent verification pass.
- No LangChain tool execution or network access is enabled by adding this Skill.

## Compatibility notes
LangChain package boundaries and APIs change over time. Use the current v1 documentation and reference pages; avoid obsolete v0.x imports and legacy community integrations. Provider integrations are generally separate packages. Verify package names and APIs before adding dependencies.
