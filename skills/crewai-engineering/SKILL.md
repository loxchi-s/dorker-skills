---
name: crewai-engineering
description: Design, review, and integrate CrewAI agents, tasks, crews, and flows with Dorker's capability policy, bounded execution, explicit approvals, and testable orchestration.
---

# CrewAI Engineering

## Purpose
Use CrewAI when a workflow benefits from role-specialized agents collaborating on tasks, or when a Flow should own deterministic event-driven orchestration. Keep Dorker as the policy and lifecycle authority; CrewAI is an orchestration backend, not a security boundary.

## Architecture rules
- Prefer CrewAI Flows for deterministic control, state transitions, routing, retries, and human approval points.
- Use Crews for bounded collaborative subtasks with explicit expected outputs.
- Keep task inputs and outputs typed, size-limited, validated, and serializable.
- Separate planning, execution, verification, and commit. Do not let an agent approve its own high-impact action.
- Make each side effect idempotent and attach a stable task/run identifier.
- Set explicit iteration, time, token, concurrency, and output limits. Define timeout and cancellation behavior.
- Persist checkpoints only through an approved Dorker state adapter; document replay and recovery semantics.
- Keep memory and knowledge sources scoped to the task and tenant. Do not place secrets in prompts, memory, logs, or artifacts.

## Tool and security policy
- Start with no tools. Add tools only through a Dorker capability adapter that checks the allowlist on every invocation.
- Never treat CrewAI tool registration, agent role text, guardrails, or prompt instructions as OS isolation.
- Deny shell, arbitrary filesystem writes, unrestricted network, process spawning, deployment, and credential access by default.
- Allowlist exact network destinations and filesystem paths; use read-only inputs and bounded scratch outputs.
- Require human approval for external side effects, destructive operations, account changes, and deployment.
- Inspect custom tools and transitive dependencies. Reject dynamic code loading, hidden downloads, unpinned dependencies, and credential forwarding.
- Do not enable telemetry or external tracing without an explicit data-flow and privacy review.

## Implementation workflow
1. Define the task contract, success criteria, failure states, and approval boundaries.
2. Decide whether a Flow, a Crew, or a single model call is sufficient; avoid multi-agent overhead without measurable benefit.
3. Design agents with narrow roles and tasks with explicit inputs and expected outputs.
4. Bind only approved model providers and tools; keep credentials in a secret manager or environment injection layer outside prompts.
5. Add deterministic validation after every agent-produced artifact.
6. Test tool denial, malformed output, timeout, cancellation, duplicate delivery, partial failure, replay, and recovery.
7. Measure latency, token/cost per task, retries, tool calls, and quality against a single-agent baseline.
8. Record exact package versions and lockfile hashes before deployment.

## Compatibility notes
CrewAI APIs and project scaffolds evolve. Check the current official documentation before using constructors, decorators, configuration formats, or lifecycle hooks. Do not assume legacy YAML/class-based examples match newly generated projects.

## Dorker integration contract
- The Dorker runtime owns task intake, capability policy, state, audit events, cancellation, and final approval.
- CrewAI receives only a validated task envelope and scoped adapters.
- CrewAI output is untrusted until schema validation and independent verification pass.
- No CrewAI process or tool execution is enabled by adding this Skill.
