# Dorker Agent Lab

A safe development workspace inside the Dorker Skills repository.

## Components
- `dorker_agent/`: provider-agnostic task agent scaffold, validated task envelope and default-deny capability policy.
- `tests/`: unit tests for agent, task validation and capability policy.
- `.github/ISSUE_TEMPLATE/`: structured bug and feature intake.
- `.github/pull_request_template.md`: change, verification and rollback checklist.
- `.github/workflows/agent-lab-ci.yml`: GitHub Actions CI.

## Run tests
```sh
python -m unittest discover -s agent-lab/tests -v
```

## Agent contract
The agent accepts a task and a model adapter, then returns a text response. `TaskRequest` validates issue-like task metadata. `CapabilityPolicy` denies all capabilities unless explicitly allowlisted. It has no shell, filesystem, network, deployment, or secret access. Tool execution is intentionally not implemented. Add tools only behind explicit capability checks and isolated execution.

## Status
- Implemented: provider interface, agent orchestration shell, unit tests, CI workflow.
- Not implemented: live model provider, tool execution, sandbox integration.
- Not validated: CI has not yet run on GitHub.
