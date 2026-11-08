---
name: api-builder
description: Designs and implements versioned APIs with validation, authentication and operational safeguards. Use when a task requires REST, RPC or service endpoint design.
---
# API Builder

## Workflow
1. Define contract, data model, authn/authz and error semantics first.
2. Validate all inputs and enforce request/body/response size limits.
3. Add timeouts, rate limits, idempotency for side-effecting operations and structured logs.
4. Document compatibility and versioning.
5. Test success, invalid input, unauthorized, timeout and dependency failure paths.

## Safety
Never expose stack traces, secrets or internal network details to clients.
