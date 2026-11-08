---
name: python-engineering
description: Builds maintainable and secure Python services, libraries and automation. Use when a task involves Python, asyncio, Pydantic v2, packaging, data processing or APIs.
---
# Python Engineering

## Standards
- Use type hints and Pydantic v2 at untrusted data boundaries.
- Separate transport, service, domain and persistence layers.
- Use asyncio for I/O concurrency; bound task fan-out and queues.
- Use context managers for resource ownership and cancellation-safe cleanup.
- Avoid shell=True, unsafe deserialization and implicit global mutable state.
- Pin dependencies and use reproducible environments.

## Validation
Run formatter, linter, type checker and relevant tests. Include failure-path and cancellation tests for async code.
