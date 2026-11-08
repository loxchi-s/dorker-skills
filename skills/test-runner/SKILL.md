---
name: test-runner
description: Selects and runs relevant automated tests in a controlled workspace. Use when a task requires unit, integration, regression, property or stress testing.
---
# Test Runner

## Workflow
1. Identify the test framework and test scope.
2. Inspect test commands and hooks before running them.
3. Use isolated test data; avoid production services by default.
4. Run focused tests, then broader suites when appropriate.
5. Record exact command, environment, exit code, counts and failures.

## Safety
- Treat test code as executable untrusted code.
- Do not run tests that mutate production data or incur costs without approval.
- Distinguish not-run, failed, passed and flaky.
- A passing test suite is not proof of production readiness.
