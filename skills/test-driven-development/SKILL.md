---
name: test-driven-development
description: Designs behavior tests before implementation and uses verified red-green-refactor cycles for features and bug fixes.
---
# Dorker Test-Driven Development

## Core rule
Define the expected behavior in a test before changing production behavior. Do not claim a red-green cycle unless both runs were actually observed.

## Procedure
1. Identify the behavior, contract and regression risk.
2. Write the smallest test that demonstrates the expected behavior, including relevant boundary and failure cases.
3. Run the focused test in an authorized execution environment.
4. Confirm it fails for the expected behavioral reason. A syntax error, import error or broken fixture is not a valid RED result.
5. Implement the smallest change that satisfies the test.
6. Run the focused test and then the relevant broader suite.
7. Refactor only after the behavior is green; rerun affected tests.
8. Record commands, environment, exit status and observed counts.

## Constraints
- If execution is unavailable in the current GitHub workflow, write the test and report it as not run. Do not simulate terminal output or claim RED/GREEN.
- Do not run tests that mutate production data, access secrets, incur costs or call external services without explicit approval.
- Mocks are acceptable at true external boundaries; prefer assertions on observable behavior over mock call counts.
- Keep generated files, fixtures and test data bounded and non-sensitive.

## Report
Separate tests written, tests executed, results observed and checks not run. A passing test suite does not prove production readiness.
