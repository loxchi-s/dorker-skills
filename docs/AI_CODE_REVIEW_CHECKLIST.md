# AI Code Review Checklist

Use this checklist for every AI-assisted pull request. Review the actual diff; do not rely only on the AI summary.

## Correctness
- [ ] Change satisfies the Issue's acceptance criteria.
- [ ] No unrelated behavior or public interface changed.
- [ ] Edge cases and invalid inputs are handled.
- [ ] Tests cover changed behavior and relevant failure paths.

## Security and privacy
- [ ] No credentials, tokens, private data, or secrets are committed.
- [ ] New permissions follow least privilege.
- [ ] Input is validated at trust boundaries.
- [ ] No unsafe shell execution, arbitrary code execution, path traversal, or injection path was introduced.
- [ ] Network and filesystem access are explicit, bounded, and necessary.
- [ ] Dependencies are justified and pinned or constrained according to repository policy.

## Reliability and operations
- [ ] Timeouts, cancellation, retries, and cleanup are correct where applicable.
- [ ] Concurrency and shared-state behavior are safe.
- [ ] Resource use is bounded (memory, CPU, disk, processes, queues).
- [ ] Failure states are observable without leaking sensitive data.
- [ ] Recovery and rollback behavior are documented.

## Evidence and scope
- [ ] CI check `test` passed for this PR.
- [ ] Claims distinguish Designed / Implemented / Tested / Validated.
- [ ] Untested platforms and limitations are stated.
- [ ] Documentation and examples match the implementation.
- [ ] Diff contains only intended files.

## Decision
- [ ] No blocking findings remain.
- [ ] Remaining non-blocking risks are documented.
- [ ] Human owner reviewed and accepted the change.

A checklist is a review aid, not proof of correctness or a substitute for required GitHub branch protection.
