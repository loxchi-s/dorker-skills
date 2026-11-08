# Dorker Skill Execution Policy

## Trust model
A GitHub skill is untrusted input until reviewed. A valid SKILL.md is documentation, not proof that its instructions or scripts are safe.

## Lifecycle gates
1. Discover: record repository, path, ref and retrieval date.
2. Review: inspect every file, script, dependency, license and network destination.
3. Pin: use immutable commit SHA; never track a moving branch in production.
4. Install: copy only reviewed files into the skill store.
5. Test: run static checks and isolated tests with synthetic data.
6. Enable: require an explicit policy decision and least-privilege capabilities.

## Default-deny capabilities
- shell: denied
- filesystem_read: allowlisted paths only
- filesystem_write: denied unless explicitly approved and scoped
- network: denied unless destination allowlisted
- secrets: never exposed to skill processes by default
- process_spawn: denied unless approved
- deployment, payments, account changes: require human confirmation

## Runtime requirements before execution
- OS/container isolation; do not rely on prompt instructions as a security boundary.
- Non-root identity, read-only base filesystem, bounded writable scratch directory.
- CPU, RAM, disk, process, output-size and wall-clock limits.
- Cancellation propagation; kill process tree on timeout/cancel.
- Per-run unique workspace; no shared mutable working directory.
- Idempotency key for retryable side effects.
- Structured audit log with run ID, skill hash, policy decision and exit status.
- No automatic retry of non-idempotent operations.

## Supply-chain requirements
- Preserve upstream URL, commit SHA, license and SHA-256 for imported content.
- Review install hooks, scripts, binaries, package lifecycle hooks and transitive dependencies.
- Reject secrets, obfuscated payloads, unexpected downloads and unpinned dependencies.
- Keep upstream content separate from Dorker-authored adaptations.
- Re-review on every upstream update.

## Status semantics
A skill marked draft/reviewed/tested/enabled must reflect evidence. Repository presence does not mean implemented, tested or safe to execute.
