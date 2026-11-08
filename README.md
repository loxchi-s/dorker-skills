# Dorker Skills Registry

Private GitHub registry for Dorker. Skills are versioned as files and are not executable merely because they are present here.

## Status
- Registry: initialized
- Skill definitions: draft; not runtime-integrated or security-validated
- Execution: disabled until Dorker runtime enforces capability checks, isolation, timeouts and resource limits

## Layout
- `catalog.yaml`: machine-readable skill index
- `skills/<name>/SKILL.md`: portable Agent Skill definitions
- `POLICY.md`: mandatory execution and supply-chain policy
- `SOURCES.md`: upstream projects and provenance

## Skill lifecycle
discovered -> reviewed -> pinned -> installed -> tested -> enabled

Every imported upstream skill must retain its source URL, exact commit/tag, license, content hash and review record. Do not execute install scripts during discovery.

## Core rules
- Deny capabilities by default.
- Require explicit approval for filesystem writes, shell commands, network access, credentials and deployments.
- Run untrusted code in an isolated sandbox with bounded CPU, memory, disk, process count and wall-clock time.
- Keep secrets out of skill files, logs and prompts.
- Record immutable run IDs, skill version/hash, inputs, outputs and failure reason.
