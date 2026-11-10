# Dorker Skills Registry

Public GitHub registry for Dorker. Skills are instructions and metadata, not executable code.

## Repository layout
- `catalog.json`: machine-readable registry index (standard JSON; no YAML dependency).
- `catalog.yaml`: human-readable legacy index; `catalog.json` is canonical for tools.
- `skills/<name>/SKILL.md`: portable Agent Skill definitions, including CrewAI and LangChain engineering guides.
- `tools/validate_registry.py`: registry validator (requires PyYAML).
- `tools/install_skill.py`: local copy installer with SHA-256 provenance.
- `tools/skill_manager.py`: list, inspect, pin and verify skill provenance without executing content.
- `tests/test_skill_manager.py`: Skill Manager policy and integrity tests.
- `tests/test_validate_registry.py`: validator tests.
- `agent-lab/`: provider-agnostic coding-agent scaffold, tests and GitHub Actions CI.
- `POLICY.md`: execution and supply-chain policy.
- `SOURCES.md`: upstream discovery references and import policy.
- `upstream-candidates.json`: machine-readable upstream candidate registry with pinned review metadata.
- `UPSTREAM_REVIEW.md`: initial screening decisions, license notes and Dorker compatibility gates.
- `THIRD_PARTY_NOTICES.md`: upstream attribution and license provenance.

## Validate
```sh
python tools/validate_registry.py --root .
python -m unittest discover -s tests -v
```

## Manage skill definitions

```sh
python tools/skill_manager.py --root . list
python tools/skill_manager.py --root . inspect python-engineering
python tools/skill_manager.py --root . verify
```

Pinning is dry-run by default. It requires catalog status `reviewed` or `tested`, an immutable commit SHA, a GitHub source URL, a license identifier, and explicit manual-review confirmation. Add `--apply` only to write `pins.json`; this records provenance and a content hash, not permission to execute.

```sh
python tools/skill_manager.py --root . pin python-engineering --revision <40-char-commit-sha> --source-url https://github.com/owner/repo --license MIT --reviewed
```

## Install a definition locally
First obtain the immutable commit SHA from GitHub, then run a dry-run:
```sh
python tools/install_skill.py python-engineering --root . --revision <40-char-commit-sha>
```
Apply only after review:
```sh
python tools/install_skill.py python-engineering --root . --revision <40-char-commit-sha> --apply
```
The installer copies only `SKILL.md` to `~/.dorker/skills`, records revision and SHA-256 in `installed.json`, refuses overwrite, and never executes skill content. It does not download GitHub content or verify a remote commit itself; the caller must provide a trusted local checkout and verified immutable revision.

## Lifecycle
discovered -> reviewed -> pinned -> installed -> tested -> enabled

The registry remains `runtime_enabled: false`. Do not enable execution until Dorker enforces OS-level isolation, default-deny capabilities, bounded resources, cancellation, audit logging and side-effect idempotency.
