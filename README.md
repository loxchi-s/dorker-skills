# Dorker Skills Registry

Private GitHub registry for Dorker. Skills are instructions and metadata, not executable code.

## Repository layout
- `catalog.json`: machine-readable registry index (standard JSON; no YAML dependency).
- `catalog.yaml`: human-readable legacy index; `catalog.json` is canonical for tools.
- `skills/<name>/SKILL.md`: portable Agent Skill definitions.
- `tools/validate_registry.py`: standard-library registry validator.
- `tools/install_skill.py`: local copy installer with SHA-256 provenance.
- `tests/test_validate_registry.py`: validator tests.
- `agent-lab/`: provider-agnostic coding-agent scaffold, tests and GitHub Actions CI.
- `POLICY.md`: execution and supply-chain policy.
- `SOURCES.md`: upstream discovery references and import policy.
- `upstream-candidates.json`: machine-readable candidate registry; discovery-only, unreviewed and runtime-disabled.

## Validate
```sh
python tools/validate_registry.py --root .
python -m unittest discover -s tests -v
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
