#!/usr/bin/env python3
"""Validate Dorker skill registry metadata without executing skills."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
REQUIRED = {"name", "description"}


def parse_skill(path: Path) -> tuple[dict[str, str] | None, list[str]]:
    errors: list[str] = []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return None, [f"{path}: cannot read UTF-8 file: {exc}"]

    if not text.startswith("---\n"):
        return None, [f"{path}: missing YAML frontmatter opening delimiter"]
    end = text.find("\n---\n", 4)
    if end < 0:
        return None, [f"{path}: missing YAML frontmatter closing delimiter"]

    metadata: dict[str, str] = {}
    for line_no, line in enumerate(text[4:end].splitlines(), start=2):
        if not line.strip():
            continue
        if ":" not in line:
            errors.append(f"{path}:{line_no}: expected key: value")
            continue
        key, value = line.split(":", 1)
        key, value = key.strip(), value.strip()
        if key in metadata:
            errors.append(f"{path}:{line_no}: duplicate metadata key {key!r}")
        metadata[key] = value

    missing = REQUIRED - metadata.keys()
    if missing:
        errors.append(f"{path}: missing metadata: {', '.join(sorted(missing))}")
    if "name" in metadata and not NAME_RE.fullmatch(metadata["name"]):
        errors.append(f"{path}: invalid skill name {metadata['name']!r}")
    if "description" in metadata and not metadata["description"]:
        errors.append(f"{path}: description must not be empty")
    if len(metadata.get("description", "")) > 1024:
        errors.append(f"{path}: description exceeds 1024 characters")
    return metadata, errors


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    catalog_path = root / "catalog.json"
    try:
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return [f"catalog.json: cannot parse: {exc}"]

    if catalog.get("schema_version") != 1:
        errors.append("catalog.json: unsupported schema_version")
    if catalog.get("runtime_enabled") is not False:
        errors.append("catalog.json: runtime_enabled must remain false until runtime security gates exist")
    entries = catalog.get("skills")
    if not isinstance(entries, list):
        return errors + ["catalog.json: skills must be a list"]

    seen: set[str] = set()
    expected_paths: set[str] = set()
    for item in entries:
        if not isinstance(item, dict):
            errors.append("catalog.json: each skill entry must be an object")
            continue
        name, rel = item.get("name"), item.get("path")
        if not isinstance(name, str) or not NAME_RE.fullmatch(name):
            errors.append(f"catalog.json: invalid skill name {name!r}")
            continue
        if name in seen:
            errors.append(f"catalog.json: duplicate skill name {name}")
            continue
        seen.add(name)
        expected = f"skills/{name}/SKILL.md"
        if rel != expected:
            errors.append(f"catalog.json: {name} path must be {expected}")
            continue
        expected_paths.add(expected)
        skill_path = root / expected
        if skill_path.is_symlink() or not skill_path.is_file():
            errors.append(f"{expected}: missing file or symlink not allowed")
            continue
        metadata, parse_errors = parse_skill(skill_path)
        errors.extend(parse_errors)
        if metadata and metadata.get("name") != name:
            errors.append(f"{expected}: frontmatter name does not match catalog name")

    actual = {
        p.relative_to(root).as_posix()
        for p in (root / "skills").glob("*/SKILL.md")
        if p.is_file() and not p.is_symlink()
    } if (root / "skills").is_dir() else set()
    for missing in sorted(expected_paths - actual):
        errors.append(f"{missing}: catalog entry has no skill file")
    for extra in sorted(actual - expected_paths):
        errors.append(f"{extra}: skill file is not registered in catalog")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    errors = validate(args.root.resolve())
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(f"FAIL: {len(errors)} issue(s)")
        return 1
    print("PASS: registry structure and skill metadata are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
