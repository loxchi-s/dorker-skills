#!/usr/bin/env python3
"""Install a reviewed SKILL.md definition locally; never execute skill content."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path

NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
REVISION_RE = re.compile(r"^[0-9a-fA-F]{40,64}$")
MAX_SKILL_BYTES = 256 * 1024


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", help="skill name from catalog.json")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="local registry checkout")
    parser.add_argument("--dest", type=Path, default=Path.home() / ".dorker" / "skills")
    parser.add_argument("--revision", required=True, help="immutable Git commit SHA")
    parser.add_argument("--apply", action="store_true", help="perform installation; otherwise dry-run")
    args = parser.parse_args()

    if not NAME_RE.fullmatch(args.name):
        parser.error("invalid skill name")
    if not REVISION_RE.fullmatch(args.revision):
        parser.error("--revision must be a 40- or 64-character hex commit SHA")

    root = args.root.resolve(strict=True)
    try:
        catalog = json.loads((root / "catalog.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        parser.error(f"cannot read catalog.json: {exc}")
    if not isinstance(catalog, dict) or not isinstance(catalog.get("skills"), list):
        parser.error("catalog.json must contain a skills list")

    entry = next(
        (item for item in catalog["skills"]
         if isinstance(item, dict) and item.get("name") == args.name),
        None,
    )
    if entry is None:
        parser.error(f"skill not found in catalog: {args.name}")
    if entry.get("status") not in {"reviewed", "tested"}:
        parser.error("only reviewed or tested skills may be installed")
    expected_rel = f"skills/{args.name}/SKILL.md"
    if entry.get("path") != expected_rel:
        parser.error("catalog path does not match canonical skill path")

    skills_root = root / "skills"
    candidate = root / expected_rel
    if candidate.is_symlink() or skills_root.is_symlink():
        parser.error("symlinked skill paths are not allowed")
    source = candidate.resolve(strict=True)
    if skills_root.resolve(strict=True) not in source.parents or not source.is_file():
        parser.error("skill path escapes registry or is not a regular file")

    payload = source.read_bytes()
    if len(payload) > MAX_SKILL_BYTES:
        parser.error("SKILL.md exceeds 256 KiB")
    digest = sha256(payload)

    dest_root = args.dest.expanduser().resolve()
    target_dir = dest_root / args.name
    target_file = target_dir / "SKILL.md"
    manifest_file = dest_root / "installed.json"
    if target_dir.is_symlink() or target_file.is_symlink():
        parser.error("symlinked installation targets are not allowed")
    if target_dir.exists() and not target_dir.is_dir():
        parser.error("target path exists and is not a directory")
    if target_file.exists():
        parser.error("skill already installed; use a separately reviewed upgrade workflow")
    if manifest_file.is_symlink():
        parser.error("installed.json symlink is not allowed")
    if manifest_file.exists() and not manifest_file.is_file():
        parser.error("installed.json must be a regular file")

    manifest = {}
    if manifest_file.exists():
        try:
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            parser.error(f"cannot read installed.json: {exc}")
    if not isinstance(manifest, dict):
        parser.error("installed.json must contain a JSON object")

    record = {
        "revision": args.revision.lower(),
        "sha256": digest,
        "source_path": expected_rel,
        "installed_file": str(target_file),
        "execution_enabled": False,
    }
    if not args.apply:
        print(json.dumps({
            "status": "dry_run", "skill": args.name, **record,
            "execution": "not_performed",
        }, indent=2))
        return 0

    dest_root.mkdir(parents=True, exist_ok=True)
    target_dir.mkdir(mode=0o700, exist_ok=True)
    temp_skill = None
    temp_manifest = None
    try:
        with tempfile.NamedTemporaryFile("wb", dir=target_dir, delete=False) as tmp:
            temp_skill = tmp.name
            tmp.write(payload)
            tmp.flush()
            os.fsync(tmp.fileno())
        os.chmod(temp_skill, 0o600)
        os.replace(temp_skill, target_file)
        manifest[args.name] = record
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=dest_root, delete=False) as tmp:
            temp_manifest = tmp.name
            json.dump(manifest, tmp, indent=2)
            tmp.write("\n")
            tmp.flush()
            os.fsync(tmp.fileno())
        os.chmod(temp_manifest, 0o600)
        os.replace(temp_manifest, manifest_file)
    except Exception:
        for temp in (temp_skill, temp_manifest):
            if temp and os.path.exists(temp):
                os.unlink(temp)
        if target_file.exists():
            target_file.unlink()
        if target_dir.exists() and not any(target_dir.iterdir()):
            target_dir.rmdir()
        raise

    print(f"INSTALLED: {args.name}")
    print(f"SHA256: {digest}")
    print("EXECUTION: disabled")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
