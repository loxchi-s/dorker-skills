#!/usr/bin/env python3
"""Install a reviewed SKILL.md definition locally; never execute skill content."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path

NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", help="skill name from catalog.json")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="local registry checkout")
    parser.add_argument("--dest", type=Path, default=Path.home() / ".dorker" / "skills")
    parser.add_argument("--revision", required=True, help="immutable Git commit SHA for provenance")
    parser.add_argument("--apply", action="store_true", help="perform installation; otherwise print a dry run")
    args = parser.parse_args()

    if not NAME_RE.fullmatch(args.name):
        parser.error("invalid skill name")
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", args.revision):
        parser.error("--revision must be an immutable 40- or 64-character hex commit SHA")

    root = args.root.resolve(strict=True)
    catalog = json.loads((root / "catalog.json").read_text(encoding="utf-8"))
    entry = next((x for x in catalog["skills"] if x.get("name") == args.name), None)
    if entry is None:
        parser.error(f"skill not found in catalog: {args.name}")
    if entry.get("status") not in {"draft", "reviewed", "tested"}:
        parser.error("unsupported skill lifecycle status")

    source = (root / entry["path"]).resolve(strict=True)
    skills_root = (root / "skills").resolve(strict=True)
    if skills_root not in source.parents or source.is_symlink() or not source.is_file():
        parser.error("skill path escapes registry or is not a regular file")

    payload = source.read_bytes()
    if len(payload) > 256 * 1024:
        parser.error("SKILL.md exceeds 256 KiB")
    digest = sha256(payload)
    dest_root = args.dest.expanduser().resolve()
    target_dir = dest_root / args.name
    target_file = target_dir / "SKILL.md"
    manifest_file = dest_root / "installed.json"

    if target_dir.exists() and not target_dir.is_dir():
        parser.error("target path exists and is not a directory")
    if target_file.exists():
        parser.error("skill already installed; manual review and a separate upgrade workflow are required")

    manifest = {}
    if manifest_file.exists():
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        parser.error("installed.json must contain a JSON object")
    if not args.apply:
        print(json.dumps({
            "status": "dry_run",
            "skill": args.name,
            "sha256": digest,
            "revision": args.revision.lower(),
            "target": str(target_file),
            "execution": "not_performed",
        }, indent=2))
        return 0

    dest_root.mkdir(parents=True, exist_ok=True)
    target_dir.mkdir(mode=0o700)
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile("wb", dir=target_dir, delete=False) as tmp:
            temp_name = tmp.name
            tmp.write(payload)
            tmp.flush()
            os.fsync(tmp.fileno())
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, target_file)
        manifest[args.name] = {
            "revision": args.revision.lower(),
            "sha256": digest,
            "source_path": entry["path"],
            "installed_file": str(target_file),
            "execution_enabled": False,
        }
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=dest_root, delete=False) as tmp:
            temp_manifest = tmp.name
            json.dump(manifest, tmp, indent=2)
            tmp.write("\n")
            tmp.flush()
            os.fsync(tmp.fileno())
        os.chmod(temp_manifest, 0o600)
        os.replace(temp_manifest, manifest_file)
    except Exception:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)
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
