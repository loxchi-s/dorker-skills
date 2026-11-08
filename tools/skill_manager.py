#!/usr/bin/env python3
"""Inspect and pin Dorker skill definitions. Never executes skill content."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
import os
from pathlib import Path
from urllib.parse import urlparse

NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
REVISION_RE = re.compile(r"^[0-9a-fA-F]{40,64}$")
PIN_FILE = "pins.json"
MAX_SKILL_BYTES = 256 * 1024


class ManagerError(ValueError):
    """A registry or pin operation failed validation."""


def digest_file(path: Path) -> str:
    data = path.read_bytes()
    if len(data) > MAX_SKILL_BYTES:
        raise ManagerError(f"{path}: exceeds {MAX_SKILL_BYTES} bytes")
    return hashlib.sha256(data).hexdigest()


def load_registry(root: Path) -> tuple[dict, dict[str, dict], dict[str, Path]]:
    root = root.resolve(strict=True)
    catalog_path = root / "catalog.json"
    try:
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ManagerError(f"cannot read catalog.json: {exc}") from exc
    if not isinstance(catalog, dict) or catalog.get("schema_version") != 1:
        raise ManagerError("unsupported registry schema")
    if catalog.get("runtime_enabled") is not False:
        raise ManagerError("runtime_enabled must remain false")
    entries = catalog.get("skills")
    if not isinstance(entries, list):
        raise ManagerError("catalog skills must be a list")

    by_name: dict[str, dict] = {}
    paths: dict[str, Path] = {}
    for item in entries:
        if not isinstance(item, dict):
            raise ManagerError("skill entry must be an object")
        name, rel = item.get("name"), item.get("path")
        if not isinstance(name, str) or not NAME_RE.fullmatch(name):
            raise ManagerError(f"invalid skill name: {name!r}")
        if name in by_name:
            raise ManagerError(f"duplicate skill: {name}")
        expected = f"skills/{name}/SKILL.md"
        if rel != expected:
            raise ManagerError(f"{name}: path must be {expected}")
        candidate = root / expected
        if candidate.is_symlink() or not candidate.is_file():
            raise ManagerError(f"{name}: missing file or symlink not allowed")
        resolved = candidate.resolve(strict=True)
        if root / "skills" not in resolved.parents:
            raise ManagerError(f"{name}: path escapes skills directory")
        by_name[name] = item
        paths[name] = resolved
    return catalog, by_name, paths


def load_pins(root: Path) -> dict:
    path = root / PIN_FILE
    if path.is_symlink():
        raise ManagerError("pins.json symlink is not allowed")
    if not path.exists():
        return {"schema_version": 1, "pins": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ManagerError(f"cannot read pins.json: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != 1 or not isinstance(data.get("pins"), dict):
        raise ManagerError("invalid pins.json structure")
    return data


def inspect_skill(root: Path, name: str) -> dict:
    _, entries, paths = load_registry(root)
    if name not in entries:
        raise ManagerError(f"skill not found: {name}")
    item = entries[name]
    return {
        "name": name,
        "category": item.get("category"),
        "status": item.get("status"),
        "path": item["path"],
        "sha256": digest_file(paths[name]),
    }


def verify_pins(root: Path) -> list[str]:
    root = root.resolve(strict=True)
    _, entries, paths = load_registry(root)
    pins = load_pins(root)["pins"]
    errors: list[str] = []
    for name, record in pins.items():
        if name not in entries:
            errors.append(f"{name}: pin references unknown skill")
            continue
        if not isinstance(record, dict):
            errors.append(f"{name}: pin record must be an object")
            continue
        revision = record.get("revision")
        expected_hash = record.get("sha256")
        if not isinstance(revision, str) or not REVISION_RE.fullmatch(revision):
            errors.append(f"{name}: invalid immutable revision")
        if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
            errors.append(f"{name}: invalid SHA-256")
        else:
            try:
                actual = digest_file(paths[name])
            except (OSError, ManagerError) as exc:
                errors.append(f"{name}: {exc}")
            else:
                if actual != expected_hash:
                    errors.append(f"{name}: content hash mismatch")
    return errors


def make_pin(root: Path, name: str, revision: str, source_url: str, license_id: str, reviewed: bool) -> dict:
    root = root.resolve(strict=True)
    _, entries, paths = load_registry(root)
    if name not in entries:
        raise ManagerError(f"skill not found: {name}")
    if entries[name].get("status") not in {"reviewed", "tested"}:
        raise ManagerError("only reviewed or tested skills may be pinned")
    if not reviewed:
        raise ManagerError("explicit --reviewed confirmation is required")
    if not REVISION_RE.fullmatch(revision):
        raise ManagerError("revision must be an immutable 40- or 64-character commit SHA")
    parsed = urlparse(source_url)
    if parsed.scheme != "https" or parsed.netloc.lower() not in {"github.com", "www.github.com"} or not parsed.path.strip("/"):
        raise ManagerError("source URL must be an https://github.com/<owner>/<repo> URL")
    if not license_id.strip() or len(license_id) > 128:
        raise ManagerError("a verified license identifier (max 128 chars) is required")
    return {
        "revision": revision.lower(),
        "source_url": source_url.rstrip("/"),
        "license": license_id.strip(),
        "sha256": digest_file(paths[name]),
        "execution_enabled": False,
    }


def write_pins(root: Path, data: dict) -> None:
    path = root / PIN_FILE
    if path.is_symlink():
        raise ManagerError("pins.json symlink is not allowed")
    if path.exists() and not path.is_file():
        raise ManagerError("pins.json must be a regular file")
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=root, delete=False) as tmp:
            temp_name = tmp.name
            json.dump(data, tmp, indent=2, sort_keys=True)
            tmp.write("\\n")
            tmp.flush()
            os.fsync(tmp.fileno())
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, path)
    except Exception:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="list registered skills")
    show = sub.add_parser("inspect", help="show metadata and content hash")
    show.add_argument("name")
    sub.add_parser("verify", help="verify pinned skill hashes")
    pin = sub.add_parser("pin", help="record reviewed immutable source provenance")
    pin.add_argument("name")
    pin.add_argument("--revision", required=True)
    pin.add_argument("--source-url", required=True)
    pin.add_argument("--license", required=True)
    pin.add_argument("--reviewed", action="store_true", help="confirm manual content/license review")
    pin.add_argument("--apply", action="store_true", help="write pins.json; default is dry-run")
    args = parser.parse_args()

    try:
        root = args.root.resolve(strict=True)
        if args.command == "list":
            _, entries, _ = load_registry(root)
            for name in sorted(entries):
                item = entries[name]
                print(f"{name}\\t{item.get('category', 'uncategorized')}\\t{item.get('status', 'unknown')}")
        elif args.command == "inspect":
            print(json.dumps(inspect_skill(root, args.name), indent=2))
        elif args.command == "verify":
            errors = verify_pins(root)
            if errors:
                for error in errors:
                    print(f"ERROR: {error}", file=sys.stderr)
                return 1
            print("PASS: all pinned skill hashes match")
        elif args.command == "pin":
            record = make_pin(root, args.name, args.revision, args.source_url, args.license, args.reviewed)
            pins = load_pins(root)
            pins["pins"][args.name] = record
            if args.apply:
                write_pins(root, pins)
                print(f"PINNED: {args.name}")
            else:
                print(json.dumps({"status": "dry_run", "skill": args.name, "record": record}, indent=2))
        return 0
    except (ManagerError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
