"""Pure validation of audit API payloads and cursors."""
from __future__ import annotations

import base64
import hashlib
import json
import re

from .errors import AuditServiceError

_MAX_BODY_BYTES = 64 * 1024
_KEY = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")

def _strict_object(raw: bytes) -> dict[str, object]:
    if len(raw) > _MAX_BODY_BYTES:
        raise AuditServiceError(413, "invalid_request", "request body exceeds 64 KiB")

    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise AuditServiceError(400, "invalid_request", "request JSON is invalid") from exc
    if not isinstance(value, dict):
        raise AuditServiceError(400, "invalid_request", "request body must be an object")
    return value

def _validate_plan(value: object) -> tuple[str, dict[str, object]]:
    if not isinstance(value, dict) or set(value) != {
        "approval_token", "cutoff_unix_ns", "total_bytes", "candidates",
    }:
        raise AuditServiceError(400, "invalid_request", "plan fields do not match contract")
    token = value["approval_token"]
    cutoff = value["cutoff_unix_ns"]
    total = value["total_bytes"]
    candidates = value["candidates"]
    if not isinstance(token, str) or not _DIGEST.fullmatch(token):
        raise AuditServiceError(400, "invalid_request", "approval_token is invalid")
    if isinstance(cutoff, bool) or not isinstance(cutoff, int) or cutoff < 0:
        raise AuditServiceError(400, "invalid_request", "cutoff_unix_ns is invalid")
    if isinstance(total, bool) or not isinstance(total, int) or total < 0:
        raise AuditServiceError(400, "invalid_request", "total_bytes is invalid")
    if not isinstance(candidates, list) or len(candidates) > 100:
        raise AuditServiceError(400, "invalid_request", "candidates must contain at most 100 items")
    normalized = []
    seen = set()
    for item in candidates:
        if not isinstance(item, dict) or set(item) != {"sha256", "size_bytes", "mtime_unix_ns"}:
            raise AuditServiceError(400, "invalid_request", "candidate fields are invalid")
        digest, size, mtime = item["sha256"], item["size_bytes"], item["mtime_unix_ns"]
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest) or digest in seen:
            raise AuditServiceError(400, "invalid_request", "candidate digest is invalid or duplicated")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise AuditServiceError(400, "invalid_request", "candidate size_bytes is invalid")
        if isinstance(mtime, bool) or not isinstance(mtime, int) or mtime < 0 or mtime > cutoff:
            raise AuditServiceError(400, "invalid_request", "candidate mtime_unix_ns is invalid")
        seen.add(digest)
        normalized.append({"sha256": digest, "size_bytes": size, "mtime_unix_ns": mtime})
    if normalized != sorted(normalized, key=lambda row: (row["mtime_unix_ns"], row["sha256"])):
        raise AuditServiceError(400, "invalid_request", "candidates are not canonically ordered")
    if sum(row["size_bytes"] for row in normalized) != total:
        raise AuditServiceError(400, "invalid_request", "total_bytes does not match candidates")
    plan_payload = {"cutoff_unix_ns": cutoff, "candidates": normalized}
    if not hashlib.sha256(json.dumps(
        plan_payload, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest() == token:
        raise AuditServiceError(422, "integrity_violation", "approval token does not match plan")
    return token, {
        "approval_token": token, "cutoff_unix_ns": cutoff,
        "total_bytes": total, "candidates": normalized,
    }

def validate_key(value: object) -> str
        if not isinstance(value, str) or not _KEY.fullmatch(value):
            raise AuditServiceError(400, "invalid_request", "idempotency key is invalid")
        return value

def encode_cursor(offset: int) -> str
        return base64.urlsafe_b64encode(str(offset).encode("ascii")).rstrip(b"=").decode("ascii")

def decode_cursor(cursor: str | None) -> int
        if cursor is None:
            return 0
        if not isinstance(cursor, str) or not 1 <= len(cursor) <= 128:
            raise AuditServiceError(400, "invalid_request", "cursor is invalid")
        try:
            raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
            value = raw.decode("ascii")
            if not value.isdecimal() or len(value) > 10:
                raise ValueError("invalid cursor")
            return int(value)
        except (ValueError, UnicodeDecodeError) as exc:
            raise AuditServiceError(400, "invalid_request", "cursor is invalid") from exc
