"""Canonical audit event hashing shared by persistence adapters."""
from __future__ import annotations

import hashlib
import json

from .audit import AuditServiceError

ZERO_HASH = "0" * 64


def canonical_hash(value: dict[str, object]) -> str:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AuditServiceError(400, "invalid_request", "request is not canonical JSON") from exc
    return hashlib.sha256(encoded).hexdigest()


def event_hash(event: dict[str, object]) -> str:
    payload = {key: value for key, value in event.items() if key != "event_hash"}
    return canonical_hash(payload)
