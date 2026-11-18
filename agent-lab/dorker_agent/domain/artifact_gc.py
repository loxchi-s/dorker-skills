"""Pure artifact garbage-collection contracts and retention policy."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass

_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def gc_plan_token(
    cutoff_unix_ns: int,
    candidates: tuple["ArtifactObjectInfo", ...],
) -> str:
    """Return the deterministic approval token for an immutable GC plan."""
    payload = json.dumps(
        {
            "cutoff_unix_ns": cutoff_unix_ns,
            "candidates": [
                {
                    "sha256": item.sha256,
                    "size_bytes": item.size_bytes,
                    "mtime_unix_ns": item.mtime_unix_ns,
                }
                for item in candidates
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True, slots=True)
class ArtifactObjectInfo:
    sha256: str
    size_bytes: int
    mtime_unix_ns: int

    def __post_init__(self) -> None:
        if not isinstance(self.sha256, str) or not _DIGEST.fullmatch(self.sha256):
            raise ValueError("sha256 must be a lowercase 64-character hex digest")
        for field_name in ("size_bytes", "mtime_unix_ns"):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{field_name} must be a non-negative integer")


@dataclass(frozen=True, slots=True)
class ArtifactRetentionPolicy:
    min_age_seconds: int = 7 * 24 * 60 * 60
    max_candidates: int = 100
    max_scan_objects: int = 10_000

    def __post_init__(self) -> None:
        for field_name in ("min_age_seconds", "max_candidates", "max_scan_objects"):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{field_name} must be a positive integer")


@dataclass(frozen=True, slots=True)
class ArtifactDeletionPlan:
    candidates: tuple[ArtifactObjectInfo, ...]
    total_bytes: int
    cutoff_unix_ns: int
    approval_token: str

    def __post_init__(self) -> None:
        if not isinstance(self.candidates, tuple):
            raise ValueError("GC plan candidates must be an immutable tuple")
        if isinstance(self.cutoff_unix_ns, bool) or not isinstance(self.cutoff_unix_ns, int) or self.cutoff_unix_ns < 0:
            raise ValueError("GC plan cutoff must be a non-negative integer")
        if isinstance(self.total_bytes, bool) or not isinstance(self.total_bytes, int) or self.total_bytes < 0:
            raise ValueError("GC plan total_bytes must be a non-negative integer")
        seen: set[str] = set()
        previous: tuple[int, str] | None = None
        total = 0
        for item in self.candidates:
            if not isinstance(item, ArtifactObjectInfo):
                raise ValueError("GC plan contains an invalid candidate")
            if item.mtime_unix_ns > self.cutoff_unix_ns or item.sha256 in seen:
                raise ValueError("GC plan contains an ineligible or duplicate candidate")
            key = (item.mtime_unix_ns, item.sha256)
            if previous is not None and key < previous:
                raise ValueError("GC plan candidates are not canonically ordered")
            seen.add(item.sha256)
            previous = key
            total += item.size_bytes
        if total != self.total_bytes:
            raise ValueError("GC plan total_bytes does not match its candidates")
        if not isinstance(self.approval_token, str) or not _DIGEST.fullmatch(self.approval_token):
            raise ValueError("GC plan approval token must be a lowercase 64-character hex digest")
        expected = gc_plan_token(self.cutoff_unix_ns, self.candidates)
        if not hmac.compare_digest(expected, self.approval_token):
            raise ValueError("GC plan approval token does not match its candidate metadata")


@dataclass(frozen=True, slots=True)
class ArtifactGCDryRun:
    scanned_objects: int
    referenced_objects: int
    orphaned: tuple[ArtifactObjectInfo, ...]
    missing_digests: tuple[str, ...]
    corrupt_digests: tuple[str, ...]
    truncated: bool

    def __post_init__(self) -> None:
        for field_name in ("scanned_objects", "referenced_objects"):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{field_name} must be a non-negative integer")
        if not isinstance(self.orphaned, tuple) or any(
            not isinstance(item, ArtifactObjectInfo) for item in self.orphaned
        ):
            raise ValueError("orphaned must be a tuple of ArtifactObjectInfo values")
        for field_name in ("missing_digests", "corrupt_digests"):
            values = getattr(self, field_name)
            if not isinstance(values, tuple) or any(
                not isinstance(value, str) or not _DIGEST.fullmatch(value) for value in values
            ):
                raise ValueError(f"{field_name} must contain lowercase SHA-256 digests")
        if not isinstance(self.truncated, bool):
            raise TypeError("truncated must be bool")
