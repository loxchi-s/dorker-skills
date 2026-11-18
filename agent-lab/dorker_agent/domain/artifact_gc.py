"""Pure artifact garbage-collection contracts and retention policy."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ArtifactObjectInfo:
    sha256: str
    size_bytes: int
    mtime_unix_ns: int


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


@dataclass(frozen=True, slots=True)
class ArtifactGCDryRun:
    scanned_objects: int
    referenced_objects: int
    orphaned: tuple[ArtifactObjectInfo, ...]
    missing_digests: tuple[str, ...]
    corrupt_digests: tuple[str, ...]
    truncated: bool


