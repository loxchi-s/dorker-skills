"""Domain value object for artifact metadata; independent of storage/runtime adapters."""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ArtifactManifest:
    """Deterministic metadata for a single bounded byte artifact."""

    name: str
    media_type: str
    size_bytes: int
    sha256: str
    source: str
    execution_id: str | None = None
    created_at_unix_ms: int | None = None

    def __post_init__(self) -> None:
        for field_name, value in (
            ("name", self.name), ("media_type", self.media_type),
            ("source", self.source),
        ):
            if not isinstance(value, str) or not value or len(value) > 256:
                raise ValueError(f"{field_name} must be a non-empty string up to 256 characters")
            if any(ord(char) < 32 for char in value):
                raise ValueError(f"{field_name} must not contain control characters")
            if field_name == "name" and (
                value in {".", ".."} or "/" in value or "\\" in value
            ):
                raise ValueError("name must be a plain filename, not a path")
        if isinstance(self.size_bytes, bool) or not isinstance(self.size_bytes, int) or self.size_bytes < 0:
            raise ValueError("size_bytes must be a non-negative integer")
        if (
            not isinstance(self.sha256, str)
            or len(self.sha256) != 64
            or self.sha256 != self.sha256.lower()
        ):
            raise ValueError("sha256 must be a lowercase 64-character hex digest")
        try:
            int(self.sha256, 16)
        except ValueError as exc:
            raise ValueError("sha256 must be a lowercase 64-character hex digest") from exc
        if self.execution_id is not None:
            if (not isinstance(self.execution_id, str) or not self.execution_id
                    or len(self.execution_id) > 128
                    or any(ord(char) < 32 for char in self.execution_id)):
                raise ValueError("execution_id must be a valid identifier up to 128 characters")
        if self.created_at_unix_ms is not None:
            if (isinstance(self.created_at_unix_ms, bool)
                    or not isinstance(self.created_at_unix_ms, int)
                    or self.created_at_unix_ms < 0):
                raise ValueError("created_at_unix_ms must be a non-negative integer")

    @classmethod
    def from_bytes(
        cls, *, name: str, media_type: str, data: bytes, source: str,
        execution_id: str | None = None,
        created_at_unix_ms: int | None = None,
    ) -> "ArtifactManifest":
        if not isinstance(data, bytes):
            raise TypeError("artifact data must be bytes")
        return cls(
            name=name, media_type=media_type, size_bytes=len(data),
            sha256=hashlib.sha256(data).hexdigest(), source=source,
            execution_id=execution_id, created_at_unix_ms=created_at_unix_ms,
        )

    def verify(self, data: bytes, *, max_bytes: int) -> bool:
        if not isinstance(data, bytes):
            return False
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0:
            raise ValueError("max_bytes must be a non-negative integer")
        if len(data) > max_bytes or len(data) != self.size_bytes:
            return False
        return hmac.compare_digest(hashlib.sha256(data).hexdigest(), self.sha256)

    def to_json(self) -> str:
        return json.dumps(
            {
                "name": self.name,
                "media_type": self.media_type,
                "size_bytes": self.size_bytes,
                "sha256": self.sha256,
                "source": self.source,
                "execution_id": self.execution_id,
                "created_at_unix_ms": self.created_at_unix_ms,
            },
            ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        )

