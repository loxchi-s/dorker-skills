"""Port and stable error contract for content-addressed artifact storage."""
from __future__ import annotations

from typing import Protocol

from ..domain.artifact_gc import ArtifactObjectInfo
from ..domain.artifact_manifest import ArtifactManifest


class ArtifactStoreError(RuntimeError):
    """Base error for artifact blob-store operations."""


class ArtifactNotFoundError(ArtifactStoreError):
    """The requested content digest is not present."""


class ArtifactIntegrityError(ArtifactStoreError):
    """Stored bytes do not match their content address or manifest."""


class ArtifactBlobStore(Protocol):
    """Provider-neutral port for bounded immutable artifact bytes."""

    @property
    def max_artifact_bytes(self) -> int: ...

    def put(
        self,
        data: bytes,
        *,
        name: str,
        media_type: str,
        source: str,
        execution_id: str | None = None,
        created_at_unix_ms: int | None = None,
    ) -> ArtifactManifest: ...

    def get(self, sha256: str) -> bytes: ...

    def scan_objects(
        self, *, max_objects: int = 10_000
    ) -> tuple[list[ArtifactObjectInfo], list[str], bool]: ...

    def contains(self, sha256: str) -> bool: ...
