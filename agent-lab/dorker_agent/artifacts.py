"""Compatibility facade for artifact storage and garbage-collection APIs.

New code should depend on domain contracts, ports, and concrete adapters directly.
"""
from __future__ import annotations

from .domain.artifact_manifest import ArtifactManifest
from .domain.artifact_gc import (
    ArtifactDeletionPlan,
    ArtifactGCDryRun,
    ArtifactObjectInfo,
    ArtifactRetentionPolicy,
)
from .domain.identity import GitHubActorClaim, VerifiedGitHubActor
from .ports.identity import GitHubIdentityVerifier
from .ports.artifact_gc_audit import AuditStore
from .adapters.storage.errors import (
    ArtifactIntegrityError,
    ArtifactNotFoundError,
    ArtifactStoreError,
)
from .adapters.storage.content_addressed_artifact_store import ContentAddressedArtifactStore
from .adapters.persistence.sqlite_artifact_index import SQLiteArtifactIndex

__all__ = [
    "ArtifactDeletionPlan",
    "ArtifactGCDryRun",
    "ArtifactIntegrityError",
    "ArtifactManifest",
    "ArtifactNotFoundError",
    "ArtifactObjectInfo",
    "ArtifactRetentionPolicy",
    "ArtifactStoreError",
    "AuditStore",
    "ContentAddressedArtifactStore",
    "GitHubActorClaim",
    "GitHubIdentityVerifier",
    "SQLiteArtifactIndex",
    "VerifiedGitHubActor",
]
