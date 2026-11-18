"""Compatibility facade composing artifact metadata and GC audit adapters."""
from __future__ import annotations

import os

from ...domain.artifact_gc import ArtifactDeletionPlan, ArtifactRetentionPolicy, ArtifactGCDryRun
from ...domain.artifact_manifest import ArtifactManifest
from ...domain.identity import GitHubActorClaim
from ...ports.artifact_blob_store import ArtifactBlobStore
from ...ports.identity import GitHubIdentityVerifier
from .sqlite_artifact_gc_audit_store import SQLiteArtifactGCAuditStore
from .sqlite_artifact_metadata_repository import SQLiteArtifactMetadataRepository


class SQLiteArtifactIndex:
    """Compose metadata persistence and approval-audit adapters behind the legacy API."""

    def __init__(
        self,
        database: str | os.PathLike[str],
        blob_store: ArtifactBlobStore,
        *,
        max_records: int = 100_000,
        max_audit_records: int = 100_000,
        busy_timeout_ms: int = 5_000,
        identity_verifier: GitHubIdentityVerifier | None = None,
    ) -> None:
        self._metadata = SQLiteArtifactMetadataRepository(
            database,
            blob_store,
            max_records=max_records,
            busy_timeout_ms=busy_timeout_ms,
        )
        self._audit = SQLiteArtifactGCAuditStore(
            database,
            max_audit_records=max_audit_records,
            busy_timeout_ms=busy_timeout_ms,
            identity_verifier=identity_verifier,
        )

    def put(
        self,
        data: bytes,
        *,
        name: str,
        media_type: str,
        source: str,
        execution_id: str | None = None,
        created_at_unix_ms: int | None = None,
    ) -> str:
        return self._metadata.put(
            data,
            name=name,
            media_type=media_type,
            source=source,
            execution_id=execution_id,
            created_at_unix_ms=created_at_unix_ms,
        )

    def register(self, manifest: ArtifactManifest) -> str:
        return self._metadata.register(manifest)

    def get_manifest(self, artifact_id: str) -> ArtifactManifest | None:
        return self._metadata.get_manifest(artifact_id)

    def get(self, artifact_id: str) -> tuple[ArtifactManifest, bytes] | None:
        return self._metadata.get(artifact_id)

    def list_for_execution(
        self, execution_id: str, *, limit: int = 100,
    ) -> list[tuple[str, ArtifactManifest]]:
        return self._metadata.list_for_execution(execution_id, limit=limit)

    def dry_run_gc(self, *, max_scan_objects: int = 10_000) -> ArtifactGCDryRun:
        return self._metadata.dry_run_gc(max_scan_objects=max_scan_objects)

    def build_gc_plan(
        self, policy: ArtifactRetentionPolicy, *, now_unix_ns: int | None = None,
    ) -> ArtifactDeletionPlan:
        return self._metadata.build_gc_plan(policy, now_unix_ns=now_unix_ns)

    def record_gc_plan(
        self, plan: ArtifactDeletionPlan, *, claim: GitHubActorClaim,
        idempotency_key: str,
    ) -> str:
        return self._audit.record_gc_plan(
            plan, claim=claim, idempotency_key=idempotency_key,
        )

    def record_gc_approval(
        self,
        approval_token: str,
        *,
        claim: GitHubActorClaim,
        approved: bool,
        idempotency_key: str,
    ) -> str:
        return self._audit.record_gc_approval(
            approval_token,
            claim=claim,
            approved=approved,
            idempotency_key=idempotency_key,
        )

    def list_audit_events(self, *, limit: int = 100) -> list[dict[str, object]]:
        return self._audit.list_audit_events(limit=limit)

    def verify_audit_log(self) -> bool:
        return self._audit.verify_audit_log()
