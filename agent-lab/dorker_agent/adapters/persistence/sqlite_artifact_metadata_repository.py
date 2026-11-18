"""SQLite persistence adapter for artifact manifest metadata and GC scans."""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import time
import threading
from contextlib import closing
from pathlib import Path

from ...domain.artifact_manifest import ArtifactManifest
from ...domain.artifact_gc import (
    ArtifactDeletionPlan,
    ArtifactGCDryRun,
    ArtifactObjectInfo,
    ArtifactRetentionPolicy,
    gc_plan_token,
)
from ...ports.artifact_blob_store import ArtifactBlobStore, ArtifactIntegrityError

_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class SQLiteArtifactMetadataRepository:
    """Persist artifact manifests and coordinate immutable blob-store reads."""

    def __init__(
        self,
        database: str | os.PathLike[str],
        blob_store: ArtifactBlobStore,
        *,
        max_records: int = 100_000,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        if isinstance(max_records, bool) or not isinstance(max_records, int) or max_records < 1:
            raise ValueError("max_records must be a positive integer")
        if isinstance(busy_timeout_ms, bool) or not isinstance(busy_timeout_ms, int) or busy_timeout_ms < 0:
            raise ValueError("busy_timeout_ms must be a non-negative integer")
        if blob_store is None:
            raise TypeError("blob_store is required")
        self._database = os.fspath(database)
        if not isinstance(self._database, str) or self._database == ":memory:":
            raise ValueError("a durable SQLite file path is required")
        if os.path.realpath(self._database) != os.path.abspath(self._database):
            raise ValueError("database path must not contain symlinks")
        self._blob_store = blob_store
        self._max_records = max_records
        self._busy_timeout_ms = busy_timeout_ms
        self._lock = threading.RLock()
        Path(self._database).parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self._database, flags, 0o600)
        os.close(fd)
        os.chmod(self._database, 0o600)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(
            self._database, timeout=self._busy_timeout_ms / 1000,
            isolation_level=None,
        )
        db.row_factory = sqlite3.Row
        db.execute(f"PRAGMA busy_timeout={self._busy_timeout_ms}")
        return db

    def _initialize(self) -> None:
        with self._lock, closing(self._connect()) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("""
                CREATE TABLE IF NOT EXISTS artifact_manifests (
                    artifact_id TEXT PRIMARY KEY,
                    sha256 TEXT NOT NULL,
                    name TEXT NOT NULL,
                    media_type TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
                    source TEXT NOT NULL,
                    execution_id TEXT,
                    created_at_unix_ms INTEGER,
                    manifest_json TEXT NOT NULL,
                    created_at REAL NOT NULL
                )
            """)
            db.execute(
                "CREATE INDEX IF NOT EXISTS idx_artifacts_execution "
                "ON artifact_manifests(execution_id, created_at, artifact_id)"
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS idx_artifacts_sha256 "
                "ON artifact_manifests(sha256)"
            )

    @staticmethod
    def _manifest_id(manifest: ArtifactManifest) -> str:
        return hashlib.sha256(manifest.to_json().encode("utf-8")).hexdigest()

    def put(
        self, data: bytes, *, name: str, media_type: str, source: str,
        execution_id: str | None = None, created_at_unix_ms: int | None = None,
    ) -> str:
        manifest = self._blob_store.put(
            data, name=name, media_type=media_type, source=source,
            execution_id=execution_id, created_at_unix_ms=created_at_unix_ms,
        )
        return self.register(manifest)

    def register(self, manifest: ArtifactManifest) -> str:
        if not isinstance(manifest, ArtifactManifest):
            raise TypeError("manifest must be an ArtifactManifest")
        blob = self._blob_store.get(manifest.sha256)
        if not manifest.verify(blob, max_bytes=self._blob_store.max_artifact_bytes):
            raise ArtifactIntegrityError("manifest does not match published artifact bytes")
        artifact_id = self._manifest_id(manifest)
        manifest_json = manifest.to_json()
        with self._lock, closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT manifest_json FROM artifact_manifests WHERE artifact_id=?",
                (artifact_id,),
            ).fetchone()
            if existing is not None:
                if existing["manifest_json"] != manifest_json:
                    db.rollback()
                    raise ArtifactIntegrityError("artifact manifest ID collision")
                db.commit()
                return artifact_id
            count = db.execute("SELECT COUNT(*) FROM artifact_manifests").fetchone()[0]
            if count >= self._max_records:
                db.rollback()
                raise RuntimeError("artifact index capacity reached")
            db.execute(
                "INSERT INTO artifact_manifests VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    artifact_id, manifest.sha256.lower(), manifest.name,
                    manifest.media_type, manifest.size_bytes, manifest.source,
                    manifest.execution_id, manifest.created_at_unix_ms,
                    manifest_json, time.time(),
                ),
            )
            db.commit()
        return artifact_id

    def get_manifest(self, artifact_id: str) -> ArtifactManifest | None:
        self._validate_artifact_id(artifact_id)
        with closing(self._connect()) as db:
            row = db.execute(
                "SELECT manifest_json FROM artifact_manifests WHERE artifact_id=?",
                (artifact_id,),
            ).fetchone()
        if row is None:
            return None
        payload = json.loads(row["manifest_json"])
        return ArtifactManifest(**payload)

    def get(self, artifact_id: str) -> tuple[ArtifactManifest, bytes] | None:
        manifest = self.get_manifest(artifact_id)
        if manifest is None:
            return None
        data = self._blob_store.get(manifest.sha256)
        if not manifest.verify(data, max_bytes=self._blob_store.max_artifact_bytes):
            raise ArtifactIntegrityError("artifact bytes do not match indexed manifest")
        return manifest, data

    def list_for_execution(self, execution_id: str, *, limit: int = 100) -> list[tuple[str, ArtifactManifest]]:
        if not isinstance(execution_id, str) or not execution_id.strip() or len(execution_id) > 128:
            raise ValueError("execution_id must be 1..128 non-whitespace characters")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("limit must be an integer from 1 to 1000")
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT artifact_id, manifest_json FROM artifact_manifests "
                "WHERE execution_id=? ORDER BY created_at, artifact_id LIMIT ?",
                (execution_id, limit),
            ).fetchall()
        return [
            (row["artifact_id"], ArtifactManifest(**json.loads(row["manifest_json"])))
            for row in rows
        ]

    def dry_run_gc(self, *, max_scan_objects: int = 10_000) -> ArtifactGCDryRun:
        """Report unreferenced blobs; this method never deletes or mutates data."""
        objects, corrupt, truncated = self._blob_store.scan_objects(max_objects=max_scan_objects)
        with closing(self._connect()) as db:
            referenced = {
                row[0] for row in db.execute(
                    "SELECT DISTINCT sha256 FROM artifact_manifests"
                ).fetchall()
            }
        object_digests = {item.sha256 for item in objects}
        corrupt_set = set(corrupt)
        missing = tuple(sorted(referenced - object_digests - corrupt_set))
        orphaned = tuple(item for item in objects if item.sha256 not in referenced)
        return ArtifactGCDryRun(
            scanned_objects=len(objects) + len(corrupt),
            referenced_objects=len(referenced),
            orphaned=orphaned,
            missing_digests=missing,
            corrupt_digests=tuple(sorted(corrupt)),
            truncated=truncated,
        )

    def build_gc_plan(
        self, policy: ArtifactRetentionPolicy, *, now_unix_ns: int | None = None,
    ) -> ArtifactDeletionPlan:
        """Build a non-destructive, approval-gated candidate plan; never deletes."""
        if not isinstance(policy, ArtifactRetentionPolicy):
            raise TypeError("policy must be an ArtifactRetentionPolicy")
        if now_unix_ns is None:
            now_unix_ns = time.time_ns()
        if isinstance(now_unix_ns, bool) or not isinstance(now_unix_ns, int) or now_unix_ns < 0:
            raise ValueError("now_unix_ns must be a non-negative integer")
        report = self.dry_run_gc(max_scan_objects=policy.max_scan_objects)
        if report.truncated:
            raise RuntimeError("cannot build deletion plan from a truncated scan")
        raw_cutoff = now_unix_ns - policy.min_age_seconds * 1_000_000_000
        cutoff = max(0, raw_cutoff)
        eligible = sorted(
            (item for item in report.orphaned if raw_cutoff >= 0 and item.mtime_unix_ns <= raw_cutoff),
            key=lambda item: (item.mtime_unix_ns, item.sha256),
        )[:policy.max_candidates]
        candidates = tuple(eligible)
        token = gc_plan_token(cutoff, candidates)
        return ArtifactDeletionPlan(
            candidates=candidates,
            total_bytes=sum(item.size_bytes for item in candidates),
            cutoff_unix_ns=cutoff,
            approval_token=token,
        )

    @staticmethod
    def _validate_artifact_id(artifact_id: str) -> str:
        if not isinstance(artifact_id, str) or not _DIGEST.fullmatch(artifact_id):
            raise ValueError("artifact_id must be a lowercase 64-character hex digest")
        return artifact_id
