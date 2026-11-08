"""POSIX content-addressed artifact storage with bounded, atomic writes."""
from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import os
import re
import stat
import threading
import time
import uuid
from contextlib import closing
from dataclasses import dataclass
from typing import Protocol
from pathlib import Path

from .container_sandbox import ArtifactManifest

_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class ArtifactStoreError(RuntimeError):
    """Base error for artifact storage failures."""


class ArtifactNotFoundError(ArtifactStoreError):
    """The requested content digest is not present."""


class ArtifactIntegrityError(ArtifactStoreError):
    """Stored bytes do not match their content address."""


@dataclass(frozen=True, slots=True)
class GitHubActorClaim:
    github_id: int
    login: str
    oidc_token: str


@dataclass(frozen=True, slots=True)
class VerifiedGitHubActor:
    github_id: int
    login: str


class GitHubIdentityVerifier(Protocol):
    """Trusted host adapter that verifies a GitHub Actions OIDC token."""

    def verify(self, claim: GitHubActorClaim) -> VerifiedGitHubActor:
        """Verify token signature/claims and return its canonical GitHub actor."""


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


class ContentAddressedArtifactStore:
    """Store immutable bytes at <root>/<sha256[:2]>/<sha256[2:]>.

    The root must be a pre-created, trusted directory. Writes use same-filesystem
    hard-link publication so an existing object is never overwritten. Per-object
    byte limits are enforced; this is not a global disk quota or hostile-host boundary.
    """

    def __init__(self, root: str | os.PathLike[str], *, max_artifact_bytes: int = 16 * 1024 * 1024) -> None:
        if isinstance(max_artifact_bytes, bool) or not isinstance(max_artifact_bytes, int) or max_artifact_bytes < 1:
            raise ValueError("max_artifact_bytes must be a positive integer")
        raw_root = os.fspath(root)
        if not isinstance(raw_root, str) or not os.path.isabs(raw_root):
            raise ValueError("artifact root must be an absolute path")
        if os.path.realpath(raw_root) != os.path.abspath(raw_root):
            raise ValueError("artifact root must not contain symlinks")
        root_stat = os.lstat(raw_root)
        if not stat.S_ISDIR(root_stat.st_mode):
            raise ValueError("artifact root must be an existing directory")
        if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
            raise RuntimeError("artifact store requires POSIX no-follow and dir_fd support")
        self._root = raw_root
        self._max_artifact_bytes = max_artifact_bytes
        self._lock = threading.RLock()

    @property
    def max_artifact_bytes(self) -> int:
        return self._max_artifact_bytes

    def put(
        self, data: bytes, *, name: str, media_type: str, source: str,
        execution_id: str | None = None, created_at_unix_ms: int | None = None,
    ) -> ArtifactManifest:
        if not isinstance(data, bytes):
            raise TypeError("artifact data must be bytes")
        if len(data) > self._max_artifact_bytes:
            raise ValueError("artifact exceeds max_artifact_bytes")
        manifest = ArtifactManifest.from_bytes(
            name=name, media_type=media_type, data=data, source=source,
            execution_id=execution_id, created_at_unix_ms=created_at_unix_ms,
        )
        shard_name, object_name = manifest.sha256[:2], manifest.sha256[2:]
        with self._lock:
            root_fd = self._open_root()
            shard_fd = -1
            temp_name = f".tmp-{uuid.uuid4().hex}"
            try:
                try:
                    os.mkdir(shard_name, mode=0o700, dir_fd=root_fd)
                except FileExistsError:
                    pass
                shard_fd = os.open(
                    shard_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=root_fd,
                )
                try:
                    fd = os.open(
                        temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600, dir_fd=shard_fd,
                    )
                    try:
                        view = memoryview(data)
                        offset = 0
                        while offset < len(view):
                            written = os.write(fd, view[offset:offset + 65536])
                            if written <= 0:
                                raise ArtifactStoreError("short write while storing artifact")
                            offset += written
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    try:
                        os.link(
                            temp_name, object_name, src_dir_fd=shard_fd,
                            dst_dir_fd=shard_fd, follow_symlinks=False,
                        )
                        os.fsync(shard_fd)
                    except FileExistsError:
                        existing = self._read_from_shard(shard_fd, object_name)
                        if not hmac.compare_digest(hashlib.sha256(existing).hexdigest(), manifest.sha256):
                            raise ArtifactIntegrityError("existing content-addressed object failed digest verification")
                finally:
                    try:
                        os.unlink(temp_name, dir_fd=shard_fd)
                    except FileNotFoundError:
                        pass
            finally:
                if shard_fd >= 0:
                    os.close(shard_fd)
                os.close(root_fd)
        return manifest

    def get(self, sha256: str) -> bytes:
        digest = self._validate_digest(sha256)
        shard_name, object_name = digest[:2], digest[2:]
        root_fd = self._open_root()
        shard_fd = -1
        try:
            try:
                shard_fd = os.open(
                    shard_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=root_fd,
                )
            except FileNotFoundError as exc:
                raise ArtifactNotFoundError("artifact not found") from exc
            data = self._read_from_shard(shard_fd, object_name)
            actual = hashlib.sha256(data).hexdigest()
            if not hmac.compare_digest(actual, digest):
                raise ArtifactIntegrityError("artifact content does not match requested digest")
            return data
        except FileNotFoundError as exc:
            raise ArtifactNotFoundError("artifact not found") from exc
        finally:
            if shard_fd >= 0:
                os.close(shard_fd)
            os.close(root_fd)

    def scan_objects(self, *, max_objects: int = 10_000) -> tuple[list[ArtifactObjectInfo], list[str], bool]:
        """Enumerate canonical blobs without following symlinks; verify every object."""
        if isinstance(max_objects, bool) or not isinstance(max_objects, int) or max_objects < 1:
            raise ValueError("max_objects must be a positive integer")
        objects: list[ArtifactObjectInfo] = []
        corrupt: list[str] = []
        truncated = False
        root_fd = self._open_root()
        try:
            for shard_name in sorted(os.listdir(root_fd)):
                if not re.fullmatch(r"[0-9a-f]{2}", shard_name):
                    continue
                try:
                    shard_fd = os.open(
                        shard_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=root_fd,
                    )
                except (FileNotFoundError, NotADirectoryError):
                    continue
                try:
                    for object_name in sorted(os.listdir(shard_fd)):
                        if not re.fullmatch(r"[0-9a-f]{62}", object_name):
                            continue
                        digest = shard_name + object_name
                        try:
                            info = os.stat(object_name, dir_fd=shard_fd, follow_symlinks=False)
                        except FileNotFoundError:
                            continue
                        if not stat.S_ISREG(info.st_mode):
                            continue
                        if len(objects) + len(corrupt) >= max_objects:
                            truncated = True
                            return objects, corrupt, truncated
                        try:
                            data = self.get(digest)
                        except ArtifactIntegrityError:
                            corrupt.append(digest)
                            continue
                        except ArtifactNotFoundError:
                            continue
                        except OSError:
                            corrupt.append(digest)
                            continue
                        objects.append(ArtifactObjectInfo(digest, len(data), info.st_mtime_ns))
                finally:
                    os.close(shard_fd)
        finally:
            os.close(root_fd)
        return objects, corrupt, truncated

    def contains(self, sha256: str) -> bool:
        try:
            self.get(sha256)
            return True
        except ArtifactNotFoundError:
            return False

    @staticmethod
    def _validate_digest(sha256: str) -> str:
        if not isinstance(sha256, str) or not _DIGEST.fullmatch(sha256):
            raise ValueError("sha256 must be a lowercase 64-character hex digest")
        return sha256

    def _open_root(self) -> int:
        return os.open(self._root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    def _read_from_shard(self, shard_fd: int, object_name: str) -> bytes:
        fd = os.open(object_name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=shard_fd)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise ArtifactIntegrityError("artifact object is not a regular file")
            if info.st_size > self._max_artifact_bytes:
                raise ArtifactIntegrityError("stored artifact exceeds configured size limit")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(fd, min(65536, self._max_artifact_bytes - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                if total > self._max_artifact_bytes:
                    raise ArtifactIntegrityError("stored artifact exceeds configured size limit")
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(fd)


class SQLiteArtifactIndex:
    """Durable metadata index for content-addressed blobs.

    Blob publication precedes the SQLite transaction. A database failure can
    leave an unindexed blob; it cannot expose a manifest for missing bytes.
    The index is single-host SQLite metadata, separate from execution storage.
    """

    def __init__(
        self, database: str | os.PathLike[str], blob_store: ContentAddressedArtifactStore,
        *, max_records: int = 100_000, max_audit_records: int = 100_000,
        busy_timeout_ms: int = 5_000, identity_verifier: GitHubIdentityVerifier | None = None,
    ) -> None:
        if isinstance(max_records, bool) or not isinstance(max_records, int) or max_records < 1:
            raise ValueError("max_records must be a positive integer")
        if isinstance(max_audit_records, bool) or not isinstance(max_audit_records, int) or max_audit_records < 1:
            raise ValueError("max_audit_records must be a positive integer")
        if isinstance(busy_timeout_ms, bool) or not isinstance(busy_timeout_ms, int) or busy_timeout_ms < 0:
            raise ValueError("busy_timeout_ms must be a non-negative integer")
        self._database = os.fspath(database)
        if not isinstance(self._database, str) or self._database == ":memory:":
            raise ValueError("a durable SQLite file path is required")
        self._blob_store = blob_store
        self._max_records = max_records
        self._max_audit_records = max_audit_records
        self._identity_verifier = identity_verifier
        self._busy_timeout_ms = busy_timeout_ms
        self._lock = threading.RLock()
        Path(self._database).parent.mkdir(parents=True, exist_ok=True)
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
            db.execute("""
                CREATE TABLE IF NOT EXISTS artifact_audit_log (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp_unix_ms INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    approval_token TEXT,
                    details_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE
                )
            """)

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
        cutoff = now_unix_ns - policy.min_age_seconds * 1_000_000_000
        eligible = sorted(
            (item for item in report.orphaned if item.mtime_unix_ns <= cutoff),
            key=lambda item: (item.mtime_unix_ns, item.sha256),
        )[:policy.max_candidates]
        candidates = tuple(eligible)
        payload = json.dumps(
            {
                "cutoff_unix_ns": cutoff,
                "candidates": [
                    {"sha256": item.sha256, "size_bytes": item.size_bytes,
                     "mtime_unix_ns": item.mtime_unix_ns}
                    for item in candidates
                ],
            },
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        token = hashlib.sha256(payload).hexdigest()
        return ArtifactDeletionPlan(
            candidates=candidates,
            total_bytes=sum(item.size_bytes for item in candidates),
            cutoff_unix_ns=cutoff,
            approval_token=token,
        )

    @staticmethod
    def _audit_hash(payload: dict[str, object]) -> str:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def _verified_actor(self, claim: GitHubActorClaim) -> VerifiedGitHubActor:
        if self._identity_verifier is None:
            raise RuntimeError("GitHub identity verification is not configured")
        if not isinstance(claim, GitHubActorClaim):
            raise TypeError("claim must be a GitHubActorClaim")
        if isinstance(claim.github_id, bool) or not isinstance(claim.github_id, int) or claim.github_id < 1:
            raise ValueError("github_id must be a positive integer")
        if not isinstance(claim.login, str) or not claim.login.strip() or len(claim.login) > 39:
            raise ValueError("login must be 1..39 non-whitespace characters")
        if not isinstance(claim.oidc_token, str) or not claim.oidc_token or len(claim.oidc_token) > 16_384:
            raise ValueError("OIDC token must be 1..16384 characters")
        actor = self._identity_verifier.verify(claim)
        if not isinstance(actor, VerifiedGitHubActor):
            raise TypeError("identity verifier must return VerifiedGitHubActor")
        if isinstance(actor.github_id, bool) or not isinstance(actor.github_id, int) or actor.github_id < 1:
            raise ValueError("verified GitHub ID must be a positive integer")
        if not isinstance(actor.login, str) or not actor.login.strip() or len(actor.login) > 39:
            raise ValueError("verified GitHub login is invalid")
        return actor

    def record_gc_plan(self, plan: ArtifactDeletionPlan, *, claim: GitHubActorClaim) -> str:
        if not isinstance(plan, ArtifactDeletionPlan):
            raise TypeError("plan must be an ArtifactDeletionPlan")
        actor = self._verified_actor(claim)
        details = {
            "candidate_count": len(plan.candidates),
            "total_bytes": plan.total_bytes,
            "cutoff_unix_ns": plan.cutoff_unix_ns,
            "candidates": [
                {"sha256": item.sha256, "size_bytes": item.size_bytes}
                for item in plan.candidates
            ],
            "github_actor_id": actor.github_id,
            "github_login": actor.login,
        }
        return self._append_audit_event(
            actor=f"github:{actor.github_id}:{actor.login}",
            action="gc_plan_created",
            approval_token=plan.approval_token, details=details,
        )

    def record_gc_approval(
        self, approval_token: str, *, claim: GitHubActorClaim, approved: bool,
    ) -> str:
        if not isinstance(approval_token, str) or not _DIGEST.fullmatch(approval_token):
            raise ValueError("approval_token must be a lowercase 64-character hex digest")
        if not isinstance(approved, bool):
            raise TypeError("approved must be bool")
        actor = self._verified_actor(claim)
        return self._append_audit_event(
            actor=f"github:{actor.github_id}:{actor.login}",
            action="gc_plan_approved" if approved else "gc_plan_rejected",
            approval_token=approval_token,
            details={"approved": approved, "github_actor_id": actor.github_id,
                     "github_login": actor.login},
            require_distinct_approver=True,
        )

    def list_audit_events(self, *, limit: int = 100) -> list[dict[str, object]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("limit must be an integer from 1 to 1000")
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT sequence, timestamp_unix_ms, actor, action, approval_token, "
                "details_json, previous_hash, event_hash FROM artifact_audit_log "
                "ORDER BY sequence DESC LIMIT ?", (limit,),
            ).fetchall()
        return [
            {
                "sequence": row["sequence"],
                "timestamp_unix_ms": row["timestamp_unix_ms"],
                "actor": row["actor"],
                "action": row["action"],
                "approval_token": row["approval_token"],
                "details": json.loads(row["details_json"]),
                "previous_hash": row["previous_hash"],
                "event_hash": row["event_hash"],
            }
            for row in reversed(rows)
        ]

    def verify_audit_log(self) -> bool:
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT sequence, timestamp_unix_ms, actor, action, approval_token, "
                "details_json, previous_hash, event_hash FROM artifact_audit_log "
                "ORDER BY sequence"
            ).fetchall()
        previous = "0" * 64
        for row in rows:
            payload = {
                "sequence": row["sequence"],
                "timestamp_unix_ms": row["timestamp_unix_ms"],
                "actor": row["actor"],
                "action": row["action"],
                "approval_token": row["approval_token"],
                "details_json": row["details_json"],
                "previous_hash": row["previous_hash"],
            }
            if row["previous_hash"] != previous:
                return False
            expected = self._audit_hash(payload)
            if not hmac.compare_digest(expected, row["event_hash"]):
                return False
            previous = row["event_hash"]
        return True

    def _append_audit_event(
        self, *, actor: str, action: str, approval_token: str | None,
        details: dict[str, object], require_distinct_approver: bool = False,
    ) -> str:
        details_json = json.dumps(details, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        if len(details_json.encode("utf-8")) > 64 * 1024:
            raise ValueError("audit event details exceed 64 KiB")
        with self._lock, closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            if require_distinct_approver:
                plan_row = db.execute(
                    "SELECT details_json FROM artifact_audit_log "
                    "WHERE action='gc_plan_created' AND approval_token=? "
                    "ORDER BY sequence DESC LIMIT 1",
                    (approval_token,),
                ).fetchone()
                if plan_row is None:
                    db.rollback()
                    raise ValueError("approval token has no recorded GC plan")
                creator_id = json.loads(plan_row["details_json"]).get("github_actor_id")
                approver_id = details.get("github_actor_id")
                if not isinstance(creator_id, int) or creator_id == approver_id:
                    db.rollback()
                    raise ValueError("GC plan approval requires a different GitHub actor")
            count = db.execute("SELECT COUNT(*) FROM artifact_audit_log").fetchone()[0]
            if count >= self._max_audit_records:
                db.rollback()
                raise RuntimeError("artifact audit log capacity reached")
            row = db.execute(
                "SELECT sequence, event_hash FROM artifact_audit_log ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            previous_hash = row["event_hash"] if row else "0" * 64
            sequence = (row["sequence"] + 1) if row else 1
            timestamp = time.time_ns() // 1_000_000
            payload = {
                "sequence": sequence,
                "timestamp_unix_ms": timestamp,
                "actor": actor,
                "action": action,
                "approval_token": approval_token,
                "details_json": details_json,
                "previous_hash": previous_hash,
            }
            event_hash = self._audit_hash(payload)
            db.execute(
                "INSERT INTO artifact_audit_log "
                "(sequence, timestamp_unix_ms, actor, action, approval_token, details_json, previous_hash, event_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (sequence, timestamp, actor, action, approval_token, details_json, previous_hash, event_hash),
            )
            db.commit()
        return event_hash

    @staticmethod
    def _validate_artifact_id(artifact_id: str) -> str:
        if not isinstance(artifact_id, str) or not _DIGEST.fullmatch(artifact_id):
            raise ValueError("artifact_id must be a lowercase 64-character hex digest")
        return artifact_id
