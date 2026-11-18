"""SQLite persistence adapter for approval-gated artifact GC audit events."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import time
import threading
from contextlib import closing
from pathlib import Path

from ...domain.artifact_gc import ArtifactDeletionPlan, ArtifactObjectInfo
from ...domain.identity import GitHubActorClaim, VerifiedGitHubActor
from ...ports.identity import GitHubIdentityVerifier
from ...ports.artifact_blob_store import ArtifactIntegrityError

_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class SQLiteArtifactGCAuditStore:
    """Append-only, hash-chained audit store for artifact GC approvals."""

    def __init__(
        self,
        database: str | os.PathLike[str],
        *,
        max_audit_records: int = 100_000,
        busy_timeout_ms: int = 5_000,
        identity_verifier: GitHubIdentityVerifier | None = None,
    ) -> None:
        if isinstance(max_audit_records, bool) or not isinstance(max_audit_records, int) or max_audit_records < 1:
            raise ValueError("max_audit_records must be a positive integer")
        if isinstance(busy_timeout_ms, bool) or not isinstance(busy_timeout_ms, int) or busy_timeout_ms < 0:
            raise ValueError("busy_timeout_ms must be a non-negative integer")
        self._database = os.fspath(database)
        if not isinstance(self._database, str) or self._database == ":memory:":
            raise ValueError("a durable SQLite file path is required")
        if os.path.realpath(self._database) != os.path.abspath(self._database):
            raise ValueError("database path must not contain symlinks")
        self._max_audit_records = max_audit_records
        self._identity_verifier = identity_verifier
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
                CREATE TABLE IF NOT EXISTS artifact_audit_log (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp_unix_ms INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    approval_token TEXT,
                    details_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE,
                    idempotency_key TEXT,
                    request_hash TEXT
                )
            """)
            columns = {row["name"] for row in db.execute(
                "PRAGMA table_info(artifact_audit_log)"
            ).fetchall()}
            if "idempotency_key" not in columns:
                db.execute("ALTER TABLE artifact_audit_log ADD COLUMN idempotency_key TEXT")
            if "request_hash" not in columns:
                db.execute("ALTER TABLE artifact_audit_log ADD COLUMN request_hash TEXT")
            db.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_idempotency_key "
                "ON artifact_audit_log(idempotency_key) WHERE idempotency_key IS NOT NULL"
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

    @classmethod
    def _validate_recorded_gc_plan(cls, token: str, raw: str) -> int:
        try:
            data = json.loads(raw)
            cutoff, candidates_data = data["cutoff_unix_ns"], data["candidates"]
            creator, total, count = data["github_actor_id"], data["total_bytes"], data["candidate_count"]
            if (isinstance(cutoff, bool) or not isinstance(cutoff, int)
                    or isinstance(creator, bool) or not isinstance(creator, int) or creator < 1
                    or isinstance(total, bool) or not isinstance(total, int)
                    or isinstance(count, bool) or not isinstance(count, int)
                    or not isinstance(candidates_data, list)):
                raise ValueError
            candidates = []
            for entry in candidates_data:
                if not isinstance(entry, dict) or set(entry) != {"sha256", "size_bytes", "mtime_unix_ns"}:
                    raise ValueError
                candidates.append(ArtifactObjectInfo(**entry))
            plan = ArtifactDeletionPlan(tuple(candidates), total, cutoff, token)
            if count != len(candidates):
                raise ValueError
            return creator
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("recorded GC plan metadata or approval token is invalid") from exc

    def record_gc_plan(
        self, plan: ArtifactDeletionPlan, *, claim: GitHubActorClaim,
        idempotency_key: str,
    ) -> str:
        if not isinstance(plan, ArtifactDeletionPlan):
            raise TypeError("plan must be an ArtifactDeletionPlan")
        actor = self._verified_actor(claim)
        details = {
            "candidate_count": len(plan.candidates),
            "total_bytes": plan.total_bytes,
            "cutoff_unix_ns": plan.cutoff_unix_ns,
            "candidates": [
                {"sha256": item.sha256, "size_bytes": item.size_bytes,
                 "mtime_unix_ns": item.mtime_unix_ns}
                for item in plan.candidates
            ],
            "github_actor_id": actor.github_id,
            "github_login": actor.login,
        }
        return self._append_audit_event(
            actor=f"github:{actor.github_id}:{actor.login}",
            action="gc_plan_created",
            approval_token=plan.approval_token, details=details,
            idempotency_key=idempotency_key,
        )

    def record_gc_approval(
        self, approval_token: str, *, claim: GitHubActorClaim, approved: bool,
        idempotency_key: str,
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
            require_distinct_approver=True, idempotency_key=idempotency_key,
        )

    def list_audit_events(self, *, limit: int = 100) -> list[dict[str, object]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("limit must be an integer from 1 to 1000")
        with closing(self._connect()) as db:
            db.execute("BEGIN")
            if not self._verify_audit_log_connection(db):
                db.rollback()
                raise ArtifactIntegrityError("artifact audit chain verification failed")
            rows = db.execute(
                "SELECT sequence, timestamp_unix_ms, actor, action, approval_token, "
                "details_json, previous_hash, event_hash, idempotency_key, request_hash "
                "FROM artifact_audit_log ORDER BY sequence DESC LIMIT ?", (limit,),
            ).fetchall()
            db.commit()
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
                "idempotency_key": row["idempotency_key"],
            }
            for row in reversed(rows)
        ]

    @classmethod
    def _verify_audit_log_connection(cls, db: sqlite3.Connection) -> bool:
        rows = db.execute(
            "SELECT sequence, timestamp_unix_ms, actor, action, approval_token, "
            "details_json, previous_hash, event_hash, idempotency_key, request_hash "
            "FROM artifact_audit_log ORDER BY sequence"
        ).fetchall()
        previous = "0" * 64
        for expected_sequence, row in enumerate(rows, start=1):
            if row["sequence"] != expected_sequence or row["previous_hash"] != previous:
                return False
            key, request_hash = row["idempotency_key"], row["request_hash"]
            if (key is None) != (request_hash is None):
                return False
            payload = {
                "sequence": row["sequence"],
                "timestamp_unix_ms": row["timestamp_unix_ms"],
                "actor": row["actor"],
                "action": row["action"],
                "approval_token": row["approval_token"],
                "details_json": row["details_json"],
                "previous_hash": row["previous_hash"],
            }
            if key is not None:
                payload["idempotency_key"] = key
                payload["request_hash"] = request_hash
            event_hash = row["event_hash"]
            if not isinstance(event_hash, str) or not hmac.compare_digest(
                cls._audit_hash(payload), event_hash,
            ):
                return False
            previous = event_hash
        return True

    def verify_audit_log(self) -> bool:
        with closing(self._connect()) as db:
            return self._verify_audit_log_connection(db)

    def _append_audit_event(
        self, *, actor: str, action: str, approval_token: str | None,
        details: dict[str, object], idempotency_key: str,
        require_distinct_approver: bool = False,
    ) -> str:
        if (not isinstance(idempotency_key, str)
                or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", idempotency_key)):
            raise ValueError("idempotency_key must be 1..128 safe ASCII characters")
        details_json = json.dumps(details, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        request_hash = self._audit_hash({
            "actor": actor, "action": action, "approval_token": approval_token,
            "details_json": details_json,
        })
        if len(details_json.encode("utf-8")) > 64 * 1024:
            raise ValueError("audit event details exceed 64 KiB")
        with self._lock, closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            if not self._verify_audit_log_connection(db):
                db.rollback()
                raise ArtifactIntegrityError("artifact audit chain verification failed")
            prior_request = db.execute(
                "SELECT request_hash, event_hash FROM artifact_audit_log "
                "WHERE idempotency_key=?", (idempotency_key,),
            ).fetchone()
            if prior_request is not None:
                if prior_request["request_hash"] is None or not hmac.compare_digest(
                    prior_request["request_hash"], request_hash,
                ):
                    db.rollback()
                    raise ValueError("idempotency key was already used for a different request")
                event_hash = prior_request["event_hash"]
                db.commit()
                return event_hash
            if action == "gc_plan_created":
                duplicate_plan = db.execute(
                    "SELECT 1 FROM artifact_audit_log "
                    "WHERE action='gc_plan_created' AND approval_token=? LIMIT 1",
                    (approval_token,),
                ).fetchone()
                if duplicate_plan is not None:
                    db.rollback()
                    raise ValueError("GC plan token has already been recorded")
            if action in ("gc_plan_approved", "gc_plan_rejected"):
                prior_decision = db.execute(
                    "SELECT 1 FROM artifact_audit_log WHERE "
                    "action IN ('gc_plan_approved', 'gc_plan_rejected') "
                    "AND approval_token=? LIMIT 1",
                    (approval_token,),
                ).fetchone()
                if prior_decision is not None:
                    db.rollback()
                    raise ValueError("GC plan already has a recorded decision")
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
                creator_id = self._validate_recorded_gc_plan(approval_token, plan_row["details_json"])
                approver_id = details.get("github_actor_id")
                if creator_id == approver_id:
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
                "idempotency_key": idempotency_key,
                "request_hash": request_hash,
            }
            event_hash = self._audit_hash(payload)
            db.execute(
                "INSERT INTO artifact_audit_log "
                "(sequence, timestamp_unix_ms, actor, action, approval_token, details_json, "
                "previous_hash, event_hash, idempotency_key, request_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (sequence, timestamp, actor, action, approval_token, details_json,
                 previous_hash, event_hash, idempotency_key, request_hash),
            )
            db.commit()
        return event_hash
