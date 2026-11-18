"""SQLite single-host reference adapter for the audit repository port."""
from __future__ import annotations

import copy
import json
import os
import sqlite3
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ...application.errors import AuditServiceError
from ...domain.audit import AuthorizationResult, VerifiedApprovalEvidence
from ...domain.audit_hashing import ZERO_HASH as _ZERO_HASH, event_hash as _event_hash
from ...domain.identity import VerifiedGitHubActor

_MAX_EVENTS = 10_000


class SQLiteAuditRepository:
    """Durable single-host SQLite adapter with cross-process write serialization."""

    mode = "sqlite-file-test-only"

    def __init__(
        self, database: str | Path, *, max_events: int = _MAX_EVENTS,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        if isinstance(max_events, bool) or not isinstance(max_events, int) or max_events < 1:
            raise ValueError("max_events must be a positive integer")
        if isinstance(busy_timeout_ms, bool) or not isinstance(busy_timeout_ms, int) or busy_timeout_ms < 0:
            raise ValueError("busy_timeout_ms must be a non-negative integer")
        raw = str(database)
        if not raw or raw == ":memory:" or not Path(raw).is_absolute():
            raise ValueError("an absolute SQLite database file path is required")
        self._database = raw
        self._max_events = max_events
        self._busy_timeout_ms = busy_timeout_ms
        Path(raw).parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(raw, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            info = os.lstat(raw)
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
                raise ValueError("SQLite database must be a regular file with owner-only permissions")
        else:
            os.close(fd)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(
            self._database, timeout=self._busy_timeout_ms / 1000,
            isolation_level=None,
        )
        db.row_factory = sqlite3.Row
        db.execute(f"PRAGMA busy_timeout={self._busy_timeout_ms}")
        db.execute("PRAGMA foreign_keys=ON")
        return db

    def _initialize(self) -> None:
        db = self._connect()
        try:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS remote_audit_events (
                    repository_id INTEGER NOT NULL,
                    sequence INTEGER NOT NULL,
                    event_id TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    plan_token TEXT,
                    PRIMARY KEY(repository_id, sequence),
                    UNIQUE(repository_id, event_id),
                    UNIQUE(repository_id, idempotency_key)
                );
                CREATE TABLE IF NOT EXISTS remote_audit_heads (
                    repository_id INTEGER PRIMARY KEY,
                    sequence INTEGER NOT NULL,
                    event_hash TEXT NOT NULL,
                    FOREIGN KEY(repository_id, sequence)
                        REFERENCES remote_audit_events(repository_id, sequence)
                );
                CREATE TABLE IF NOT EXISTS remote_audit_plans (
                    repository_id INTEGER NOT NULL,
                    plan_token TEXT NOT NULL,
                    creator_actor_id INTEGER NOT NULL,
                    event_sequence INTEGER NOT NULL,
                    PRIMARY KEY(repository_id, plan_token),
                    FOREIGN KEY(repository_id, event_sequence)
                        REFERENCES remote_audit_events(repository_id, sequence)
                );
                CREATE TABLE IF NOT EXISTS remote_audit_decisions (
                    repository_id INTEGER NOT NULL,
                    plan_token TEXT NOT NULL,
                    event_sequence INTEGER NOT NULL,
                    PRIMARY KEY(repository_id, plan_token),
                    FOREIGN KEY(repository_id, plan_token)
                        REFERENCES remote_audit_plans(repository_id, plan_token),
                    FOREIGN KEY(repository_id, event_sequence)
                        REFERENCES remote_audit_events(repository_id, sequence)
                );
                CREATE TABLE IF NOT EXISTS remote_audit_consumed_evidence (
                    repository_id INTEGER NOT NULL,
                    issuer TEXT NOT NULL,
                    evidence_id TEXT NOT NULL,
                    evidence_digest TEXT NOT NULL,
                    plan_token TEXT NOT NULL,
                    event_sequence INTEGER NOT NULL,
                    PRIMARY KEY(repository_id, issuer, evidence_id),
                    FOREIGN KEY(repository_id, event_sequence)
                        REFERENCES remote_audit_events(repository_id, sequence)
                );
                CREATE INDEX IF NOT EXISTS idx_remote_audit_plan_token
                    ON remote_audit_events(repository_id, plan_token, sequence);
            """)
            db.execute(
                "INSERT OR IGNORE INTO remote_audit_heads(repository_id, sequence, event_hash) "
                "SELECT e.repository_id, e.sequence, e.event_hash FROM remote_audit_events e "
                "JOIN (SELECT repository_id, MAX(sequence) AS sequence FROM remote_audit_events GROUP BY repository_id) latest "
                "ON latest.repository_id=e.repository_id AND latest.sequence=e.sequence"
            )
        finally:
            db.close()

    @staticmethod
    def _decode_event(row: sqlite3.Row) -> dict[str, object]:
        value = json.loads(row["event_json"])
        if not isinstance(value, dict):
            raise AuditServiceError(422, "integrity_violation", "stored event is malformed")
        return value

    def _verify_connection(self, db: sqlite3.Connection, repository_id: int) -> bool:
        rows = db.execute(
            "SELECT sequence, event_json, event_hash FROM remote_audit_events "
            "WHERE repository_id=? ORDER BY sequence",
            (repository_id,),
        ).fetchall()
        previous = _ZERO_HASH
        try:
            for expected, row in enumerate(rows, start=1):
                event = self._decode_event(row)
                if (
                    row["sequence"] != expected
                    or event.get("sequence") != expected
                    or event.get("previous_hash") != previous
                    or event.get("event_hash") != row["event_hash"]
                    or row["event_hash"] != _event_hash(event)
                ):
                    return False
                previous = str(row["event_hash"])
        except (ValueError, TypeError, RecursionError, AuditServiceError):
            return False
        head = db.execute(
            "SELECT sequence, event_hash FROM remote_audit_heads WHERE repository_id=?",
            (repository_id,),
        ).fetchone()
        if not rows:
            return head is None
        return bool(
            head is not None
            and head["sequence"] == len(rows)
            and head["event_hash"] == previous
        )

    def append(
        self, *, repository_id: int, idempotency_key: str, request_hash: str,
        event_type: str, actor: VerifiedGitHubActor, details: dict[str, object],
        approval_token: str | None,
        approval_evidence: VerifiedApprovalEvidence | None = None,
        authorization: AuthorizationResult | None = None,
    ) -> tuple[dict[str, object], bool]:
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            if not self._verify_connection(db, repository_id):
                raise AuditServiceError(422, "integrity_violation", "audit chain verification failed")
            prior = db.execute(
                "SELECT request_hash, event_json FROM remote_audit_events "
                "WHERE repository_id=? AND idempotency_key=?",
                (repository_id, idempotency_key),
            ).fetchone()
            if prior is not None:
                if prior["request_hash"] != request_hash:
                    raise AuditServiceError(409, "idempotency_conflict", "idempotency key was reused")
                event = json.loads(prior["event_json"])
                db.commit()
                return event, True
            count = db.execute(
                "SELECT COUNT(*) FROM remote_audit_events WHERE repository_id=?",
                (repository_id,),
            ).fetchone()[0]
            if count >= self._max_events:
                raise AuditServiceError(503, "unavailable", "audit repository capacity reached", retryable=True)

            token = str(approval_token)
            if event_type == "gc_plan_created":
                existing = db.execute(
                    "SELECT 1 FROM remote_audit_plans WHERE repository_id=? AND plan_token=?",
                    (repository_id, token),
                ).fetchone()
                if existing:
                    raise AuditServiceError(409, "decision_conflict", "plan token already exists")
            else:
                plan = db.execute(
                    "SELECT creator_actor_id FROM remote_audit_plans WHERE repository_id=? AND plan_token=?",
                    (repository_id, token),
                ).fetchone()
                if plan is None:
                    raise AuditServiceError(404, "not_found", "GC plan was not found")
                if plan["creator_actor_id"] == actor.github_id:
                    raise AuditServiceError(403, "forbidden", "creator cannot approve own plan")
                decision = db.execute(
                    "SELECT 1 FROM remote_audit_decisions WHERE repository_id=? AND plan_token=?",
                    (repository_id, token),
                ).fetchone()
                if decision:
                    raise AuditServiceError(409, "decision_conflict", "plan already has a terminal decision")
                if approval_evidence is None or authorization is None or not authorization.allowed:
                    raise AuditServiceError(403, "approval_evidence_required", "verified approval evidence is required")
                consumed = db.execute(
                    "SELECT 1 FROM remote_audit_consumed_evidence WHERE repository_id=? AND issuer=? AND evidence_id=?",
                    (repository_id, approval_evidence.issuer, approval_evidence.evidence_id),
                ).fetchone()
                if consumed:
                    raise AuditServiceError(409, "approval_evidence_replayed", "approval evidence was already consumed")

            last = db.execute(
                "SELECT sequence, event_hash FROM remote_audit_events WHERE repository_id=? ORDER BY sequence DESC LIMIT 1",
                (repository_id,),
            ).fetchone()
            sequence = int(last["sequence"]) + 1 if last else 1
            previous_hash = str(last["event_hash"]) if last else _ZERO_HASH
            timestamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            event_details = copy.deepcopy(details)
            if event_type != "gc_plan_created":
                event_details = {
                    **event_details,
                    "approval_evidence": {
                        "issuer": approval_evidence.issuer,
                        "evidence_id": approval_evidence.evidence_id,
                        "evidence_digest": approval_evidence.evidence_digest,
                    },
                    "authorization": {
                        "decision_id": authorization.decision_id,
                        "policy_version": authorization.policy_version,
                    },
                }
            event: dict[str, object] = {
                "sequence": sequence, "event_id": str(uuid.uuid4()),
                "event_type": event_type, "actor_id": actor.github_id,
                "actor_login": actor.login, "timestamp": timestamp,
                "details": event_details, "idempotency_key": idempotency_key,
                "request_hash": request_hash, "previous_hash": previous_hash,
                "event_hash": "",
            }
            event["event_hash"] = _event_hash(event)
            event_json = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
            db.execute(
                "INSERT INTO remote_audit_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (repository_id, sequence, event["event_id"], event_json, event["event_hash"],
                 idempotency_key, request_hash, event_type, token),
            )
            db.execute(
                "INSERT INTO remote_audit_heads(repository_id, sequence, event_hash) VALUES (?, ?, ?) "
                "ON CONFLICT(repository_id) DO UPDATE SET sequence=excluded.sequence, event_hash=excluded.event_hash",
                (repository_id, sequence, event["event_hash"]),
            )
            if event_type == "gc_plan_created":
                db.execute(
                    "INSERT INTO remote_audit_plans VALUES (?, ?, ?, ?)",
                    (repository_id, token, actor.github_id, sequence),
                )
            else:
                db.execute(
                    "INSERT INTO remote_audit_decisions VALUES (?, ?, ?)",
                    (repository_id, token, sequence),
                )
                db.execute(
                    "INSERT INTO remote_audit_consumed_evidence VALUES (?, ?, ?, ?, ?, ?)",
                    (repository_id, approval_evidence.issuer, approval_evidence.evidence_id,
                     approval_evidence.evidence_digest, token, sequence),
                )
            db.commit()
            return event, False
        except sqlite3.IntegrityError as exc:
            db.rollback()
            raise AuditServiceError(409, "transaction_conflict", "audit uniqueness constraint rejected the write") from exc
        except sqlite3.DatabaseError as exc:
            db.rollback()
            raise AuditServiceError(503, "repository_unavailable", "audit repository transaction failed", retryable=True) from exc
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def lookup(self, repository_id: int, idempotency_key: str) -> dict[str, object] | None:
        db = self._connect()
        try:
            if not self._verify_connection(db, repository_id):
                raise AuditServiceError(422, "integrity_violation", "audit chain verification failed")
            row = db.execute(
                "SELECT event_json FROM remote_audit_events WHERE repository_id=? AND idempotency_key=?",
                (repository_id, idempotency_key),
            ).fetchone()
            return self._decode_event(row) if row else None
        except sqlite3.DatabaseError as exc:
            raise AuditServiceError(503, "repository_unavailable", "audit repository read failed", retryable=True) from exc
        finally:
            db.close()

    def list_events(self, repository_id: int, offset: int, limit: int) -> list[dict[str, object]]:
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise ValueError("offset must be a non-negative integer")
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        db = self._connect()
        try:
            if not self._verify_connection(db, repository_id):
                raise AuditServiceError(422, "integrity_violation", "audit chain verification failed")
            rows = db.execute(
                "SELECT event_json FROM remote_audit_events WHERE repository_id=? "
                "ORDER BY sequence LIMIT ? OFFSET ?",
                (repository_id, limit, offset),
            ).fetchall()
            return [self._decode_event(row) for row in rows]
        except sqlite3.DatabaseError as exc:
            raise AuditServiceError(503, "repository_unavailable", "audit repository read failed", retryable=True) from exc
        finally:
            db.close()

    def verify(self, repository_id: int) -> bool:
        db = self._connect()
        try:
            return self._verify_connection(db, repository_id)
        except sqlite3.DatabaseError as exc:
            raise AuditServiceError(503, "repository_unavailable", "audit repository verification failed", retryable=True) from exc
        finally:
            db.close()
