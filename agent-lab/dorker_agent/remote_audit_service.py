"""Test reference repositories for Remote Audit Service Contract v1.

SQLite durability is single-host only; neither adapter is a production deployment.
"""
from __future__ import annotations

import base64
from collections import OrderedDict
import copy
import hashlib
import json
import os
import re
import sqlite3
import stat
import threading
import time
import uuid
from math import ceil
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Protocol
from urllib.parse import parse_qs, unquote, urlsplit

from .artifacts import GitHubActorClaim, VerifiedGitHubActor
from .github_oidc import OIDCVerificationError

_MAX_BODY_BYTES = 64 * 1024
_MAX_EVENTS = 10_000
_KEY = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ZERO_HASH = "0" * 64


class AuditServiceError(RuntimeError):
    def __init__(self, status: int, code: str, message: str, *, retryable: bool = False):
        super().__init__(message)
        self.status = status
        self.code = code
        self.retryable = retryable


class IdentityVerifier(Protocol):
    def verify(self, claim: GitHubActorClaim) -> VerifiedGitHubActor: ...


@dataclass(frozen=True)
class AuthorizationResult:
    allowed: bool
    decision_id: str
    policy_version: str


@dataclass(frozen=True)
class VerifiedApprovalEvidence:
    issuer: str
    evidence_id: str
    repository_id: int
    plan_token: str
    decision: str
    reviewer_actor_id: int
    evidence_digest: str


class ApprovalEvidenceVerifier(Protocol):
    def verify(self, *, envelope: dict[str, object], repository_id: int, plan_token: str, decision: str, actor: VerifiedGitHubActor) -> VerifiedApprovalEvidence: ...


class DefaultDenyApprovalEvidenceVerifier:
    def verify(self, **kwargs) -> VerifiedApprovalEvidence:
        raise AuditServiceError(403, "approval_evidence_required", "independent approval evidence is not configured")


class AuthorizationPolicy(Protocol):
    def authorize(
        self, *, actor: VerifiedGitHubActor, operation: str,
        repository_id: int, plan_token: str | None,
    ) -> AuthorizationResult: ...


class DefaultDenyAuthorizationPolicy:
    """Safe default until an explicitly reviewed policy is configured."""

    def authorize(
        self, *, actor: VerifiedGitHubActor, operation: str,
        repository_id: int, plan_token: str | None,
    ) -> AuthorizationResult:
        return AuthorizationResult(
            allowed=False,
            decision_id="policy-unconfigured",
            policy_version="default-deny-v1",
        )


class AuditRepository(Protocol):
    def append(
        self, *, repository_id: int, idempotency_key: str, request_hash: str,
        event_type: str, actor: VerifiedGitHubActor, details: dict[str, object],
        approval_token: str | None,
        approval_evidence: VerifiedApprovalEvidence | None = None,
        authorization: AuthorizationResult | None = None,
    ) -> tuple[dict[str, object], bool]: ...

    def lookup(self, repository_id: int, idempotency_key: str) -> dict[str, object] | None: ...
    def list_events(self, repository_id: int, offset: int, limit: int) -> list[dict[str, object]]: ...
    def verify(self, repository_id: int) -> bool: ...


def _strict_object(raw: bytes) -> dict[str, object]:
    if len(raw) > _MAX_BODY_BYTES:
        raise AuditServiceError(413, "invalid_request", "request body exceeds 64 KiB")

    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise AuditServiceError(400, "invalid_request", "request JSON is invalid") from exc
    if not isinstance(value, dict):
        raise AuditServiceError(400, "invalid_request", "request body must be an object")
    return value


def _canonical_hash(value: dict[str, object]) -> str:
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AuditServiceError(400, "invalid_request", "request is not canonical JSON") from exc
    return hashlib.sha256(encoded).hexdigest()


def _event_hash(event: dict[str, object]) -> str:
    payload = {key: value for key, value in event.items() if key != "event_hash"}
    return _canonical_hash(payload)


def _claim_from_bearer(token: str) -> GitHubActorClaim:
    if not token or len(token) > 16_384:
        raise AuditServiceError(401, "unauthenticated", "bearer token is missing or oversized")
    parts = token.split(".")
    if len(parts) != 3:
        raise AuditServiceError(401, "unauthenticated", "bearer token is malformed")
    try:
        raw = base64.b64decode(
            parts[1] + "=" * (-len(parts[1]) % 4), altchars=b"-_", validate=True,
        )
        payload = _strict_object(raw)
    except (ValueError, AuditServiceError) as exc:
        raise AuditServiceError(401, "unauthenticated", "bearer token claims are malformed") from exc
    actor_id = payload.get("actor_id")
    actor_login = payload.get("actor")
    if isinstance(actor_id, bool) or not (
        isinstance(actor_id, int) or isinstance(actor_id, str) and actor_id.isdecimal()
    ):
        raise AuditServiceError(401, "unauthenticated", "bearer token actor ID is invalid")
    try:
        numeric_id = int(actor_id)
    except (TypeError, ValueError) as exc:
        raise AuditServiceError(401, "unauthenticated", "bearer token actor ID is invalid") from exc
    if numeric_id < 1 or not isinstance(actor_login, str) or not actor_login.strip() or len(actor_login) > 39:
        raise AuditServiceError(401, "unauthenticated", "bearer token actor is invalid")
    return GitHubActorClaim(numeric_id, actor_login, token)


def _validate_plan(value: object) -> tuple[str, dict[str, object]]:
    if not isinstance(value, dict) or set(value) != {
        "approval_token", "cutoff_unix_ns", "total_bytes", "candidates",
    }:
        raise AuditServiceError(400, "invalid_request", "plan fields do not match contract")
    token = value["approval_token"]
    cutoff = value["cutoff_unix_ns"]
    total = value["total_bytes"]
    candidates = value["candidates"]
    if not isinstance(token, str) or not _DIGEST.fullmatch(token):
        raise AuditServiceError(400, "invalid_request", "approval_token is invalid")
    if isinstance(cutoff, bool) or not isinstance(cutoff, int) or cutoff < 0:
        raise AuditServiceError(400, "invalid_request", "cutoff_unix_ns is invalid")
    if isinstance(total, bool) or not isinstance(total, int) or total < 0:
        raise AuditServiceError(400, "invalid_request", "total_bytes is invalid")
    if not isinstance(candidates, list) or len(candidates) > 100:
        raise AuditServiceError(400, "invalid_request", "candidates must contain at most 100 items")
    normalized = []
    seen = set()
    for item in candidates:
        if not isinstance(item, dict) or set(item) != {"sha256", "size_bytes", "mtime_unix_ns"}:
            raise AuditServiceError(400, "invalid_request", "candidate fields are invalid")
        digest, size, mtime = item["sha256"], item["size_bytes"], item["mtime_unix_ns"]
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest) or digest in seen:
            raise AuditServiceError(400, "invalid_request", "candidate digest is invalid or duplicated")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise AuditServiceError(400, "invalid_request", "candidate size_bytes is invalid")
        if isinstance(mtime, bool) or not isinstance(mtime, int) or mtime < 0 or mtime > cutoff:
            raise AuditServiceError(400, "invalid_request", "candidate mtime_unix_ns is invalid")
        seen.add(digest)
        normalized.append({"sha256": digest, "size_bytes": size, "mtime_unix_ns": mtime})
    if normalized != sorted(normalized, key=lambda row: (row["mtime_unix_ns"], row["sha256"])):
        raise AuditServiceError(400, "invalid_request", "candidates are not canonically ordered")
    if sum(row["size_bytes"] for row in normalized) != total:
        raise AuditServiceError(400, "invalid_request", "total_bytes does not match candidates")
    plan_payload = {"cutoff_unix_ns": cutoff, "candidates": normalized}
    if not hashlib.sha256(json.dumps(
        plan_payload, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest() == token:
        raise AuditServiceError(422, "integrity_violation", "approval token does not match plan")
    return token, {
        "approval_token": token, "cutoff_unix_ns": cutoff,
        "total_bytes": total, "candidates": normalized,
    }


class InMemoryAuditRepository:
    """Lock-serialized repository double; state is lost when the process exits."""

    mode = "in-memory-test-only"

    def __init__(self, *, max_events: int = _MAX_EVENTS) -> None:
        if isinstance(max_events, bool) or not isinstance(max_events, int) or max_events < 1:
            raise ValueError("max_events must be a positive integer")
        self._max_events = max_events
        self._lock = threading.RLock()
        self._events: dict[int, list[dict[str, object]]] = {}
        self._idempotency: dict[tuple[int, str], dict[str, object]] = {}
        self._plans: dict[tuple[int, str], dict[str, object]] = {}
        self._decisions: set[tuple[int, str]] = set()
        self._consumed_evidence: set[tuple[int, str, str]] = set()

    def append(
        self, *, repository_id: int, idempotency_key: str, request_hash: str,
        event_type: str, actor: VerifiedGitHubActor, details: dict[str, object],
        approval_token: str | None,
        approval_evidence: VerifiedApprovalEvidence | None = None,
        authorization: AuthorizationResult | None = None,
    ) -> tuple[dict[str, object], bool]:
        with self._lock:
            if not self._verify_locked(repository_id):
                raise AuditServiceError(422, "integrity_violation", "audit chain verification failed")
            key = (repository_id, idempotency_key)
            prior = self._idempotency.get(key)
            if prior is not None:
                if prior["request_hash"] != request_hash:
                    raise AuditServiceError(409, "idempotency_conflict", "idempotency key was reused")
                return copy.deepcopy(prior["event"]), True
            events = self._events.setdefault(repository_id, [])
            if len(events) >= self._max_events:
                raise AuditServiceError(503, "unavailable", "audit repository capacity reached", retryable=True)
            if event_type == "gc_plan_created":
                plan_key = (repository_id, str(approval_token))
                if plan_key in self._plans:
                    raise AuditServiceError(409, "decision_conflict", "plan token already exists")
            else:
                plan_key = (repository_id, str(approval_token))
                plan = self._plans.get(plan_key)
                if plan is None:
                    raise AuditServiceError(404, "not_found", "GC plan was not found")
                if plan["actor_id"] == actor.github_id:
                    raise AuditServiceError(403, "forbidden", "creator cannot approve own plan")
                if plan_key in self._decisions:
                    raise AuditServiceError(409, "decision_conflict", "plan already has a terminal decision")
                if approval_evidence is None or authorization is None or not authorization.allowed:
                    raise AuditServiceError(403, "approval_evidence_required", "verified approval evidence is required")
                evidence_key = (repository_id, approval_evidence.issuer, approval_evidence.evidence_id)
                if evidence_key in self._consumed_evidence:
                    raise AuditServiceError(409, "approval_evidence_replayed", "approval evidence was already consumed")

            sequence = len(events) + 1
            previous_hash = events[-1]["event_hash"] if events else _ZERO_HASH
            timestamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            event: dict[str, object] = {
                "sequence": sequence,
                "event_id": str(uuid.uuid4()),
                "event_type": event_type,
                "actor_id": actor.github_id,
                "actor_login": actor.login,
                "timestamp": timestamp,
                "details": copy.deepcopy(details),
                "idempotency_key": idempotency_key,
                "request_hash": request_hash,
                "previous_hash": previous_hash,
                "event_hash": "",
            }
            if event_type != "gc_plan_created":
                details = {**details, "approval_evidence": {
                    "issuer": approval_evidence.issuer,
                    "evidence_id": approval_evidence.evidence_id,
                    "evidence_digest": approval_evidence.evidence_digest,
                }, "authorization": {
                    "decision_id": authorization.decision_id,
                    "policy_version": authorization.policy_version,
                }}
                event["details"] = copy.deepcopy(details)
            event["event_hash"] = _event_hash(event)
            events.append(event)
            result = {
                "event": copy.deepcopy(event),
                "request_hash": request_hash,
            }
            self._idempotency[key] = result
            if event_type == "gc_plan_created":
                self._plans[plan_key] = {"actor_id": actor.github_id, "event": copy.deepcopy(event)}
            else:
                self._decisions.add(plan_key)
                self._consumed_evidence.add((repository_id, approval_evidence.issuer, approval_evidence.evidence_id))
            return copy.deepcopy(event), False

    def lookup(self, repository_id: int, idempotency_key: str) -> dict[str, object] | None:
        with self._lock:
            if not self._verify_locked(repository_id):
                raise AuditServiceError(422, "integrity_violation", "audit chain verification failed")
            value = self._idempotency.get((repository_id, idempotency_key))
            return copy.deepcopy(value["event"]) if value else None

    def list_events(self, repository_id: int, offset: int, limit: int) -> list[dict[str, object]]:
        with self._lock:
            if not self._verify_locked(repository_id):
                raise AuditServiceError(422, "integrity_violation", "audit chain verification failed")
            return copy.deepcopy(self._events.get(repository_id, [])[offset:offset + limit])

    def _verify_locked(self, repository_id: int) -> bool:
        previous = _ZERO_HASH
        for expected, event in enumerate(self._events.get(repository_id, []), start=1):
            if event.get("sequence") != expected or event.get("previous_hash") != previous:
                return False
            if event.get("event_hash") != _event_hash(event):
                return False
            previous = str(event["event_hash"])
        return True

    def verify(self, repository_id: int) -> bool:
        with self._lock:
            return self._verify_locked(repository_id)



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


class RequestRateLimiter:
    """Bounded process-local token buckets for a single-worker WSGI deployment."""

    def __init__(
        self, *, global_rate_per_minute: float = 30, global_burst: int = 5,
        per_client_rate_per_minute: float = 10, per_client_burst: int = 3,
        max_clients: int = 2048, clock: Callable[[], float] = time.monotonic,
    ) -> None:
        values = (global_rate_per_minute, per_client_rate_per_minute)
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) or v <= 0 for v in values):
            raise ValueError("request rates must be positive numbers")
        bursts = (global_burst, per_client_burst, max_clients)
        if any(isinstance(v, bool) or not isinstance(v, int) or v < 1 for v in bursts):
            raise ValueError("burst and max_clients values must be positive integers")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._global_rate = float(global_rate_per_minute) / 60.0
        self._global_capacity = float(global_burst)
        self._global_tokens = float(global_burst)
        self._global_updated = clock()
        self._client_rate = float(per_client_rate_per_minute) / 60.0
        self._client_capacity = float(per_client_burst)
        self._max_clients = max_clients
        self._clock = clock
        self._clients: OrderedDict[str, tuple[float, float]] = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def _refill(tokens: float, updated: float, now: float, rate: float, capacity: float) -> tuple[float, float]:
        return min(capacity, tokens + max(0.0, now - updated) * rate), now

    def allow(self, client_key: str) -> tuple[bool, int]:
        if not isinstance(client_key, str) or not client_key or len(client_key) > 128:
            client_key = "unknown"
        now = self._clock()
        with self._lock:
            global_tokens, global_updated = self._refill(
                self._global_tokens, self._global_updated, now,
                self._global_rate, self._global_capacity,
            )
            client = self._clients.get(client_key)
            if client is None:
                if len(self._clients) >= self._max_clients:
                    self._clients.popitem(last=False)
                client_tokens, client_updated = self._client_capacity, now
            else:
                client_tokens, client_updated = self._refill(
                    client[0], client[1], now, self._client_rate, self._client_capacity,
                )
                self._clients.move_to_end(client_key)

            global_wait = max(0.0, (1.0 - global_tokens) / self._global_rate)
            client_wait = max(0.0, (1.0 - client_tokens) / self._client_rate)
            self._global_tokens, self._global_updated = global_tokens, global_updated
            self._clients[client_key] = (client_tokens, client_updated)
            if global_wait > 0.0 or client_wait > 0.0:
                return False, max(1, ceil(max(global_wait, client_wait)))

            self._global_tokens -= 1.0
            self._clients[client_key] = (client_tokens - 1.0, client_updated)
            return True, 0


class RemoteAuditService:
    """Small WSGI-compatible HTTP service core for contract tests only."""

    def __init__(
        self, *, repository_id: int, identity_verifier: IdentityVerifier,
        repository: AuditRepository,
        authorization_policy: AuthorizationPolicy | None = None,
        approval_evidence_verifier: ApprovalEvidenceVerifier | None = None,
        request_rate_limiter: RequestRateLimiter | None = None,
        request_timeout_seconds: float = 8.0,
    ) -> None:
        if isinstance(repository_id, bool) or not isinstance(repository_id, int) or repository_id < 1:
            raise ValueError("repository_id must be a positive integer")
        if not callable(getattr(identity_verifier, "verify", None)):
            raise TypeError("identity_verifier must expose verify()")
        for method in ("append", "lookup", "list_events", "verify"):
            if not callable(getattr(repository, method, None)):
                raise TypeError(f"repository must expose {method}()")
        self._repository_id = repository_id
        if authorization_policy is not None and not callable(getattr(authorization_policy, "authorize", None)):
            raise TypeError("authorization_policy must expose authorize()")
        self._identity_verifier = identity_verifier
        self._repository = repository
        self._authorization_policy = authorization_policy or DefaultDenyAuthorizationPolicy()
        if approval_evidence_verifier is not None and not callable(getattr(approval_evidence_verifier, "verify", None)):
            raise TypeError("approval_evidence_verifier must expose verify()")
        self._approval_evidence_verifier = approval_evidence_verifier or DefaultDenyApprovalEvidenceVerifier()
        if request_rate_limiter is not None and not callable(getattr(request_rate_limiter, "allow", None)):
            raise TypeError("request_rate_limiter must expose allow()")
        if isinstance(request_timeout_seconds, bool) or not isinstance(request_timeout_seconds, (int, float)) or not 0 < request_timeout_seconds <= 30:
            raise ValueError("request_timeout_seconds must be in (0, 30]")
        self._request_rate_limiter = request_rate_limiter or RequestRateLimiter()
        self._request_timeout_seconds = float(request_timeout_seconds)
        self._request_slots = threading.BoundedSemaphore(1)

    def handle(
        self, method: str, target: str, headers: dict[str, str] | None = None,
        body: bytes = b"",
    ) -> tuple[int, dict[str, str], bytes]:
        request_id = str(uuid.uuid4())
        try:
            if not isinstance(method, str) or method not in {"GET", "POST"}:
                raise AuditServiceError(400, "invalid_request", "HTTP method is invalid")
            if not isinstance(target, str) or not target or len(target) > 4096:
                raise AuditServiceError(400, "invalid_request", "request target is invalid or oversized")
            if not isinstance(body, bytes):
                raise AuditServiceError(400, "invalid_request", "request body must be bytes")
            if headers is not None and not isinstance(headers, dict):
                raise AuditServiceError(400, "invalid_request", "request headers are invalid")
            if headers is not None and any(not isinstance(k, str) or not isinstance(v, str) for k, v in headers.items()):
                raise AuditServiceError(400, "invalid_request", "request headers are invalid")
            headers = {key.lower(): value for key, value in (headers or {}).items()}
            if len(body) > _MAX_BODY_BYTES:
                raise AuditServiceError(413, "invalid_request", "request body exceeds 64 KiB")
            parsed = urlsplit(target)
            if parsed.fragment:
                raise AuditServiceError(400, "invalid_request", "URL fragment is not allowed")
            path = parsed.path
            if method == "GET" and path == "/v1/audit/health":
                actor = self._authenticate(headers)
                self._authorize(actor, "read_audit")
                ready = self._repository.verify(self._repository_id)
                return self._json(200, {
                    "ready": ready, "mode": getattr(self._repository, "mode", "custom-test-only"),
                    "request_id": request_id,
                })
            actor = self._authenticate(headers)
            if method == "POST" and path == "/v1/audit/plans":
                payload = _strict_object(body)
                if set(payload) != {"idempotency_key", "plan"}:
                    raise AuditServiceError(400, "invalid_request", "plan request fields are invalid")
                key = self._validate_key(payload["idempotency_key"])
                token, plan = _validate_plan(payload["plan"])
                operation = {
                    "api_version": "v1", "operation": "record_plan",
                    "repository_id": self._repository_id, "actor_id": actor.github_id,
                    "payload": {"idempotency_key": key, "plan": plan},
                }
                request_hash = _canonical_hash(operation)
                self._authorize(actor, "create_plan", token)
                event, replayed = self._repository.append(
                    repository_id=self._repository_id, idempotency_key=key,
                    request_hash=request_hash, event_type="gc_plan_created",
                    actor=actor, details=plan, approval_token=token,
                )
                return self._json(200, self._success(event, key, replayed, request_id))
            if method == "POST" and path == "/v1/audit/decisions":
                payload = _strict_object(body)
                if set(payload) != {"idempotency_key", "approval_token", "decision", "evidence"}:
                    raise AuditServiceError(400, "invalid_request", "decision request fields are invalid")
                key = self._validate_key(payload["idempotency_key"])
                token, decision = payload["approval_token"], payload["decision"]
                if not isinstance(token, str) or not _DIGEST.fullmatch(token):
                    raise AuditServiceError(400, "invalid_request", "approval_token is invalid")
                if decision not in ("approve", "reject"):
                    raise AuditServiceError(400, "invalid_request", "decision must be approve or reject")
                evidence_envelope = payload["evidence"]
                if not isinstance(evidence_envelope, dict):
                    raise AuditServiceError(400, "invalid_request", "evidence envelope must be an object")
                operation = {
                    "api_version": "v1", "operation": "record_decision",
                    "repository_id": self._repository_id, "actor_id": actor.github_id,
                    "payload": {"idempotency_key": key, "approval_token": token, "decision": decision, "evidence": evidence_envelope},
                }
                request_hash = _canonical_hash(operation)
                authorization = self._authorize(actor, decision, token)
                try:
                    verified_evidence = self._approval_evidence_verifier.verify(
                        envelope=evidence_envelope, repository_id=self._repository_id,
                        plan_token=token, decision=decision, actor=actor,
                    )
                except AuditServiceError:
                    raise
                except Exception as exc:
                    raise AuditServiceError(503, "approval_evidence_unavailable", "approval evidence could not be verified", retryable=True) from exc
                if (
                    not isinstance(verified_evidence, VerifiedApprovalEvidence)
                    or verified_evidence.repository_id != self._repository_id
                    or verified_evidence.plan_token != token
                    or verified_evidence.decision != decision
                    or verified_evidence.reviewer_actor_id != actor.github_id
                    or not verified_evidence.issuer or not verified_evidence.evidence_id
                    or not _DIGEST.fullmatch(verified_evidence.evidence_digest)
                ):
                    raise AuditServiceError(403, "invalid_approval_evidence", "verified evidence does not match this decision")
                event, replayed = self._repository.append(
                    repository_id=self._repository_id, idempotency_key=key,
                    request_hash=request_hash,
                    event_type="gc_plan_approved" if decision == "approve" else "gc_plan_rejected",
                    actor=actor, details={"approval_token": token, "decision": decision},
                    approval_token=token, approval_evidence=verified_evidence,
                    authorization=authorization,
                )
                return self._json(200, self._success(event, key, replayed, request_id))
            if method == "GET" and path.startswith("/v1/audit/idempotency/"):
                self._authorize(actor, "lookup_idempotency")
                key = self._validate_key(unquote(path.rsplit("/", 1)[-1]))
                event = self._repository.lookup(self._repository_id, key)
                if event is None:
                    raise AuditServiceError(404, "not_found", "idempotency key was not found")
                return self._json(200, self._success(event, key, True, request_id))
            if method == "GET" and path == "/v1/audit/events":
                self._authorize(actor, "read_audit")
                if len(parsed.query) > 2048:
                    raise AuditServiceError(400, "invalid_request", "event query is oversized")
                query = parse_qs(parsed.query, strict_parsing=True, max_num_fields=2)
                if set(query) - {"limit", "cursor"} or any(len(v) != 1 for v in query.values()):
                    raise AuditServiceError(400, "invalid_request", "event query parameters are invalid")
                raw_limit = query.get("limit", ["100"])[0]
                if not raw_limit.isdecimal() or not 1 <= int(raw_limit) <= 1000:
                    raise AuditServiceError(400, "invalid_request", "limit must be 1..1000")
                cursor = query.get("cursor", [None])[0]
                offset = self._decode_cursor(cursor)
                page_limit = min(int(raw_limit), 10)
                events = self._repository.list_events(self._repository_id, offset, page_limit + 1)
                next_cursor = None
                if len(events) > page_limit:
                    events = events[:page_limit]
                    next_cursor = self._encode_cursor(offset + len(events))
                return self._json(200, {"events": events, "next_cursor": next_cursor})
            raise AuditServiceError(404, "not_found", "endpoint was not found")
        except AuditServiceError as exc:
            return self._error(exc.status, exc.code, str(exc), request_id, exc.retryable)
        except OIDCVerificationError:
            return self._error(401, "unauthenticated", "OIDC identity could not be verified", request_id)
        except (ValueError, TypeError, RecursionError):
            return self._error(400, "invalid_request", "request fields are invalid", request_id)

    def _authenticate(self, headers: dict[str, str]) -> VerifiedGitHubActor:
        authorization = headers.get("authorization", "")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token or " " in token:
            raise AuditServiceError(401, "unauthenticated", "bearer token is required")
        claim = _claim_from_bearer(token)
        actor = self._identity_verifier.verify(claim)
        if not isinstance(actor, VerifiedGitHubActor):
            raise AuditServiceError(401, "unauthenticated", "identity verifier returned invalid actor")
        return actor

    def _authorize(
        self, actor: VerifiedGitHubActor, operation: str,
        plan_token: str | None = None,
    ) -> AuthorizationResult:
        try:
            result = self._authorization_policy.authorize(
                actor=actor, operation=operation,
                repository_id=self._repository_id, plan_token=plan_token,
            )
        except Exception as exc:
            raise AuditServiceError(
                503, "authorization_unavailable",
                "authorization policy could not be evaluated", retryable=True,
            ) from exc
        if (
            not isinstance(result, AuthorizationResult)
            or type(result.allowed) is not bool
            or not isinstance(result.decision_id, str) or not result.decision_id
            or not isinstance(result.policy_version, str) or not result.policy_version
        ):
            raise AuditServiceError(
                503, "authorization_unavailable",
                "authorization policy returned an invalid result", retryable=True,
            )
        if not result.allowed:
            raise AuditServiceError(403, "forbidden", "operation is not authorized")
        return result

    @staticmethod
    def _validate_key(value: object) -> str:
        if not isinstance(value, str) or not _KEY.fullmatch(value):
            raise AuditServiceError(400, "invalid_request", "idempotency key is invalid")
        return value

    @staticmethod
    def _encode_cursor(offset: int) -> str:
        return base64.urlsafe_b64encode(str(offset).encode("ascii")).rstrip(b"=").decode("ascii")

    @staticmethod
    def _decode_cursor(cursor: str | None) -> int:
        if cursor is None:
            return 0
        if not isinstance(cursor, str) or not 1 <= len(cursor) <= 128:
            raise AuditServiceError(400, "invalid_request", "cursor is invalid")
        try:
            raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
            value = raw.decode("ascii")
            if not value.isdecimal() or len(value) > 10:
                raise ValueError("invalid cursor")
            return int(value)
        except (ValueError, UnicodeDecodeError) as exc:
            raise AuditServiceError(400, "invalid_request", "cursor is invalid") from exc

    @staticmethod
    def _success(event: dict[str, object], key: str, replayed: bool, request_id: str) -> dict[str, object]:
        return {
            "request_id": request_id, "idempotency_key": key,
            "event_id": event["event_id"], "sequence": event["sequence"],
            "event_hash": event["event_hash"], "replayed": replayed,
        }

    @staticmethod
    def _json(status: int, value: dict[str, object]) -> tuple[int, dict[str, str], bytes]:
        payload = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
        ).encode("utf-8")
        if len(payload) > 256 * 1024:
            raise AuditServiceError(503, "unavailable", "response exceeds 256 KiB", retryable=True)
        return status, {"Content-Type": "application/json", "Cache-Control": "no-store"}, payload

    @classmethod
    def _error(
        cls, status: int, code: str, message: str, request_id: str,
        retryable: bool = False,
    ) -> tuple[int, dict[str, str], bytes]:
        return cls._json(status, {"error": {
            "code": code, "message": message, "retryable": retryable,
            "request_id": request_id,
        }})

    def __call__(self, environ, start_response):
        started = time.monotonic()
        client_key = environ.get("REMOTE_ADDR", "unknown")
        allowed, retry_after = self._request_rate_limiter.allow(client_key)
        acquired = False
        if not allowed:
            status, headers, payload = self._error(
                429, "rate_limited", "request rate limit exceeded", str(uuid.uuid4()), True,
            )
            headers["Retry-After"] = str(retry_after)
        elif not self._request_slots.acquire(blocking=False):
            status, headers, payload = self._error(
                503, "capacity_limited", "request concurrency limit reached", str(uuid.uuid4()), True,
            )
            headers["Retry-After"] = "1"
        else:
            acquired = True
            try:
                raw_length = environ.get("CONTENT_LENGTH") or "0"
                try:
                    length = int(raw_length)
                except (TypeError, ValueError):
                    length = -1
                if length < 0:
                    status, headers, payload = self._error(
                        400, "invalid_request", "Content-Length is invalid", str(uuid.uuid4()),
                    )
                elif length > _MAX_BODY_BYTES:
                    status, headers, payload = self._error(
                        413, "invalid_request", "request body exceeds 64 KiB", str(uuid.uuid4()),
                    )
                elif time.monotonic() - started >= self._request_timeout_seconds:
                    status, headers, payload = self._error(
                        408, "request_timeout", "request deadline exceeded", str(uuid.uuid4()), True,
                    )
                else:
                    stream = environ.get("wsgi.input")
                    if length and not callable(getattr(stream, "read", None)):
                        status, headers, payload = self._error(
                            400, "invalid_request", "request body stream is invalid", str(uuid.uuid4()),
                        )
                    else:
                        body = stream.read(length) if length else b""
                        if not isinstance(body, bytes) or len(body) != length:
                            status, headers, payload = self._error(
                                400, "invalid_request", "request body length does not match Content-Length", str(uuid.uuid4()),
                            )
                        elif time.monotonic() - started >= self._request_timeout_seconds:
                            status, headers, payload = self._error(
                                408, "request_timeout", "request body deadline exceeded", str(uuid.uuid4()), True,
                            )
                        else:
                            authorization = environ.get("HTTP_AUTHORIZATION", "")
                            if not isinstance(authorization, str) or len(authorization) > 16_500:
                                status, headers, payload = self._error(
                                    431, "invalid_request", "request headers exceed service limits", str(uuid.uuid4()),
                                )
                            else:
                                headers_in = {"Authorization": authorization}
                                method = environ.get("REQUEST_METHOD", "GET")
                                target = environ.get("PATH_INFO", "/")
                                query = environ.get("QUERY_STRING", "")
                                if query:
                                    target += "?" + query
                                status, headers, payload = self.handle(method, target, headers_in, body)
                                if time.monotonic() - started > self._request_timeout_seconds:
                                    status, headers, payload = self._error(
                                        504, "request_deadline_exceeded", "request processing deadline exceeded", str(uuid.uuid4()), True,
                                    )
            finally:
                if acquired:
                    self._request_slots.release()

        phrase = {200: "OK", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
                  404: "Not Found", 408: "Request Timeout", 409: "Conflict",
                  413: "Payload Too Large", 422: "Unprocessable Entity",
                  429: "Too Many Requests", 431: "Request Header Fields Too Large",
                  503: "Service Unavailable", 504: "Gateway Timeout"}.get(status, "Error")
        response_headers = list(headers.items()) + [("Content-Length", str(len(payload)))]
        start_response(f"{status} {phrase}", response_headers)
        return [payload]
