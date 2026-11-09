"""PostgreSQL implementation of the Remote Audit Repository contract.

Requires psycopg 3 for the DSN constructor. Inject connection_factory in tests.
"""
from __future__ import annotations

import copy
import json
import uuid
from datetime import datetime, timezone
from typing import Callable

from .artifacts import VerifiedGitHubActor
from .remote_audit_service import (
    AuditServiceError,
    AuthorizationResult,
    VerifiedApprovalEvidence,
    _ZERO_HASH,
    _event_hash,
)

_MAX_EVENTS = 10_000


class PostgresAuditRepository:
    """Multi-runner PostgreSQL audit store; all writes are transaction-serialized."""

    mode = "postgresql"

    def __init__(
        self,
        connection_factory: Callable[[], object],
        *,
        max_events: int = _MAX_EVENTS,
        statement_timeout_ms: int = 5_000,
    ) -> None:
        if not callable(connection_factory):
            raise TypeError("connection_factory must be callable")
        if isinstance(max_events, bool) or not isinstance(max_events, int) or max_events < 1:
            raise ValueError("max_events must be a positive integer")
        if isinstance(statement_timeout_ms, bool) or not isinstance(statement_timeout_ms, int) or statement_timeout_ms < 1:
            raise ValueError("statement_timeout_ms must be a positive integer")
        self._connect = connection_factory
        self._max_events = max_events
        self._statement_timeout_ms = statement_timeout_ms

    @classmethod
    def from_dsn(
        cls, dsn: str, *, max_events: int = _MAX_EVENTS,
        statement_timeout_ms: int = 5_000,
    ) -> "PostgresAuditRepository":
        if not isinstance(dsn, str) or not dsn.strip():
            raise ValueError("a PostgreSQL DSN is required")

        def connect():
            try:
                import psycopg
                from psycopg.rows import dict_row
            except ImportError as exc:
                raise RuntimeError("install psycopg[binary]>=3.2 to use PostgreSQL") from exc
            return psycopg.connect(
                dsn,
                row_factory=dict_row,
                connect_timeout=5,
                application_name="dorker-remote-audit",
            )

        return cls(connect, max_events=max_events, statement_timeout_ms=statement_timeout_ms)

    @staticmethod
    def _json_object(value: object) -> dict[str, object]:
        if isinstance(value, str):
            value = json.loads(value)
        if not isinstance(value, dict):
            raise AuditServiceError(422, "integrity_violation", "stored event is malformed")
        return value

    def _configure(self, cursor) -> None:
        cursor.execute("SET LOCAL statement_timeout = %s", (self._statement_timeout_ms,))

    def _verify_cursor(self, cursor, repository_id: int) -> bool:
        cursor.execute(
            "SELECT sequence, event_document, event_hash FROM remote_audit.events "
            "WHERE repository_id = %s ORDER BY sequence",
            (repository_id,),
        )
        rows = cursor.fetchall()
        previous = _ZERO_HASH
        try:
            for expected, row in enumerate(rows, start=1):
                event = self._json_object(row["event_document"])
                stored_hash = str(row["event_hash"]).strip()
                if (
                    int(row["sequence"]) != expected
                    or event.get("sequence") != expected
                    or event.get("previous_hash") != previous
                    or event.get("event_hash") != stored_hash
                    or stored_hash != _event_hash(event)
                ):
                    return False
                previous = stored_hash
        except (ValueError, TypeError, KeyError, RecursionError, AuditServiceError):
            return False

        cursor.execute(
            "SELECT sequence, event_hash FROM remote_audit.heads WHERE repository_id = %s",
            (repository_id,),
        )
        head = cursor.fetchone()
        if not rows:
            return head is None
        return bool(
            head is not None
            and int(head["sequence"]) == len(rows)
            and str(head["event_hash"]).strip() == previous
        )

    @staticmethod
    def _translate_database_error(exc: Exception, *, write: bool = False) -> AuditServiceError:
        sqlstate = getattr(exc, "sqlstate", None) or getattr(exc, "pgcode", None)
        if isinstance(sqlstate, str) and sqlstate.startswith("23"):
            return AuditServiceError(
                409, "transaction_conflict",
                "audit uniqueness or referential constraint rejected the write",
            )
        return AuditServiceError(
            503, "repository_unavailable",
            "audit repository transaction failed" if write else "audit repository read failed",
            retryable=True,
        )

    def append(
        self, *, repository_id: int, idempotency_key: str, request_hash: str,
        event_type: str, actor: VerifiedGitHubActor, details: dict[str, object],
        approval_token: str | None,
        approval_evidence: VerifiedApprovalEvidence | None = None,
        authorization: AuthorizationResult | None = None,
    ) -> tuple[dict[str, object], bool]:
        conn = None
        try:
            conn = self._connect()
            with conn.cursor() as cursor:
                self._configure(cursor)
                # Hash the repository ID in PostgreSQL; the transaction lock also
                # protects the empty-chain case where no head row exists yet.
                cursor.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (str(repository_id),),
                )
                if not self._verify_cursor(cursor, repository_id):
                    raise AuditServiceError(422, "integrity_violation", "audit chain verification failed")

                cursor.execute(
                    "SELECT request_hash, event_document FROM remote_audit.events "
                    "WHERE repository_id = %s AND idempotency_key = %s",
                    (repository_id, idempotency_key),
                )
                prior = cursor.fetchone()
                if prior is not None:
                    if str(prior["request_hash"]).strip() != request_hash:
                        raise AuditServiceError(409, "idempotency_conflict", "idempotency key was reused")
                    event = self._json_object(prior["event_document"])
                    conn.commit()
                    return event, True

                cursor.execute(
                    "SELECT COUNT(*) AS event_count FROM remote_audit.events WHERE repository_id = %s",
                    (repository_id,),
                )
                if int(cursor.fetchone()["event_count"]) >= self._max_events:
                    raise AuditServiceError(503, "unavailable", "audit repository capacity reached", retryable=True)

                token = str(approval_token)
                if event_type == "gc_plan_created":
                    cursor.execute(
                        "SELECT 1 FROM remote_audit.plans WHERE repository_id = %s AND plan_token = %s",
                        (repository_id, token),
                    )
                    if cursor.fetchone() is not None:
                        raise AuditServiceError(409, "decision_conflict", "plan token already exists")
                else:
                    cursor.execute(
                        "SELECT creator_actor_id FROM remote_audit.plans "
                        "WHERE repository_id = %s AND plan_token = %s",
                        (repository_id, token),
                    )
                    plan = cursor.fetchone()
                    if plan is None:
                        raise AuditServiceError(404, "not_found", "GC plan was not found")
                    if int(plan["creator_actor_id"]) == actor.github_id:
                        raise AuditServiceError(403, "forbidden", "creator cannot approve own plan")
                    cursor.execute(
                        "SELECT 1 FROM remote_audit.decisions WHERE repository_id = %s AND plan_token = %s",
                        (repository_id, token),
                    )
                    if cursor.fetchone() is not None:
                        raise AuditServiceError(409, "decision_conflict", "plan already has a terminal decision")
                    if approval_evidence is None or authorization is None or not authorization.allowed:
                        raise AuditServiceError(403, "approval_evidence_required", "verified approval evidence is required")
                    cursor.execute(
                        "SELECT 1 FROM remote_audit.consumed_evidence "
                        "WHERE repository_id = %s AND issuer = %s AND evidence_id = %s",
                        (repository_id, approval_evidence.issuer, approval_evidence.evidence_id),
                    )
                    if cursor.fetchone() is not None:
                        raise AuditServiceError(409, "approval_evidence_replayed", "approval evidence was already consumed")

                cursor.execute(
                    "SELECT sequence, event_hash FROM remote_audit.heads WHERE repository_id = %s",
                    (repository_id,),
                )
                head = cursor.fetchone()
                sequence = int(head["sequence"]) + 1 if head else 1
                previous_hash = str(head["event_hash"]).strip() if head else _ZERO_HASH
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
                    "sequence": sequence,
                    "event_id": str(uuid.uuid4()),
                    "event_type": event_type,
                    "actor_id": actor.github_id,
                    "actor_login": actor.login,
                    "timestamp": timestamp,
                    "details": event_details,
                    "idempotency_key": idempotency_key,
                    "request_hash": request_hash,
                    "previous_hash": previous_hash,
                    "event_hash": "",
                }
                event["event_hash"] = _event_hash(event)
                cursor.execute(
                    "INSERT INTO remote_audit.events "
                    "(repository_id, sequence, event_id, event_document, event_hash, "
                    "idempotency_key, request_hash, event_type, plan_token) "
                    "VALUES (%s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s)",
                    (
                        repository_id, sequence, event["event_id"],
                        json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False),
                        event["event_hash"], idempotency_key, request_hash, event_type, token,
                    ),
                )
                cursor.execute(
                    "INSERT INTO remote_audit.heads (repository_id, sequence, event_hash) "
                    "VALUES (%s, %s, %s) ON CONFLICT (repository_id) DO UPDATE "
                    "SET sequence = EXCLUDED.sequence, event_hash = EXCLUDED.event_hash, updated_at = clock_timestamp()",
                    (repository_id, sequence, event["event_hash"]),
                )
                if event_type == "gc_plan_created":
                    cursor.execute(
                        "INSERT INTO remote_audit.plans (repository_id, plan_token, creator_actor_id, event_sequence) "
                        "VALUES (%s, %s, %s, %s)",
                        (repository_id, token, actor.github_id, sequence),
                    )
                else:
                    cursor.execute(
                        "INSERT INTO remote_audit.decisions (repository_id, plan_token, event_sequence) "
                        "VALUES (%s, %s, %s)",
                        (repository_id, token, sequence),
                    )
                    cursor.execute(
                        "INSERT INTO remote_audit.consumed_evidence "
                        "(repository_id, issuer, evidence_id, evidence_digest, plan_token, event_sequence) "
                        "VALUES (%s, %s, %s, %s, %s, %s)",
                        (
                            repository_id, approval_evidence.issuer, approval_evidence.evidence_id,
                            approval_evidence.evidence_digest, token, sequence,
                        ),
                    )
            # Explicit commit before reporting success. If commit outcome is
            # uncertain, callers must retry the exact idempotent request.
            conn.commit()
            return event, False
        except AuditServiceError:
            if conn is not None:
                conn.rollback()
            raise
        except Exception as exc:
            if conn is not None:
                conn.rollback()
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise self._translate_database_error(exc, write=True) from exc
        finally:
            if conn is not None:
                conn.close()

    def _read(self, repository_id: int, query: str, params: tuple) -> list[dict[str, object]]:
        conn = None
        try:
            conn = self._connect()
            with conn.cursor() as cursor:
                cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                self._configure(cursor)
                if not self._verify_cursor(cursor, repository_id):
                    raise AuditServiceError(422, "integrity_violation", "audit chain verification failed")
                cursor.execute(query, params)
                rows = cursor.fetchall()
                return [self._json_object(row["event_document"]) for row in rows]
        except AuditServiceError:
            raise
        except Exception as exc:
            raise self._translate_database_error(exc) from exc
        finally:
            if conn is not None:
                conn.close()

    def lookup(self, repository_id: int, idempotency_key: str) -> dict[str, object] | None:
        rows = self._read(
            repository_id,
            "SELECT event_document FROM remote_audit.events "
            "WHERE repository_id = %s AND idempotency_key = %s",
            (repository_id, idempotency_key),
        )
        return rows[0] if rows else None

    def list_events(self, repository_id: int, offset: int, limit: int) -> list[dict[str, object]]:
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise ValueError("offset must be a non-negative integer")
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        return self._read(
            repository_id,
            "SELECT event_document FROM remote_audit.events "
            "WHERE repository_id = %s ORDER BY sequence LIMIT %s OFFSET %s",
            (repository_id, limit, offset),
        )

    def verify(self, repository_id: int) -> bool:
        conn = None
        try:
            conn = self._connect()
            with conn.cursor() as cursor:
                cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                self._configure(cursor)
                return self._verify_cursor(cursor, repository_id)
        except Exception as exc:
            raise self._translate_database_error(exc) from exc
        finally:
            if conn is not None:
                conn.close()
