"""In-memory reference adapter for the audit repository port."""
from __future__ import annotations

import copy
import threading
import uuid
from datetime import datetime, timezone

from ...application.errors import AuditServiceError
from ...domain.audit import AuthorizationResult, VerifiedApprovalEvidence
from ...domain.audit_hashing import ZERO_HASH as _ZERO_HASH, event_hash as _event_hash
from ...domain.identity import VerifiedGitHubActor

_MAX_EVENTS = 10_000


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
