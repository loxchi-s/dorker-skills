"""In-memory reference implementation for Remote Audit Service Contract v1.

This module is a test harness only. It is not a durable or production service.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import threading
import uuid
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


class AuditRepository(Protocol):
    def append(
        self, *, repository_id: int, idempotency_key: str, request_hash: str,
        event_type: str, actor: VerifiedGitHubActor, details: dict[str, object],
        approval_token: str | None,
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
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
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
        raw = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
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

    def __init__(self, *, max_events: int = _MAX_EVENTS) -> None:
        if isinstance(max_events, bool) or not isinstance(max_events, int) or max_events < 1:
            raise ValueError("max_events must be a positive integer")
        self._max_events = max_events
        self._lock = threading.RLock()
        self._events: dict[int, list[dict[str, object]]] = {}
        self._idempotency: dict[tuple[int, str], dict[str, object]] = {}
        self._plans: dict[tuple[int, str], dict[str, object]] = {}
        self._decisions: set[tuple[int, str]] = set()

    def append(
        self, *, repository_id: int, idempotency_key: str, request_hash: str,
        event_type: str, actor: VerifiedGitHubActor, details: dict[str, object],
        approval_token: str | None,
    ) -> tuple[dict[str, object], bool]:
        with self._lock:
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
            return copy.deepcopy(event), False

    def lookup(self, repository_id: int, idempotency_key: str) -> dict[str, object] | None:
        with self._lock:
            value = self._idempotency.get((repository_id, idempotency_key))
            return copy.deepcopy(value["event"]) if value else None

    def list_events(self, repository_id: int, offset: int, limit: int) -> list[dict[str, object]]:
        with self._lock:
            return copy.deepcopy(self._events.get(repository_id, [])[offset:offset + limit])

    def verify(self, repository_id: int) -> bool:
        with self._lock:
            previous = _ZERO_HASH
            for expected, event in enumerate(self._events.get(repository_id, []), start=1):
                if event.get("sequence") != expected or event.get("previous_hash") != previous:
                    return False
                if event.get("event_hash") != _event_hash(event):
                    return False
                previous = str(event["event_hash"])
            return True


class RemoteAuditService:
    """Small WSGI-compatible HTTP service core for contract tests only."""

    def __init__(
        self, *, repository_id: int, identity_verifier: IdentityVerifier,
        repository: AuditRepository,
    ) -> None:
        if isinstance(repository_id, bool) or not isinstance(repository_id, int) or repository_id < 1:
            raise ValueError("repository_id must be a positive integer")
        if not callable(getattr(identity_verifier, "verify", None)):
            raise TypeError("identity_verifier must expose verify()")
        for method in ("append", "lookup", "list_events", "verify"):
            if not callable(getattr(repository, method, None)):
                raise TypeError(f"repository must expose {method}()")
        self._repository_id = repository_id
        self._identity_verifier = identity_verifier
        self._repository = repository

    def handle(
        self, method: str, target: str, headers: dict[str, str] | None = None,
        body: bytes = b"",
    ) -> tuple[int, dict[str, str], bytes]:
        request_id = str(uuid.uuid4())
        headers = {key.lower(): value for key, value in (headers or {}).items()}
        try:
            if len(body) > _MAX_BODY_BYTES:
                raise AuditServiceError(413, "invalid_request", "request body exceeds 64 KiB")
            parsed = urlsplit(target)
            if parsed.fragment:
                raise AuditServiceError(400, "invalid_request", "URL fragment is not allowed")
            path = parsed.path
            if method == "GET" and path == "/v1/audit/health":
                ready = self._repository.verify(self._repository_id)
                return self._json(200, {
                    "ready": ready, "mode": "in-memory-test-only",
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
                event, replayed = self._repository.append(
                    repository_id=self._repository_id, idempotency_key=key,
                    request_hash=request_hash, event_type="gc_plan_created",
                    actor=actor, details=plan, approval_token=token,
                )
                return self._json(200, self._success(event, key, replayed, request_id))
            if method == "POST" and path == "/v1/audit/decisions":
                payload = _strict_object(body)
                if set(payload) != {"idempotency_key", "approval_token", "decision"}:
                    raise AuditServiceError(400, "invalid_request", "decision request fields are invalid")
                key = self._validate_key(payload["idempotency_key"])
                token, decision = payload["approval_token"], payload["decision"]
                if not isinstance(token, str) or not _DIGEST.fullmatch(token):
                    raise AuditServiceError(400, "invalid_request", "approval_token is invalid")
                if decision not in ("approve", "reject"):
                    raise AuditServiceError(400, "invalid_request", "decision must be approve or reject")
                operation = {
                    "api_version": "v1", "operation": "record_decision",
                    "repository_id": self._repository_id, "actor_id": actor.github_id,
                    "payload": {"idempotency_key": key, "approval_token": token, "decision": decision},
                }
                request_hash = _canonical_hash(operation)
                event, replayed = self._repository.append(
                    repository_id=self._repository_id, idempotency_key=key,
                    request_hash=request_hash,
                    event_type="gc_plan_approved" if decision == "approve" else "gc_plan_rejected",
                    actor=actor, details={"approval_token": token, "decision": decision},
                    approval_token=token,
                )
                return self._json(200, self._success(event, key, replayed, request_id))
            if method == "GET" and path.startswith("/v1/audit/idempotency/"):
                key = self._validate_key(unquote(path.rsplit("/", 1)[-1]))
                event = self._repository.lookup(self._repository_id, key)
                if event is None:
                    raise AuditServiceError(404, "not_found", "idempotency key was not found")
                return self._json(200, self._success(event, key, True, request_id))
            if method == "GET" and path == "/v1/audit/events":
                query = parse_qs(parsed.query, strict_parsing=True)
                if set(query) - {"limit", "cursor"} or any(len(v) != 1 for v in query.values()):
                    raise AuditServiceError(400, "invalid_request", "event query parameters are invalid")
                raw_limit = query.get("limit", ["100"])[0]
                if not raw_limit.isdecimal() or not 1 <= int(raw_limit) <= 1000:
                    raise AuditServiceError(400, "invalid_request", "limit must be 1..1000")
                cursor = query.get("cursor", [None])[0]
                offset = self._decode_cursor(cursor)
                events = self._repository.list_events(self._repository_id, offset, int(raw_limit))
                next_cursor = None
                if len(events) == int(raw_limit):
                    next_cursor = self._encode_cursor(offset + len(events))
                return self._json(200, {"events": events, "next_cursor": next_cursor})
            raise AuditServiceError(404, "not_found", "endpoint was not found")
        except AuditServiceError as exc:
            return self._error(exc.status, exc.code, str(exc), request_id, exc.retryable)
        except OIDCVerificationError:
            return self._error(401, "unauthenticated", "OIDC identity could not be verified", request_id)
        except (ValueError, TypeError):
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
        return status, {"Content-Type": "application/json", "Cache-Control": "no-store"}, json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
        ).encode("utf-8")

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
        try:
            length = int(environ.get("CONTENT_LENGTH") or "0")
        except ValueError:
            length = _MAX_BODY_BYTES + 1
        if length < 0 or length > _MAX_BODY_BYTES:
            status, headers, payload = self._error(
                413, "invalid_request", "request body exceeds 64 KiB", str(uuid.uuid4()),
            )
        else:
            body = environ["wsgi.input"].read(length) if length else b""
            headers_in = {"Authorization": environ.get("HTTP_AUTHORIZATION", "")}
            method = environ.get("REQUEST_METHOD", "GET")
            target = environ.get("PATH_INFO", "/")
            query = environ.get("QUERY_STRING", "")
            if query:
                target += "?" + query
            status, headers, payload = self.handle(method, target, headers_in, body)
        phrase = {200: "OK", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
                  404: "Not Found", 409: "Conflict", 413: "Payload Too Large",
                  422: "Unprocessable Entity", 503: "Service Unavailable"}.get(status, "Error")
        response_headers = list(headers.items()) + [("Content-Length", str(len(payload)))]
        start_response(f"{status} {phrase}", response_headers)
        return [payload]
