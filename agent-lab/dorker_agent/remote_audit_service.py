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
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import parse_qs, unquote, urlsplit

from .domain.identity import GitHubActorClaim, VerifiedGitHubActor
from .adapters.persistence.in_memory_audit_repository import InMemoryAuditRepository
from .adapters.persistence.sqlite_audit_repository import SQLiteAuditRepository
from .application.errors import AuditServiceError
from .domain.audit import AuthorizationResult, VerifiedApprovalEvidence
from .domain.audit_hashing import ZERO_HASH as _ZERO_HASH, canonical_hash as _domain_canonical_hash, event_hash as _event_hash
from .ports.audit import (
    ApprovalEvidenceVerifier,
    AuditRepository,
    AuthorizationPolicy,
)
from .ports.identity import GitHubIdentityVerifier as IdentityVerifier
from .github_oidc import OIDCVerificationError

_MAX_BODY_BYTES = 64 * 1024
_MAX_EVENTS = 10_000
_KEY = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def _canonical_hash(value: dict[str, object]) -> str:
    try:
        return _domain_canonical_hash(value)
    except ValueError as exc:
        raise AuditServiceError(400, "invalid_request", "request is not canonical JSON") from exc


class DefaultDenyApprovalEvidenceVerifier:
    def verify(self, **kwargs) -> VerifiedApprovalEvidence:
        raise AuditServiceError(403, "approval_evidence_required", "independent approval evidence is not configured")


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
                readiness = getattr(self._repository, "readiness", None)
                ready = readiness(self._repository_id) if callable(readiness) else self._repository.verify(self._repository_id)
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
                429, "rate_limited", "request rate limit exceeded", str(uuid.uuid4()),
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
                        try:
                            body = stream.read(length) if length else b""
                        except Exception:
                            body = None
                        if not isinstance(body, bytes) or len(body) != length:
                            status, headers, payload = self._error(
                                400, "invalid_request", "request body could not be read completely", str(uuid.uuid4()),
                            )
                        elif time.monotonic() - started >= self._request_timeout_seconds:
                            status, headers, payload = self._error(
                                408, "request_timeout", "request body deadline exceeded", str(uuid.uuid4()), True,
                            )
                        else:
                            authorization = environ.get("HTTP_AUTHORIZATION", "")
                            method = environ.get("REQUEST_METHOD", "GET")
                            target = environ.get("PATH_INFO", "/")
                            query = environ.get("QUERY_STRING", "")
                            if (
                                not isinstance(authorization, str) or len(authorization) > 16_500
                                or not isinstance(method, str)
                                or not isinstance(target, str)
                                or not isinstance(query, str)
                            ):
                                status, headers, payload = self._error(
                                    431, "invalid_request", "request headers or target exceed service limits", str(uuid.uuid4()),
                                )
                            else:
                                headers_in = {"Authorization": authorization}
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
