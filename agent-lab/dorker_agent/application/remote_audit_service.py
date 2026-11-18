"""Application service for the Remote Audit Service Contract v1."""
from __future__ import annotations

import base64
import json
import uuid
from urllib.parse import parse_qs, unquote, urlsplit

from ..domain.identity import GitHubActorClaim, VerifiedGitHubActor
from .errors import AuditServiceError
from .audit_validation import (
    _strict_object, _validate_plan, _DIGEST, validate_key as _validate_key,
    encode_cursor as _encode_cursor, decode_cursor as _decode_cursor,
)
from ..domain.audit import AuthorizationResult, VerifiedApprovalEvidence
from ..domain.audit_hashing import (
    ZERO_HASH as _ZERO_HASH,
    canonical_hash as _domain_canonical_hash,
    event_hash as _event_hash,
)
from ..ports.audit import ApprovalEvidenceVerifier, AuditRepository, AuthorizationPolicy
from ..ports.identity import GitHubIdentityVerifier, IdentityVerificationError

_MAX_BODY_BYTES = 64 * 1024


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




class RemoteAuditApplicationService:
    """HTTP application service; persistence and WSGI are supplied at the boundary."""

    def __init__(
        self, *, repository_id: int, identity_verifier: GitHubIdentityVerifier,
        repository: AuditRepository,
        authorization_policy: AuthorizationPolicy | None = None,
        approval_evidence_verifier: ApprovalEvidenceVerifier | None = None,
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
                key = _validate_key(payload["idempotency_key"])
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
                key = _validate_key(payload["idempotency_key"])
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
                key = _validate_key(unquote(path.rsplit("/", 1)[-1]))
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
                offset = _decode_cursor(cursor)
                page_limit = min(int(raw_limit), 10)
                events = self._repository.list_events(self._repository_id, offset, page_limit + 1)
                next_cursor = None
                if len(events) > page_limit:
                    events = events[:page_limit]
                    next_cursor = _encode_cursor(offset + len(events))
                return self._json(200, {"events": events, "next_cursor": next_cursor})
            raise AuditServiceError(404, "not_found", "endpoint was not found")
        except AuditServiceError as exc:
            return self.error_response(exc.status, exc.code, str(exc), request_id, exc.retryable)
        except IdentityVerificationError:
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
    def error_response(
        cls, status: int, code: str, message: str, request_id: str,
        retryable: bool = False,
    ) -> tuple[int, dict[str, str], bytes]:
        return cls._json(status, {"error": {
            "code": code, "message": message, "retryable": retryable,
            "request_id": request_id,
        }})
