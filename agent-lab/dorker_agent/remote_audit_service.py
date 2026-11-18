"""Compatibility composition facade for the remote audit HTTP service.

New application code should depend on RemoteAuditApplicationService and its Ports.
This module preserves the historical WSGI-compatible public API.
"""
from __future__ import annotations

from .application.errors import AuditServiceError
from .application.remote_audit_service import (
    DefaultDenyApprovalEvidenceVerifier,
    DefaultDenyAuthorizationPolicy,
    RemoteAuditApplicationService,
    _ZERO_HASH,
    _canonical_hash,
    _claim_from_bearer,
    _event_hash,
)
from .adapters.http.audit_wsgi import AuditWSGIAdapter
from .adapters.http.request_rate_limiter import RequestRateLimiter
from .adapters.persistence.in_memory_audit_repository import InMemoryAuditRepository
from .adapters.persistence.sqlite_audit_repository import SQLiteAuditRepository
from .domain.audit import AuthorizationResult, VerifiedApprovalEvidence
from .domain.identity import GitHubActorClaim, VerifiedGitHubActor
from .ports.audit import ApprovalEvidenceVerifier, AuditRepository, AuthorizationPolicy
from .ports.identity import GitHubIdentityVerifier

IdentityVerifier = GitHubIdentityVerifier


class RemoteAuditService(RemoteAuditApplicationService):
    """Backward-compatible composition root with a WSGI callable interface."""

    def __init__(
        self,
        *,
        repository_id: int,
        identity_verifier: GitHubIdentityVerifier,
        repository: AuditRepository,
        authorization_policy: AuthorizationPolicy | None = None,
        approval_evidence_verifier: ApprovalEvidenceVerifier | None = None,
        request_rate_limiter: RequestRateLimiter | None = None,
        request_timeout_seconds: float = 8.0,
    ) -> None:
        if request_rate_limiter is not None and not callable(getattr(request_rate_limiter, "allow", None)):
            raise TypeError("request_rate_limiter must expose allow()")
        if (
            isinstance(request_timeout_seconds, bool)
            or not isinstance(request_timeout_seconds, (int, float))
            or not 0 < request_timeout_seconds <= 30
        ):
            raise ValueError("request_timeout_seconds must be in (0, 30]")
        super().__init__(
            repository_id=repository_id,
            identity_verifier=identity_verifier,
            repository=repository,
            authorization_policy=authorization_policy,
            approval_evidence_verifier=approval_evidence_verifier,
        )
        self._wsgi_adapter = AuditWSGIAdapter(
            self,
            rate_limiter=request_rate_limiter or RequestRateLimiter(),
            request_timeout_seconds=float(request_timeout_seconds),
        )

    @classmethod
    def _error(cls, status: int, code: str, message: str, request_id: str, retryable: bool = False):
        """Compatibility alias for the historical private error helper."""
        return cls.error_response(status, code, message, request_id, retryable)

    def __call__(self, environ, start_response):
        return self._wsgi_adapter(environ, start_response)


__all__ = [
    "AuditServiceError",
    "AuthorizationResult",
    "DefaultDenyApprovalEvidenceVerifier",
    "DefaultDenyAuthorizationPolicy",
    "GitHubActorClaim",
    "GitHubIdentityVerifier",
    "IdentityVerifier",
    "InMemoryAuditRepository",
    "RemoteAuditApplicationService",
    "RemoteAuditService",
    "SQLiteAuditRepository",
    "VerifiedApprovalEvidence",
    "VerifiedGitHubActor",
]
