"""Ports required by the audit application service."""
from __future__ import annotations

from typing import Protocol

from ..domain.audit import AuthorizationResult, VerifiedApprovalEvidence
from ..domain.identity import GitHubActorClaim, VerifiedGitHubActor


class IdentityVerifier(Protocol):
    def verify(self, claim: GitHubActorClaim) -> VerifiedGitHubActor: ...


class ApprovalEvidenceVerifier(Protocol):
    def verify(
        self,
        *,
        envelope: dict[str, object],
        repository_id: int,
        plan_token: str,
        decision: str,
        actor: VerifiedGitHubActor,
    ) -> VerifiedApprovalEvidence: ...


class AuthorizationPolicy(Protocol):
    def authorize(
        self,
        *,
        actor: VerifiedGitHubActor,
        operation: str,
        repository_id: int,
        plan_token: str | None,
    ) -> AuthorizationResult: ...


class AuditRepository(Protocol):
    def append(
        self,
        *,
        repository_id: int,
        idempotency_key: str,
        request_hash: str,
        event_type: str,
        actor: VerifiedGitHubActor,
        details: dict[str, object],
        approval_token: str | None,
        approval_evidence: VerifiedApprovalEvidence | None = None,
        authorization: AuthorizationResult | None = None,
    ) -> tuple[dict[str, object], bool]: ...

    def lookup(
        self, repository_id: int, idempotency_key: str
    ) -> dict[str, object] | None: ...

    def list_events(
        self, repository_id: int, offset: int, limit: int
    ) -> list[dict[str, object]]: ...

    def verify(self, repository_id: int) -> bool: ...
