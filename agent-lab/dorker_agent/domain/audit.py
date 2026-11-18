"""Stable audit domain errors and immutable decision value objects."""
from __future__ import annotations

from dataclasses import dataclass


class AuditServiceError(RuntimeError):
    """Transport-neutral failure contract returned by audit use cases/adapters."""

    def __init__(self, status: int, code: str, message: str, *, retryable: bool = False):
        super().__init__(message)
        self.status = status
        self.code = code
        self.retryable = retryable


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
