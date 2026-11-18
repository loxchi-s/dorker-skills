"""Stable audit domain errors and immutable decision value objects."""
from __future__ import annotations

from dataclasses import dataclass


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
