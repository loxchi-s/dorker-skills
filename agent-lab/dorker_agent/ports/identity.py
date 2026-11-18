"""Identity verification port implemented by trusted host adapters."""
from __future__ import annotations

from typing import Protocol

from ..domain.identity import GitHubActorClaim, VerifiedGitHubActor


class GitHubIdentityVerifier(Protocol):
    """Verify an untrusted GitHub actor claim and return its canonical identity."""

    def verify(self, claim: GitHubActorClaim) -> VerifiedGitHubActor: ...
