"""Provider-neutral identity value objects used by Agent Lab contracts."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class GitHubActorClaim:
    github_id: int
    login: str
    oidc_token: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class VerifiedGitHubActor:
    github_id: int
    login: str
