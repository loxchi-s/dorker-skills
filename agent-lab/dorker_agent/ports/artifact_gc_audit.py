"""Port for durable, approval-gated artifact-GC audit records."""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..domain.artifact_gc import ArtifactDeletionPlan
from ..domain.identity import GitHubActorClaim


@runtime_checkable
class AuditStore(Protocol):
    """Provider-neutral contract for the current artifact-GC audit operations.

    Implementations must commit each operation atomically and fail closed.
    Every write requires a caller-supplied idempotency key. Reusing a key with
    the same canonical request returns the original event hash; changed content
    under the same key fails closed.
    """

    def record_gc_plan(
        self, plan: ArtifactDeletionPlan, *, claim: GitHubActorClaim,
        idempotency_key: str,
    ) -> str: ...

    def record_gc_approval(
        self, approval_token: str, *, claim: GitHubActorClaim, approved: bool,
        idempotency_key: str,
    ) -> str: ...

    def list_audit_events(self, *, limit: int = 100) -> list[dict[str, object]]: ...

    def verify_audit_log(self) -> bool: ...


