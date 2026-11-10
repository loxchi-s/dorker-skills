"""Dorker Agent Lab: policy-gated, provider-agnostic agent scaffold."""

from .agent import Agent, ChatModel, ModelMessage
from .framework_adapters import (
    CrewAIAdapter,
    FrameworkExecutionError,
    LangChainAdapter,
)
from .tasks import TaskRequest
from .github_oidc import (
    GitHubActionsJWKSProvider,
    GitHubActionsOIDCTokenProvider,
    GitHubActionsOIDCVerifier,
    GitHubActionsOIDCIdentityProvider,
    GitHubOIDCPolicy,
    OIDCVerificationError,
)

from .artifacts import (
    ArtifactIntegrityError,
    ArtifactGCDryRun,
    ArtifactRetentionPolicy,
    ArtifactDeletionPlan,
    ArtifactObjectInfo,
    ArtifactNotFoundError,
    GitHubActorClaim,
    VerifiedGitHubActor,
    GitHubIdentityVerifier,
    ArtifactStoreError,
    ContentAddressedArtifactStore,
    SQLiteArtifactIndex,
)

from .isolated_worker import (
    IsolatedWorkerRunner,
    ResourceLimits,
    WorkerCancelledError,
    WorkerCrashedError,
    WorkerError,
    WorkerHandlerError,
    WorkerOutputLimitError,
    WorkerTimeoutError,
)
from .remote_audit import (
    AuditClientError, AuditOutcomeIndeterminate, AuditRequestRejected,
    AuditServiceUnavailable, RemoteAuditHttpClient,
)
from .remote_audit_service import (
    AuditServiceError, InMemoryAuditRepository, RemoteAuditService,
)
from .execution import (
    DuplicateExecutionError, ExecutionRecord, ExecutionState, InMemoryExecutionLedger,
    SQLiteExecutionStore, ExecutionControl, ExecutionCancelledError, ExecutionDeadlineExceeded,
)

__all__ = [
    "Agent",
    "ChatModel",
    "ModelMessage",
    "TaskRequest",
    "GitHubActionsJWKSProvider",
    "GitHubActionsOIDCTokenProvider",
    "GitHubActionsOIDCVerifier",
    "GitHubActionsOIDCIdentityProvider",
    "GitHubOIDCPolicy",
    "OIDCVerificationError",
    "ContentAddressedArtifactStore",
    "SQLiteArtifactIndex",
    "ArtifactStoreError",
    "ArtifactNotFoundError",
    "GitHubActorClaim",
    "VerifiedGitHubActor",
    "GitHubIdentityVerifier",
    "ArtifactIntegrityError",
    "ArtifactGCDryRun",
    "ArtifactRetentionPolicy",
    "ArtifactDeletionPlan",
    "ArtifactObjectInfo",
    "CrewAIAdapter",
    "LangChainAdapter",
    "FrameworkExecutionError",
    "DuplicateExecutionError",
    "ExecutionRecord",
    "ExecutionState",
    "InMemoryExecutionLedger",
    "SQLiteExecutionStore",
    "ExecutionControl",
    "ExecutionCancelledError",
    "ExecutionDeadlineExceeded",
    "IsolatedWorkerRunner",
    "ResourceLimits",
    "WorkerError",
    "WorkerTimeoutError",
    "WorkerCancelledError",
    "WorkerCrashedError",
    "WorkerHandlerError",
    "WorkerOutputLimitError",
    "AuditClientError",
    "AuditOutcomeIndeterminate",
    "AuditRequestRejected",
    "AuditServiceUnavailable",
    "RemoteAuditHttpClient",
    "AuditServiceError",
    "InMemoryAuditRepository",
    "RemoteAuditService",
]
