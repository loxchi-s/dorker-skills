"""Dorker Agent Lab public API with lazy optional-module exports.

Importing the Agent Core must not load unrelated framework, storage, OIDC,
worker, or audit adapters and their optional third-party dependencies.
"""

from __future__ import annotations

from importlib import import_module

_EXPORTS: dict[str, tuple[str, str]] = {
    "Agent": (".agent", "Agent"),
    "ChatModel": (".agent", "ChatModel"),
    "ModelMessage": (".agent", "ModelMessage"),
    "TaskRequest": (".tasks", "TaskRequest"),
    "GitHubActionsJWKSProvider": (".github_oidc", "GitHubActionsJWKSProvider"),
    "GitHubActionsOIDCTokenProvider": (".github_oidc", "GitHubActionsOIDCTokenProvider"),
    "GitHubActionsOIDCVerifier": (".github_oidc", "GitHubActionsOIDCVerifier"),
    "GitHubActionsOIDCIdentityProvider": (".github_oidc", "GitHubActionsOIDCIdentityProvider"),
    "GitHubOIDCPolicy": (".github_oidc", "GitHubOIDCPolicy"),
    "OIDCVerificationError": (".github_oidc", "OIDCVerificationError"),
    "ContentAddressedArtifactStore": (".artifacts", "ContentAddressedArtifactStore"),
    "SQLiteArtifactIndex": (".artifacts", "SQLiteArtifactIndex"),
    "ArtifactStoreError": (".artifacts", "ArtifactStoreError"),
    "ArtifactNotFoundError": (".artifacts", "ArtifactNotFoundError"),
    "GitHubActorClaim": (".artifacts", "GitHubActorClaim"),
    "VerifiedGitHubActor": (".artifacts", "VerifiedGitHubActor"),
    "GitHubIdentityVerifier": (".artifacts", "GitHubIdentityVerifier"),
    "ArtifactIntegrityError": (".artifacts", "ArtifactIntegrityError"),
    "ArtifactGCDryRun": (".artifacts", "ArtifactGCDryRun"),
    "ArtifactRetentionPolicy": (".artifacts", "ArtifactRetentionPolicy"),
    "ArtifactDeletionPlan": (".artifacts", "ArtifactDeletionPlan"),
    "ArtifactObjectInfo": (".artifacts", "ArtifactObjectInfo"),
    "CrewAIAdapter": (".framework_adapters", "CrewAIAdapter"),
    "LangChainAdapter": (".framework_adapters", "LangChainAdapter"),
    "FrameworkExecutionError": (".framework_adapters", "FrameworkExecutionError"),
    "DuplicateExecutionError": (".execution", "DuplicateExecutionError"),
    "ExecutionRecord": (".execution", "ExecutionRecord"),
    "ExecutionState": (".execution", "ExecutionState"),
    "InMemoryExecutionLedger": (".execution", "InMemoryExecutionLedger"),
    "SQLiteExecutionStore": (".execution", "SQLiteExecutionStore"),
    "ExecutionControl": (".execution", "ExecutionControl"),
    "ExecutionCancelledError": (".execution", "ExecutionCancelledError"),
    "ExecutionDeadlineExceeded": (".execution", "ExecutionDeadlineExceeded"),
    "IsolatedWorkerRunner": (".isolated_worker", "IsolatedWorkerRunner"),
    "ResourceLimits": (".isolated_worker", "ResourceLimits"),
    "WorkerError": (".isolated_worker", "WorkerError"),
    "WorkerTimeoutError": (".isolated_worker", "WorkerTimeoutError"),
    "WorkerCancelledError": (".isolated_worker", "WorkerCancelledError"),
    "WorkerCrashedError": (".isolated_worker", "WorkerCrashedError"),
    "WorkerHandlerError": (".isolated_worker", "WorkerHandlerError"),
    "WorkerOutputLimitError": (".isolated_worker", "WorkerOutputLimitError"),
    "AuditClientError": (".remote_audit", "AuditClientError"),
    "AuditOutcomeIndeterminate": (".remote_audit", "AuditOutcomeIndeterminate"),
    "AuditRequestRejected": (".remote_audit", "AuditRequestRejected"),
    "AuditServiceUnavailable": (".remote_audit", "AuditServiceUnavailable"),
    "RemoteAuditHttpClient": (".remote_audit", "RemoteAuditHttpClient"),
    "AuditServiceError": (".remote_audit_service", "AuditServiceError"),
    "InMemoryAuditRepository": (".remote_audit_service", "InMemoryAuditRepository"),
    "RemoteAuditService": (".remote_audit_service", "RemoteAuditService"),
}

__all__ = list(_EXPORTS)


def __getattr__(name: str) -> object:
    """Load an exported symbol only when its owning module is requested."""
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc

    module = import_module(module_name, __name__)
    value = getattr(module, attribute_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
