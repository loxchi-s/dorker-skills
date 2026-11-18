"""Dorker Agent Lab core package.

Importing the package or its domain/application/port exports does not load
unrelated framework, storage, OIDC, worker, or audit adapters. Infrastructure
adapters are imported lazily only when their concrete exports are requested.
"""
from __future__ import annotations

from importlib import import_module

_EXPORTS = {
    "Agent": (".agent", "Agent"),
    "ChatModel": (".agent", "ChatModel"),
    "ModelMessage": (".agent", "ModelMessage"),
    "TaskRequest": (".tasks", "TaskRequest"),
    "TaskRegistry": (".tasks", "TaskRegistry"),
    "TaskExecutor": (".tasks", "TaskExecutor"),
    "TaskState": (".tasks", "TaskState"),
    "TaskResult": (".tasks", "TaskResult"),
    "CapabilityPolicy": (".capabilities", "CapabilityPolicy"),
    "DEFAULT_POLICY": (".capabilities", "DEFAULT_POLICY"),

    "ArtifactManifest": (".domain.artifact_manifest", "ArtifactManifest"),
    "ArtifactGCDryRun": (".domain.artifact_gc", "ArtifactGCDryRun"),
    "ArtifactRetentionPolicy": (".domain.artifact_gc", "ArtifactRetentionPolicy"),
    "ArtifactDeletionPlan": (".domain.artifact_gc", "ArtifactDeletionPlan"),
    "ArtifactObjectInfo": (".domain.artifact_gc", "ArtifactObjectInfo"),
    "ArtifactBlobStore": (".ports.artifact_blob_store", "ArtifactBlobStore"),
    "ArtifactStoreError": (".ports.artifact_blob_store", "ArtifactStoreError"),
    "ArtifactNotFoundError": (".ports.artifact_blob_store", "ArtifactNotFoundError"),
    "ArtifactIntegrityError": (".ports.artifact_blob_store", "ArtifactIntegrityError"),
    "ContentAddressedArtifactStore": (
        ".adapters.storage.content_addressed_artifact_store",
        "ContentAddressedArtifactStore",
    ),
    "SQLiteArtifactIndex": (
        ".adapters.persistence.sqlite_artifact_index",
        "SQLiteArtifactIndex",
    ),
    "AuditStore": (".ports.artifact_gc_audit", "AuditStore"),

    "GitHubActorClaim": (".domain.identity", "GitHubActorClaim"),
    "VerifiedGitHubActor": (".domain.identity", "VerifiedGitHubActor"),
    "GitHubIdentityVerifier": (".ports.identity", "GitHubIdentityVerifier"),
    "IdentityVerificationError": (".ports.identity", "IdentityVerificationError"),
    "GitHubActionsJWKSProvider": (".github_oidc", "GitHubActionsJWKSProvider"),
    "GitHubActionsOIDCTokenProvider": (".github_oidc", "GitHubActionsOIDCTokenProvider"),
    "GitHubActionsOIDCVerifier": (".github_oidc", "GitHubActionsOIDCVerifier"),
    "GitHubOIDCPolicy": (".github_oidc", "GitHubOIDCPolicy"),
    "OIDCVerificationError": (".github_oidc", "OIDCVerificationError"),

    "AuthorizationResult": (".domain.audit", "AuthorizationResult"),
    "VerifiedApprovalEvidence": (".domain.audit", "VerifiedApprovalEvidence"),
    "AuditRepository": (".ports.audit", "AuditRepository"),
    "AuthorizationPolicy": (".ports.audit", "AuthorizationPolicy"),
    "ApprovalEvidenceVerifier": (".ports.audit", "ApprovalEvidenceVerifier"),
    "AuditServiceError": (".application.errors", "AuditServiceError"),
    "InMemoryAuditRepository": (
        ".adapters.persistence.in_memory_audit_repository",
        "InMemoryAuditRepository",
    ),
    "RemoteAuditService": (".remote_audit_service", "RemoteAuditService"),
    "AuditClientError": (".remote_audit", "AuditClientError"),
    "AuditCursorError": (".remote_audit", "AuditCursorError"),
    "AuditHTTPError": (".remote_audit", "AuditHTTPError"),
    "RemoteAuditHttpClient": (".remote_audit", "RemoteAuditHttpClient"),

    "ExecutionRecord": (".domain.execution", "ExecutionRecord"),
    "ExecutionState": (".domain.execution", "ExecutionState"),
    "ExecutionLedger": (".ports.execution_ledger", "ExecutionLedger"),
    "InMemoryExecutionLedger": (
        ".adapters.persistence.in_memory_execution_ledger",
        "InMemoryExecutionLedger",
    ),
    "SQLiteExecutionStore": (
        ".adapters.persistence.sqlite_execution_store",
        "SQLiteExecutionStore",
    ),
    "ExecutionControl": (".application.execution_control", "ExecutionControl"),
    "ExecutionCancelledError": (".application.errors", "ExecutionCancelledError"),
    "ExecutionDeadlineExceeded": (".application.errors", "ExecutionDeadlineExceeded"),
    "DuplicateExecutionError": (".application.errors", "DuplicateExecutionError"),

    "CrewAIAdapter": (".framework_adapters", "CrewAIAdapter"),
    "LangChainAdapter": (".framework_adapters", "LangChainAdapter"),
    "FrameworkExecutionError": (".framework_adapters", "FrameworkExecutionError"),
    "IsolatedWorkerRunner": (".isolated_worker", "IsolatedWorkerRunner"),
    "ResourceLimits": (".isolated_worker", "ResourceLimits"),
    "WorkerContext": (".isolated_worker", "WorkerContext"),
    "WorkerHandler": (".isolated_worker", "WorkerHandler"),
    "WorkerError": (".isolated_worker", "WorkerError"),
    "WorkerTimeoutError": (".isolated_worker", "WorkerTimeoutError"),
    "WorkerCancelledError": (".isolated_worker", "WorkerCancelledError"),
    "WorkerCrashedError": (".isolated_worker", "WorkerCrashedError"),
    "WorkerHandlerError": (".isolated_worker", "WorkerHandlerError"),
    "WorkerOutputLimitError": (".isolated_worker", "WorkerOutputLimitError"),
}

__all__ = sorted(_EXPORTS)


def __getattr__(name: str):
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute_name = target
    value = getattr(import_module(module_name, __name__), attribute_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
