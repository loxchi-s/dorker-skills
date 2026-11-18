"""Application-level errors shared by services and outbound adapters."""
from __future__ import annotations


class AuditServiceError(RuntimeError):
    """Stable audit use-case error mapped to transport responses at the edge."""

    def __init__(self, status: int, code: str, message: str, *, retryable: bool = False):
        super().__init__(message)
        self.status = status
        self.code = code
        self.retryable = retryable
