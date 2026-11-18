"""Port for process-local or durable execution lifecycle storage."""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..domain.execution import ExecutionRecord


@runtime_checkable
class ExecutionLedger(Protocol):
    def begin(self, execution_id: str) -> None: ...
    def succeed(self, execution_id: str, result: str) -> None: ...
    def fail(self, execution_id: str, error: Exception) -> None: ...
    def get(self, execution_id: str) -> ExecutionRecord | None: ...
