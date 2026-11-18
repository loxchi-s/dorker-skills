"""Bounded, thread-safe process-local execution ledger adapter."""
from __future__ import annotations

from threading import RLock

from ...application.errors import DuplicateExecutionError
from ...domain.execution import (
    ExecutionRecord,
    ExecutionState,
    validate_execution_id,
    validate_execution_result,
)


class InMemoryExecutionLedger:
    """Thread-safe, process-local execution ledger."""

    def __init__(self, *, max_records: int = 10_000) -> None:
        if isinstance(max_records, bool) or not isinstance(max_records, int) or max_records < 1:
            raise ValueError("max_records must be a positive integer")
        self._max_records = max_records
        self._records: dict[str, ExecutionRecord] = {}
        self._lock = RLock()

    def begin(self, execution_id: str) -> None:
        validate_execution_id(execution_id)
        with self._lock:
            if execution_id in self._records:
                raise DuplicateExecutionError(f"execution already exists: {execution_id}")
            if len(self._records) >= self._max_records:
                raise RuntimeError("execution ledger capacity reached")
            self._records[execution_id] = ExecutionRecord(execution_id, ExecutionState.RUNNING)

    def succeed(self, execution_id: str, result: str) -> None:
        validate_execution_result(result)
        self._transition(execution_id, ExecutionState.SUCCEEDED, result=result.strip())

    def fail(self, execution_id: str, error: Exception) -> None:
        self._transition(execution_id, ExecutionState.FAILED, error_type=type(error).__name__)

    def get(self, execution_id: str) -> ExecutionRecord | None:
        with self._lock:
            return self._records.get(execution_id)

    def _transition(
        self, execution_id: str, state: ExecutionState, *,
        result: str | None = None, error_type: str | None = None,
    ) -> None:
        validate_execution_id(execution_id)
        with self._lock:
            current = self._records.get(execution_id)
            if current is None or current.state is not ExecutionState.RUNNING:
                raise RuntimeError("execution is missing or not running")
            self._records[execution_id] = ExecutionRecord(
                execution_id, state, result=result, error_type=error_type
            )
