"""In-memory execution lifecycle ledger.

This is a process-local contract implementation, not durable storage.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from threading import RLock


class ExecutionState(str, Enum):
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class DuplicateExecutionError(RuntimeError):
    """An execution identifier has already been claimed."""


@dataclass(frozen=True, slots=True)
class ExecutionRecord:
    execution_id: str
    state: ExecutionState
    result: str | None = None
    error_type: str | None = None


class InMemoryExecutionLedger:
    """Thread-safe, bounded-by-caller in-memory idempotency ledger."""

    def __init__(self, *, max_records: int = 10_000) -> None:
        if isinstance(max_records, bool) or not isinstance(max_records, int) or max_records < 1:
            raise ValueError("max_records must be a positive integer")
        self._max_records = max_records
        self._records: dict[str, ExecutionRecord] = {}
        self._lock = RLock()

    def begin(self, execution_id: str) -> None:
        self._validate_id(execution_id)
        with self._lock:
            if execution_id in self._records:
                raise DuplicateExecutionError(f"execution already exists: {execution_id}")
            if len(self._records) >= self._max_records:
                raise RuntimeError("execution ledger capacity reached")
            self._records[execution_id] = ExecutionRecord(execution_id, ExecutionState.RUNNING)

    def succeed(self, execution_id: str, result: str) -> None:
        if not isinstance(result, str) or not result.strip():
            raise ValueError("result must be non-empty text")
        self._transition(execution_id, ExecutionState.SUCCEEDED, result=result.strip())

    def fail(self, execution_id: str, error: Exception) -> None:
        self._transition(execution_id, ExecutionState.FAILED, error_type=type(error).__name__)

    def get(self, execution_id: str) -> ExecutionRecord | None:
        with self._lock:
            return self._records.get(execution_id)

    def _transition(
        self,
        execution_id: str,
        state: ExecutionState,
        *,
        result: str | None = None,
        error_type: str | None = None,
    ) -> None:
        self._validate_id(execution_id)
        with self._lock:
            current = self._records.get(execution_id)
            if current is None or current.state is not ExecutionState.RUNNING:
                raise RuntimeError("execution is missing or not running")
            self._records[execution_id] = ExecutionRecord(
                execution_id, state, result=result, error_type=error_type
            )

    @staticmethod
    def _validate_id(execution_id: str) -> None:
        if not isinstance(execution_id, str) or not execution_id.strip() or len(execution_id) > 128:
            raise ValueError("execution_id must be 1..128 non-whitespace characters")
