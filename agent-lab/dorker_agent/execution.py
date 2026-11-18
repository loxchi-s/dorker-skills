"""Compatibility facade for execution lifecycle and persistence APIs."""
from __future__ import annotations

from .application.execution_control import ExecutionControl
from .application.errors import (
    DuplicateExecutionError,
    ExecutionCancelledError,
    ExecutionDeadlineExceeded,
)
from .domain.execution import ExecutionRecord, ExecutionState
from .ports.execution_ledger import ExecutionLedger
from .adapters.persistence.in_memory_execution_ledger import InMemoryExecutionLedger
from .adapters.persistence.sqlite_execution_store import SQLiteExecutionStore

__all__ = [
    "DuplicateExecutionError",
    "ExecutionCancelledError",
    "ExecutionControl",
    "ExecutionDeadlineExceeded",
    "ExecutionLedger",
    "ExecutionRecord",
    "ExecutionState",
    "InMemoryExecutionLedger",
    "SQLiteExecutionStore",
]
