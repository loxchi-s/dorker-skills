"""Execution lifecycle value objects and pure input invariants."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ExecutionState(str, Enum):
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"

@dataclass(frozen=True, slots=True)
class ExecutionRecord:
    execution_id: str
    state: ExecutionState
    result: str | None = None
    error_type: str | None = None

def validate_execution_id(execution_id: str) -> None:
    if not isinstance(execution_id, str) or not execution_id.strip() or len(execution_id) > 128:
        raise ValueError("execution_id must be 1..128 non-whitespace characters")


def validate_execution_result(result: str) -> None:
    if not isinstance(result, str) or not result.strip():
        raise ValueError("result must be non-empty text")
