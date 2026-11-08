"""Execution lifecycle contracts and storage backends."""
from __future__ import annotations

import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
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
    """Thread-safe, process-local execution ledger."""

    def __init__(self, *, max_records: int = 10_000) -> None:
        if isinstance(max_records, bool) or not isinstance(max_records, int) or max_records < 1:
            raise ValueError("max_records must be a positive integer")
        self._max_records = max_records
        self._records: dict[str, ExecutionRecord] = {}
        self._lock = RLock()

    def begin(self, execution_id: str) -> None:
        _validate_id(execution_id)
        with self._lock:
            if execution_id in self._records:
                raise DuplicateExecutionError(f"execution already exists: {execution_id}")
            if len(self._records) >= self._max_records:
                raise RuntimeError("execution ledger capacity reached")
            self._records[execution_id] = ExecutionRecord(execution_id, ExecutionState.RUNNING)

    def succeed(self, execution_id: str, result: str) -> None:
        _validate_result(result)
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
        _validate_id(execution_id)
        with self._lock:
            current = self._records.get(execution_id)
            if current is None or current.state is not ExecutionState.RUNNING:
                raise RuntimeError("execution is missing or not running")
            self._records[execution_id] = ExecutionRecord(
                execution_id, state, result=result, error_type=error_type
            )


class SQLiteExecutionStore:
    """Durable single-host ledger; interrupted work is failed, never auto-replayed."""

    def __init__(
        self, database: str | Path, *, max_records: int = 100_000,
        max_result_chars: int = 16_384, busy_timeout_ms: int = 5_000,
    ) -> None:
        for name, value in (("max_records", max_records), ("max_result_chars", max_result_chars)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if isinstance(busy_timeout_ms, bool) or not isinstance(busy_timeout_ms, int) or busy_timeout_ms < 0:
            raise ValueError("busy_timeout_ms must be a non-negative integer")
        self._database = str(database)
        if self._database == ":memory:":
            raise ValueError("a durable SQLite file path is required")
        self._max_records = max_records
        self._max_result_chars = max_result_chars
        self._busy_timeout_ms = busy_timeout_ms
        self._lock = RLock()
        Path(self._database).parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(
            self._database, timeout=self._busy_timeout_ms / 1000,
            isolation_level=None,
        )
        db.row_factory = sqlite3.Row
        db.execute(f"PRAGMA busy_timeout={self._busy_timeout_ms}")
        return db

    def _initialize(self) -> None:
        with self._lock, closing(self._connect()) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("""
                CREATE TABLE IF NOT EXISTS executions (
                    execution_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL CHECK(state IN ('running','succeeded','failed')),
                    result TEXT,
                    error_type TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    CHECK (
                        (state='running' AND result IS NULL AND error_type IS NULL) OR
                        (state='succeeded' AND result IS NOT NULL AND error_type IS NULL) OR
                        (state='failed' AND result IS NULL AND error_type IS NOT NULL)
                    )
                )
            """)
            db.execute("CREATE INDEX IF NOT EXISTS idx_executions_state ON executions(state)")

    def begin(self, execution_id: str) -> None:
        _validate_id(execution_id)
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT COUNT(*) FROM executions").fetchone()[0] >= self._max_records:
                db.rollback()
                raise RuntimeError("execution store capacity reached")
            now = time.time()
            try:
                db.execute(
                    "INSERT INTO executions VALUES (?, 'running', NULL, NULL, ?, ?)",
                    (execution_id, now, now),
                )
            except sqlite3.IntegrityError as exc:
                db.rollback()
                raise DuplicateExecutionError(
                    f"execution already exists: {execution_id}"
                ) from exc
            db.commit()

    def succeed(self, execution_id: str, result: str) -> None:
        _validate_id(execution_id)
        _validate_result(result)
        if len(result) > self._max_result_chars:
            raise ValueError("result exceeds configured persistence limit")
        self._transition(execution_id, "succeeded", result=result.strip(), error_type=None)

    def fail(self, execution_id: str, error: Exception) -> None:
        _validate_id(execution_id)
        self._transition(execution_id, "failed", result=None, error_type=type(error).__name__)

    def get(self, execution_id: str) -> ExecutionRecord | None:
        _validate_id(execution_id)
        with closing(self._connect()) as db:
            row = db.execute(
                "SELECT execution_id,state,result,error_type FROM executions WHERE execution_id=?",
                (execution_id,),
            ).fetchone()
        if row is None:
            return None
        return ExecutionRecord(
            row["execution_id"], ExecutionState(row["state"]), row["result"], row["error_type"]
        )

    def recover_interrupted(self) -> int:
        """Mark records left RUNNING by a prior process as failed."""
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            now = time.time()
            cursor = db.execute(
                "UPDATE executions SET state='failed', error_type='ProcessInterrupted', "
                "updated_at=? WHERE state='running'", (now,),
            )
            changed = cursor.rowcount
            db.commit()
            return changed

    def _transition(
        self, execution_id: str, state: str, *,
        result: str | None, error_type: str | None,
    ) -> None:
        with self._lock, self._connect() as db:
            cursor = db.execute(
                "UPDATE executions SET state=?, result=?, error_type=?, updated_at=? "
                "WHERE execution_id=? AND state='running'",
                (state, result, error_type, time.time(), execution_id),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("execution is missing or not running")


def _validate_id(execution_id: str) -> None:
    if not isinstance(execution_id, str) or not execution_id.strip() or len(execution_id) > 128:
        raise ValueError("execution_id must be 1..128 non-whitespace characters")


def _validate_result(result: str) -> None:
    if not isinstance(result, str) or not result.strip():
        raise ValueError("result must be non-empty text")
