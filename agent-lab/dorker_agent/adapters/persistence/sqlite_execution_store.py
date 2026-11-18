"""Durable single-host SQLite execution ledger adapter."""
from __future__ import annotations

import sqlite3
import time
from contextlib import closing
from pathlib import Path
from threading import RLock

from ...application.errors import DuplicateExecutionError
from ...domain.execution import (
    ExecutionRecord,
    ExecutionState,
    validate_execution_id,
    validate_execution_result,
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
        validate_execution_id(execution_id)
        with self._lock, closing(self._connect()) as db:
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
        validate_execution_id(execution_id)
        validate_execution_result(result)
        if len(result) > self._max_result_chars:
            raise ValueError("result exceeds configured persistence limit")
        self._transition(execution_id, "succeeded", result=result.strip(), error_type=None)

    def fail(self, execution_id: str, error: Exception) -> None:
        validate_execution_id(execution_id)
        self._transition(execution_id, "failed", result=None, error_type=type(error).__name__)

    def get(self, execution_id: str) -> ExecutionRecord | None:
        validate_execution_id(execution_id)
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
        with self._lock, closing(self._connect()) as db:
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
        with self._lock, closing(self._connect()) as db:
            cursor = db.execute(
                "UPDATE executions SET state=?, result=?, error_type=?, updated_at=? "
                "WHERE execution_id=? AND state='running'",
                (state, result, error_type, time.time(), execution_id),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("execution is missing or not running")
