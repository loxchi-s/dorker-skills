"""Cooperative cancellation and monotonic deadline control."""
from __future__ import annotations

import math
import time
from threading import Event

from .errors import ExecutionCancelledError, ExecutionDeadlineExceeded


class ExecutionControl:
    """Thread-safe cooperative cancellation and monotonic deadline control.

    This cannot forcibly stop a blocking framework call. Injected ports must
    poll check() to observe cancellation or deadline expiry while running.
    """

    def __init__(self, *, timeout_seconds: float | None = None) -> None:
        if timeout_seconds is not None:
            if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
                raise ValueError("timeout_seconds must be a positive number")
            if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
                raise ValueError("timeout_seconds must be a finite positive number")
        self._deadline = (
            time.monotonic() + float(timeout_seconds)
            if timeout_seconds is not None else None
        )
        self._cancelled = Event()

    def cancel(self) -> None:
        self._cancelled.set()

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def remaining_seconds(self) -> float | None:
        if self._deadline is None:
            return None
        return max(0.0, self._deadline - time.monotonic())

    def check(self) -> None:
        if self._cancelled.is_set():
            raise ExecutionCancelledError("execution was cancelled")
        if self._deadline is not None and time.monotonic() >= self._deadline:
            raise ExecutionDeadlineExceeded("execution deadline exceeded")
