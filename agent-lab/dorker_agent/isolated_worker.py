"""Spawn-isolated execution for explicitly registered, trusted handlers.

This is process isolation for termination, not an OS security sandbox.
"""
from __future__ import annotations

import json
import math
import multiprocessing
import os
import signal
import time
from dataclasses import dataclass
from multiprocessing.connection import Connection
from typing import Any, Callable, Mapping

from .execution import (
    ExecutionCancelledError,
    ExecutionControl,
    ExecutionDeadlineExceeded,
    InMemoryExecutionLedger,
    SQLiteExecutionStore,
)

WorkerHandler = Callable[["WorkerContext", Mapping[str, Any]], Any]
Ledger = InMemoryExecutionLedger | SQLiteExecutionStore


class WorkerError(RuntimeError):
    """Base class for isolated worker failures."""


class WorkerTimeoutError(WorkerError, TimeoutError):
    """The worker exceeded its hard wall-clock deadline."""


class WorkerCancelledError(WorkerError):
    """The worker was cancelled and reaped."""


class WorkerCrashedError(WorkerError):
    """The worker exited without a valid response."""


class WorkerHandlerError(WorkerError):
    """A registered handler raised an exception."""


class WorkerOutputLimitError(WorkerError):
    """The handler response exceeded the configured output limit."""


@dataclass(frozen=True)
class ResourceLimits:
    """Optional POSIX rlimits applied before handler code starts."""

    cpu_seconds: int | None = None
    address_space_bytes: int | None = None
    open_files: int | None = None
    file_size_bytes: int | None = None

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or value < 1
            ):
                raise ValueError(f"{name} must be a positive integer or None")


def _apply_resource_limits(limits: ResourceLimits | None) -> None:
    if limits is None:
        return
    if os.name != "posix":
        raise RuntimeError("POSIX resource limits are unavailable on this platform")
    import resource

    for field, resource_id in (
        ("cpu_seconds", resource.RLIMIT_CPU),
        ("address_space_bytes", resource.RLIMIT_AS),
        ("open_files", resource.RLIMIT_NOFILE),
        ("file_size_bytes", resource.RLIMIT_FSIZE),
    ):
        value = getattr(limits, field)
        if value is not None:
            resource.setrlimit(resource_id, (value, value))


class WorkerContext:
    """Cooperative context exposed to an isolated handler."""

    def __init__(self, cancel_event: Any, deadline: float | None) -> None:
        self._cancel_event = cancel_event
        self._deadline = deadline

    @property
    def cancelled(self) -> bool:
        return self._cancel_event.is_set()

    def check(self) -> None:
        if self.cancelled:
            raise ExecutionCancelledError("worker cancelled")
        if self._deadline is not None and time.monotonic() >= self._deadline:
            raise ExecutionDeadlineExceeded("worker deadline exceeded")


def _worker_entry(
    send_conn: Connection,
    handler: WorkerHandler,
    payload: Mapping[str, Any],
    cancel_event: Any,
    deadline: float | None,
    max_output_bytes: int,
    limits: ResourceLimits | None,
    group_ready: Any,
) -> None:
    try:
        if os.name == "posix":
            os.setsid()
        _apply_resource_limits(limits)
        group_ready.set()
        context = WorkerContext(cancel_event, deadline)
        context.check()
        result = handler(context, payload)
        context.check()
        encoded = json.dumps(
            {"ok": True, "result": result},
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) > max_output_bytes:
            send_conn.send_bytes(json.dumps({"ok": False, "error": "WorkerOutputLimitError"}).encode())
        else:
            send_conn.send_bytes(encoded)
    except (ExecutionCancelledError, ExecutionDeadlineExceeded) as exc:
        try:
            send_conn.send_bytes(json.dumps({"ok": False, "error": type(exc).__name__}).encode())
        except (BrokenPipeError, EOFError, OSError):
            pass
    except BaseException as exc:
        try:
            send_conn.send_bytes(json.dumps({"ok": False, "error": type(exc).__name__}).encode())
        except (BrokenPipeError, EOFError, OSError):
            pass
    finally:
        group_ready.set()
        send_conn.close()


class IsolatedWorkerRunner:
    """Run an allowlisted, importable handler in a fresh spawn process.

    Handler code is trusted application code. POSIX process groups and optional
    rlimits provide cleanup/resource ceilings, not a hostile-code sandbox.
    """

    def __init__(
        self,
        handlers: Mapping[str, WorkerHandler],
        *,
        max_payload_bytes: int = 64 * 1024,
        max_output_bytes: int = 256 * 1024,
        poll_interval_seconds: float = 0.025,
        terminate_grace_seconds: float = 0.25,
        resource_limits: ResourceLimits | None = None,
    ) -> None:
        if not isinstance(handlers, Mapping) or not handlers:
            raise ValueError("an explicit non-empty handler allowlist is required")
        validated: dict[str, WorkerHandler] = {}
        for name, handler in handlers.items():
            if (
                not isinstance(name, str)
                or not name
                or len(name) > 64
                or not name.replace("_", "").replace("-", "").isalnum()
                or not callable(handler)
            ):
                raise ValueError("invalid handler registration")
            validated[name] = handler
        for name, value in (
            ("max_payload_bytes", max_payload_bytes),
            ("max_output_bytes", max_output_bytes),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        for name, value in (
            ("poll_interval_seconds", poll_interval_seconds),
            ("terminate_grace_seconds", terminate_grace_seconds),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{name} must be a positive finite number")
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be a positive finite number")
        self._handlers = validated
        self._max_payload_bytes = max_payload_bytes
        self._max_output_bytes = max_output_bytes
        self._poll_interval = float(poll_interval_seconds)
        if resource_limits is not None and not isinstance(resource_limits, ResourceLimits):
            raise TypeError("resource_limits must be ResourceLimits or None")
        if resource_limits is not None and os.name != "posix":
            raise ValueError("resource_limits require a POSIX platform")
        self._terminate_grace = float(terminate_grace_seconds)
        self._resource_limits = resource_limits

    def run(
        self,
        handler_id: str,
        payload: Mapping[str, Any],
        *,
        timeout_seconds: float,
        execution_id: str | None = None,
        control: ExecutionControl | None = None,
        ledger: Ledger | None = None,
    ) -> Any:
        if handler_id not in self._handlers:
            raise ValueError("handler is not allowlisted")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
            raise ValueError("timeout_seconds must be a positive finite number")
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be a positive finite number")
        if (ledger is None) != (execution_id is None):
            raise ValueError("ledger and execution_id must be supplied together")
        if not isinstance(payload, Mapping):
            raise TypeError("payload must be a mapping")
        try:
            payload_bytes = json.dumps(
                payload, ensure_ascii=False, allow_nan=False, separators=(",", ":")
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("payload must contain JSON-safe values") from exc
        if len(payload_bytes) > self._max_payload_bytes:
            raise ValueError("payload exceeds configured size limit")

        if control is not None:
            control.check()
        deadline = time.monotonic() + float(timeout_seconds)
        if ledger is not None:
            ledger.begin(execution_id)

        ctx = multiprocessing.get_context("spawn")
        cancel_event = ctx.Event()
        group_ready = ctx.Event()
        recv_conn, send_conn = ctx.Pipe(duplex=False)
        process = ctx.Process(
            target=_worker_entry,
            args=(
                send_conn, self._handlers[handler_id], dict(payload),
                cancel_event, deadline, self._max_output_bytes,
                self._resource_limits, group_ready,
            ),
            daemon=True,
        )
        failure: Exception | None = None
        result: Any = None
        try:
            process.start()
            send_conn.close()
            while not group_ready.wait(self._poll_interval):
                if time.monotonic() >= deadline:
                    failure = WorkerTimeoutError("worker startup deadline exceeded")
                    break
            while failure is None:
                if control is not None and control.cancelled:
                    cancel_event.set()
                    failure = WorkerCancelledError("worker cancelled")
                    break
                if time.monotonic() >= deadline:
                    cancel_event.set()
                    failure = WorkerTimeoutError("worker deadline exceeded")
                    break
                if recv_conn.poll(self._poll_interval):
                    try:
                        message = recv_conn.recv_bytes(self._max_output_bytes + 1024)
                    except (EOFError, OSError):
                        failure = WorkerCrashedError("worker response channel closed")
                        break
                    try:
                        envelope = json.loads(message.decode("utf-8"))
                        if not isinstance(envelope, dict):
                            raise ValueError
                        if envelope.get("ok") is not True:
                            error_type = envelope.get("error")
                            if error_type == "WorkerOutputLimitError":
                                failure = WorkerOutputLimitError("worker output limit exceeded")
                            elif error_type == "ExecutionCancelledError":
                                failure = WorkerCancelledError("worker cancelled")
                            elif error_type == "ExecutionDeadlineExceeded":
                                failure = WorkerTimeoutError("worker deadline exceeded")
                            else:
                                failure = WorkerHandlerError("registered handler failed")
                        else:
                            result = envelope["result"]
                    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, ValueError, AttributeError):
                        failure = WorkerCrashedError("worker returned an invalid response")
                    break
                if not process.is_alive():
                    if recv_conn.poll():
                        continue
                    failure = WorkerCrashedError("worker exited without a response")
                    break
        except Exception as exc:
            failure = exc
        finally:
            if process.pid is not None:
                if failure is not None:
                    cancel_event.set()
                process.join(self._terminate_grace)
                if os.name == "posix" and group_ready.is_set():
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    process.join(self._terminate_grace)
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    if process.is_alive():
                        process.terminate()
                        process.join(self._terminate_grace)
                        if process.is_alive() and hasattr(process, "kill"):
                            process.kill()
                            process.join(self._terminate_grace)
                elif process.is_alive():
                    process.terminate()
                    process.join(self._terminate_grace)
                    if process.is_alive() and hasattr(process, "kill"):
                        process.kill()
                        process.join(self._terminate_grace)
            if process.pid is not None and process.is_alive():
                failure = WorkerCrashedError("worker could not be reaped")
            recv_conn.close()
            try:
                send_conn.close()
            except OSError:
                pass
            if process.pid is not None:
                process.close()

        if failure is None and control is not None:
            try:
                control.check()
            except ExecutionCancelledError:
                failure = WorkerCancelledError("worker cancelled")
            except ExecutionDeadlineExceeded:
                failure = WorkerTimeoutError("worker deadline exceeded")
        if failure is not None:
            if ledger is not None:
                ledger.fail(execution_id, failure)
            raise failure
        if ledger is not None:
            ledger.succeed(
                execution_id,
                json.dumps(result, ensure_ascii=False, allow_nan=False, separators=(",", ":")),
            )
        return result
