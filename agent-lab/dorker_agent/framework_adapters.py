"""Explicit, synchronous adapters for optional agent frameworks."""
from __future__ import annotations

from typing import Mapping, Protocol

from .capabilities import CapabilityPolicy, DEFAULT_POLICY
from .execution import (
    ExecutionCancelledError, ExecutionControl, ExecutionDeadlineExceeded,
    InMemoryExecutionLedger, SQLiteExecutionStore,
)
from .tasks import TaskRequest


class CrewPort(Protocol):
    def kickoff(self, *, inputs: Mapping[str, str]) -> object: ...


class RunnablePort(Protocol):
    def invoke(self, input: Mapping[str, str]) -> object: ...


class FrameworkExecutionError(RuntimeError):
    """A framework call failed or returned an unsupported response."""


def _task_input(task: TaskRequest) -> dict[str, str]:
    if not isinstance(task, TaskRequest):
        raise TypeError("task must be a TaskRequest")
    return {"title": task.title, "description": task.body, "task_type": task.task_type}


def _response_text(result: object, *, attribute: str | None = None) -> str:
    candidate = result if isinstance(result, str) else (
        getattr(result, attribute, None) if attribute else result
    )
    if not isinstance(candidate, str) or not candidate.strip():
        raise FrameworkExecutionError("framework returned an empty or unsupported response")
    return candidate.strip()


def _invoke_with_ledger(
    invoke,
    *,
    ledger: InMemoryExecutionLedger | SQLiteExecutionStore | None,
    execution_id: str | None,
    control: ExecutionControl | None,
) -> str:
    if (ledger is None) != (execution_id is None):
        raise ValueError("ledger and execution_id must be supplied together")
    if ledger is not None:
        ledger.begin(execution_id)
    try:
        if control is not None:
            control.check()
        result = invoke()
        if control is not None:
            control.check()
        if ledger is not None:
            ledger.succeed(execution_id, result)
        return result
    except Exception as exc:
        if ledger is not None:
            ledger.fail(execution_id, exc)
        raise


class CrewAIAdapter:
    """Invoke one injected CrewAI crew after an explicit capability check."""

    CAPABILITY = "framework:crewai"

    def __init__(
        self,
        crew: CrewPort,
        *,
        policy: CapabilityPolicy = DEFAULT_POLICY,
        ledger: InMemoryExecutionLedger | SQLiteExecutionStore | None = None,
    ) -> None:
        self._crew, self._policy, self._ledger = crew, policy, ledger

    def run(
        self, task: TaskRequest, *, execution_id: str | None = None,
        control: ExecutionControl | None = None,
    ) -> str:
        payload = _task_input(task)
        self._policy.require(self.CAPABILITY)

        def invoke() -> str:
            try:
                if control is None:
                    result = self._crew.kickoff(inputs=payload)
                else:
                    contextual = getattr(self._crew, "kickoff_with_context", None)
                    if not callable(contextual):
                        raise TypeError("controlled execution requires kickoff_with_context(inputs, control)")
                    result = contextual(inputs=payload, control=control)
                return _response_text(result, attribute="raw")
            except (ExecutionCancelledError, ExecutionDeadlineExceeded):
                raise
            except FrameworkExecutionError:
                raise
            except Exception as exc:
                raise FrameworkExecutionError("CrewAI execution failed") from exc

        return _invoke_with_ledger(
            invoke, ledger=self._ledger, execution_id=execution_id, control=control
        )


class LangChainAdapter:
    """Invoke one injected LangChain Runnable after an explicit capability check."""

    CAPABILITY = "framework:langchain"

    def __init__(
        self,
        runnable: RunnablePort,
        *,
        policy: CapabilityPolicy = DEFAULT_POLICY,
        ledger: InMemoryExecutionLedger | SQLiteExecutionStore | None = None,
    ) -> None:
        self._runnable, self._policy, self._ledger = runnable, policy, ledger

    def run(
        self, task: TaskRequest, *, execution_id: str | None = None,
        control: ExecutionControl | None = None,
    ) -> str:
        payload = _task_input(task)
        self._policy.require(self.CAPABILITY)

        def invoke() -> str:
            try:
                if control is None:
                    result = self._runnable.invoke(payload)
                else:
                    contextual = getattr(self._runnable, "invoke_with_context", None)
                    if not callable(contextual):
                        raise TypeError("controlled execution requires invoke_with_context(input, control)")
                    result = contextual(input=payload, control=control)
                return _response_text(result, attribute="content")
            except (ExecutionCancelledError, ExecutionDeadlineExceeded):
                raise
            except FrameworkExecutionError:
                raise
            except Exception as exc:
                raise FrameworkExecutionError("LangChain execution failed") from exc

        return _invoke_with_ledger(
            invoke, ledger=self._ledger, execution_id=execution_id, control=control
        )
