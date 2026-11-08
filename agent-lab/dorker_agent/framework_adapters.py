"""Explicit, synchronous adapters for optional agent frameworks.

Framework packages are not imported here. Callers inject already-constructed
framework objects; Dorker checks capability policy before invoking them.
"""
from __future__ import annotations

from typing import Mapping, Protocol

from .capabilities import CapabilityPolicy, DEFAULT_POLICY
from .tasks import TaskRequest


class CrewPort(Protocol):
    def kickoff(self, *, inputs: Mapping[str, str]) -> object:
        """Run a preconfigured CrewAI crew."""


class RunnablePort(Protocol):
    def invoke(self, input: Mapping[str, str]) -> object:
        """Invoke a preconfigured LangChain runnable."""


class FrameworkExecutionError(RuntimeError):
    """A framework call failed or returned an unsupported response."""


def _task_input(task: TaskRequest) -> dict[str, str]:
    if not isinstance(task, TaskRequest):
        raise TypeError("task must be a TaskRequest")
    return {
        "title": task.title,
        "description": task.body,
        "task_type": task.task_type,
    }


def _response_text(result: object, *, attribute: str | None = None) -> str:
    candidate = getattr(result, attribute, None) if attribute else result
    if not isinstance(candidate, str) or not candidate.strip():
        raise FrameworkExecutionError("framework returned an empty or unsupported response")
    return candidate.strip()


class CrewAIAdapter:
    """Invoke one injected CrewAI crew after an explicit capability check."""

    CAPABILITY = "framework:crewai"

    def __init__(
        self,
        crew: CrewPort,
        *,
        policy: CapabilityPolicy = DEFAULT_POLICY,
    ) -> None:
        self._crew = crew
        self._policy = policy

    def run(self, task: TaskRequest) -> str:
        payload = _task_input(task)
        self._policy.require(self.CAPABILITY)
        try:
            result = self._crew.kickoff(inputs=payload)
        except Exception as exc:
            raise FrameworkExecutionError("CrewAI execution failed") from exc
        return _response_text(result, attribute="raw")


class LangChainAdapter:
    """Invoke one injected LangChain Runnable after an explicit capability check."""

    CAPABILITY = "framework:langchain"

    def __init__(
        self,
        runnable: RunnablePort,
        *,
        policy: CapabilityPolicy = DEFAULT_POLICY,
    ) -> None:
        self._runnable = runnable
        self._policy = policy

    def run(self, task: TaskRequest) -> str:
        payload = _task_input(task)
        self._policy.require(self.CAPABILITY)
        try:
            result = self._runnable.invoke(payload)
        except Exception as exc:
            raise FrameworkExecutionError("LangChain execution failed") from exc
        return _response_text(result, attribute="content")
