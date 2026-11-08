"""Minimal agent orchestration with no implicit tool execution."""

from dataclasses import dataclass
from typing import Protocol, Sequence


@dataclass(frozen=True, slots=True)
class ModelMessage:
    role: str
    content: str


class ChatModel(Protocol):
    def complete(self, messages: Sequence[ModelMessage]) -> str:
        """Return a model-generated response."""


class Agent:
    """Task agent that delegates language generation to an injected model.

    This class deliberately exposes no shell, filesystem, network, or tool APIs.
    """

    def __init__(self, model: ChatModel, *, system_prompt: str) -> None:
        if not system_prompt.strip():
            raise ValueError("system_prompt must not be empty")
        self._model = model
        self._system_prompt = system_prompt

    def run(self, task: str) -> str:
        if not task.strip():
            raise ValueError("task must not be empty")

        messages = (
            ModelMessage("system", self._system_prompt),
            ModelMessage("user", task.strip()),
        )
        result = self._model.complete(messages)
        if not isinstance(result, str) or not result.strip():
            raise RuntimeError("model returned an empty or invalid response")
        return result.strip()
