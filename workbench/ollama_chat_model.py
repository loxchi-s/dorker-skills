"""Ollama adapter for the Dorker Agent Lab ChatModel port."""

from __future__ import annotations

import http.client
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Sequence

from dorker_agent import ModelMessage


@dataclass(frozen=True, slots=True)
class ModelResponse:
    text: str
    done_reason: str | None
    prompt_eval_count: int | None
    eval_count: int | None


class OllamaChatModel:
    """Translate the Agent Lab message contract into Ollama /api/generate calls.

    The adapter is request-scoped: response metadata belongs to this instance,
    so parallel Agent invocations must use separate adapter instances.
    """

    def __init__(
        self,
        *,
        model: str,
        base_url: str,
        timeout_seconds: float,
        num_ctx: int,
        num_predict: int,
        keep_alive: str = "5m",
    ) -> None:
        if not model.strip():
            raise ValueError("model must not be empty")
        if not base_url.startswith(("http://", "https://")):
            raise ValueError("base_url must be an HTTP(S) URL")
        if timeout_seconds <= 0 or num_ctx <= 0 or num_predict <= 0:
            raise ValueError("timeout and token limits must be positive")
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds
        self._num_ctx = num_ctx
        self._num_predict = num_predict
        self._keep_alive = keep_alive
        self.last_response: ModelResponse | None = None

    def complete(self, messages: Sequence[ModelMessage]) -> str:
        """Complete one system/user exchange through the local Ollama endpoint."""
        system_parts: list[str] = []
        user_parts: list[str] = []
        for message in messages:
            if not isinstance(message, ModelMessage):
                raise TypeError("messages must contain ModelMessage values")
            if not isinstance(message.content, str) or not message.content.strip():
                raise ValueError("message content must not be empty")
            if message.role == "system":
                system_parts.append(message.content)
            elif message.role == "user":
                user_parts.append(message.content)
            else:
                raise ValueError(f"Ollama generate adapter does not support role: {message.role}")

        if len(system_parts) != 1 or not user_parts:
            raise ValueError("Ollama requires exactly one system message and at least one user message")

        payload = {
            "model": self._model,
            "system": system_parts[0],
            "prompt": "\n\n".join(user_parts),
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_ctx": self._num_ctx,
                "num_predict": self._num_predict,
            },
            "keep_alive": self._keep_alive,
        }
        request = urllib.request.Request(
            f"{self._base_url}/api/generate",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout_seconds) as response:
                body = json.loads(response.read(2_000_000))
        except (
            urllib.error.URLError,
            http.client.HTTPException,
            TimeoutError,
            OSError,
            ValueError,
        ) as exc:
            raise RuntimeError(f"Local model request failed: {exc}") from exc

        if not isinstance(body, dict):
            raise RuntimeError("Local model returned a non-object JSON response")
        result = body.get("response")
        if not isinstance(result, str) or not result.strip():
            raise RuntimeError("Local model returned an empty or invalid response")

        done_reason = body.get("done_reason")
        prompt_eval_count = body.get("prompt_eval_count")
        eval_count = body.get("eval_count")
        self.last_response = ModelResponse(
            text=result.strip(),
            done_reason=done_reason if isinstance(done_reason, str) else None,
            prompt_eval_count=(
                prompt_eval_count
                if isinstance(prompt_eval_count, int) and not isinstance(prompt_eval_count, bool)
                else None
            ),
            eval_count=(
                eval_count
                if isinstance(eval_count, int) and not isinstance(eval_count, bool)
                else None
            ),
        )
        return self.last_response.text
