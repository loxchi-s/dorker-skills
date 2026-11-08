"""Validated task envelope for GitHub Issue intake."""

from dataclasses import dataclass


ALLOWED_TASK_TYPES = frozenset({"bug", "feature", "refactor", "test", "review"})


@dataclass(frozen=True, slots=True)
class TaskRequest:
    title: str
    body: str
    task_type: str = "feature"

    def __post_init__(self) -> None:
        if not self.title.strip():
            raise ValueError("title must not be empty")
        if len(self.title) > 200:
            raise ValueError("title exceeds 200 characters")
        if not self.body.strip():
            raise ValueError("body must not be empty")
        if len(self.body) > 20_000:
            raise ValueError("body exceeds 20000 characters")
        if self.task_type not in ALLOWED_TASK_TYPES:
            raise ValueError("unsupported task_type")
