"""OCI container sandbox contract.

The runner delegates to an injected trusted runtime port. This module does not
connect to a Docker socket or claim isolation until a real runtime is integrated
and tested on the target host.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Protocol, Sequence

from .execution import (
    ExecutionCancelledError,
    ExecutionControl,
    ExecutionDeadlineExceeded,
    InMemoryExecutionLedger,
    SQLiteExecutionStore,
)

_DIGEST_IMAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:+-]*@sha256:[0-9a-f]{64}$")


class ContainerSandboxError(RuntimeError):
    """Base error for container sandbox failures."""


class ContainerExitError(ContainerSandboxError):
    """The container process exited unsuccessfully."""


class ContainerOutputLimitError(ContainerSandboxError):
    """The runtime returned output beyond the configured bound."""


@dataclass(frozen=True, slots=True)
class Mount:
    """Explicit host-to-container mount; read-only unless opted in."""

    source: str
    target: str
    read_only: bool = True


@dataclass(frozen=True, slots=True)
class ContainerSandboxConfig:
    """Immutable, restrictive OCI execution policy."""

    image: str
    command: tuple[str, ...]
    allowed_mount_roots: tuple[str, ...] = ()
    mounts: tuple[Mount, ...] = ()
    user_uid: int = 10000
    user_gid: int = 10000
    memory_bytes: int = 512 * 1024 * 1024
    cpu_limit: float = 1.0
    pids_limit: int = 64
    tmpfs_bytes: int = 64 * 1024 * 1024
    max_output_bytes: int = 256 * 1024

    def __post_init__(self) -> None:
        if not isinstance(self.image, str) or not _DIGEST_IMAGE.fullmatch(self.image):
            raise ValueError("image must be pinned to an immutable sha256 digest")
        if not isinstance(self.command, tuple) or not self.command:
            raise ValueError("command must be a non-empty tuple of arguments")
        if any(not isinstance(arg, str) or not arg or "\x00" in arg for arg in self.command):
            raise ValueError("command arguments must be non-empty strings without NUL")
        if any("\x00" in arg for arg in self.command):
            raise ValueError("invalid command argument")
        for name, value in (
            ("user_uid", self.user_uid), ("user_gid", self.user_gid),
            ("memory_bytes", self.memory_bytes), ("pids_limit", self.pids_limit),
            ("tmpfs_bytes", self.tmpfs_bytes), ("max_output_bytes", self.max_output_bytes),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if self.user_uid == 0 or self.user_gid == 0:
            raise ValueError("container user must be non-root")
        if isinstance(self.cpu_limit, bool) or not isinstance(self.cpu_limit, (int, float)):
            raise ValueError("cpu_limit must be a positive finite number")
        if not math.isfinite(self.cpu_limit) or self.cpu_limit <= 0:
            raise ValueError("cpu_limit must be a positive finite number")

        roots = tuple(_absolute_path(p, "allowed mount root") for p in self.allowed_mount_roots)
        if len(set(roots)) != len(roots):
            raise ValueError("duplicate allowed mount root")
        targets: set[str] = set()
        for mount in self.mounts:
            if not isinstance(mount, Mount):
                raise TypeError("mounts must contain Mount values")
            source = _absolute_path(mount.source, "mount source")
            target = _absolute_path(mount.target, "mount target")
            if target in targets:
                raise ValueError("duplicate container mount target")
            targets.add(target)
            if not any(_is_within(source, root) for root in roots):
                raise ValueError("mount source is outside allowed mount roots")
            if not isinstance(mount.read_only, bool):
                raise ValueError("mount read_only must be boolean")


def _absolute_path(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("/") or "\x00" in value:
        raise ValueError(f"{label} must be an absolute POSIX path")
    path = PurePosixPath(value)
    if ".." in path.parts:
        raise ValueError(f"{label} must not contain parent traversal")
    return str(path)


def _is_within(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


@dataclass(frozen=True, slots=True)
class ContainerResult:
    exit_code: int
    stdout: bytes
    stderr: bytes


class ContainerRuntime(Protocol):
    """Trusted runtime adapter; implementations must stream-bound output."""

    def run_container(
        self, config: ContainerSandboxConfig, *, timeout_seconds: float,
        control: ExecutionControl | None,
    ) -> ContainerResult:
        """Run with the exact policy in config and enforce timeout/cancellation."""
        ...


Ledger = InMemoryExecutionLedger | SQLiteExecutionStore


class ContainerSandboxRunner:
    """Validate policy, invoke a trusted runtime port, and record lifecycle.

    This is a contract/orchestrator, not a concrete Docker/Podman implementation.
    """

    def __init__(self, runtime: ContainerRuntime, config: ContainerSandboxConfig) -> None:
        if not callable(getattr(runtime, "run_container", None)):
            raise TypeError("runtime must implement run_container")
        if not isinstance(config, ContainerSandboxConfig):
            raise TypeError("config must be ContainerSandboxConfig")
        self._runtime = runtime
        self._config = config

    def run(
        self, *, timeout_seconds: float, execution_id: str | None = None,
        control: ExecutionControl | None = None, ledger: Ledger | None = None,
    ) -> ContainerResult:
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
            raise ValueError("timeout_seconds must be a positive finite number")
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be a positive finite number")
        if (ledger is None) != (execution_id is None):
            raise ValueError("ledger and execution_id must be supplied together")
        if control is not None:
            control.check()
        if ledger is not None:
            ledger.begin(execution_id)

        try:
            result = self._runtime.run_container(
                self._config, timeout_seconds=float(timeout_seconds), control=control
            )
            if not isinstance(result, ContainerResult):
                raise ContainerSandboxError("runtime returned an invalid result")
            if not isinstance(result.stdout, bytes) or not isinstance(result.stderr, bytes):
                raise ContainerSandboxError("runtime output must be bytes")
            if len(result.stdout) + len(result.stderr) > self._config.max_output_bytes:
                raise ContainerOutputLimitError("container output limit exceeded")
            if isinstance(result.exit_code, bool) or not isinstance(result.exit_code, int):
                raise ContainerSandboxError("runtime exit code must be an integer")
            if control is not None:
                control.check()
            if result.exit_code != 0:
                raise ContainerExitError(f"container exited with status {result.exit_code}")
            if ledger is not None:
                ledger.succeed(
                    execution_id,
                    result.stdout.decode("utf-8", errors="replace"),
                )
            return result
        except (ExecutionCancelledError, ExecutionDeadlineExceeded,
                ContainerSandboxError, Exception) as exc:
            if ledger is not None:
                ledger.fail(execution_id, exc)
            raise
