"""OCI container sandbox contract and Docker CLI runtime adapter.

The Docker daemon and CLI are trusted infrastructure. Never expose their control
socket or credentials to an agent. This adapter is Linux-host oriented.
"""
from __future__ import annotations

import math
import os
import re
import stat
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Protocol

from .execution import (
    ExecutionControl,
    ExecutionDeadlineExceeded,
    InMemoryExecutionLedger,
    SQLiteExecutionStore,
)

_DIGEST_IMAGE = re.compile(r"^(?:[A-Za-z0-9][A-Za-z0-9._/:+-]*@sha256:[0-9a-f]{64}|sha256:[0-9a-f]{64})$")


class ContainerSandboxError(RuntimeError):
    """Base error for container sandbox failures."""


class ContainerExitError(ContainerSandboxError):
    """The container process exited unsuccessfully."""


class ContainerOutputLimitError(ContainerSandboxError):
    """The runtime emitted output beyond the configured bound."""


@dataclass(frozen=True, slots=True)
class Mount:
    """Host-to-container mount; read-only unless explicitly opted in."""

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
    allow_host_mounts: bool = False
    user_uid: int = 10000
    user_gid: int = 10000
    memory_bytes: int = 512 * 1024 * 1024
    cpu_limit: float = 1.0
    pids_limit: int = 64
    tmpfs_bytes: int = 64 * 1024 * 1024
    max_output_bytes: int = 256 * 1024
    input_payload: bytes = b""
    max_input_bytes: int = 1024 * 1024

    def __post_init__(self) -> None:
        if not isinstance(self.image, str) or not _DIGEST_IMAGE.fullmatch(self.image):
            raise ValueError("image must be a repository digest or local sha256 image ID")
        if not isinstance(self.command, tuple) or not self.command:
            raise ValueError("command must be a non-empty tuple of arguments")
        if any(not isinstance(arg, str) or not arg or "\x00" in arg for arg in self.command):
            raise ValueError("command arguments must be non-empty strings without NUL")
        for name, value in (
            ("user_uid", self.user_uid), ("user_gid", self.user_gid),
            ("memory_bytes", self.memory_bytes), ("pids_limit", self.pids_limit),
            ("tmpfs_bytes", self.tmpfs_bytes), ("max_output_bytes", self.max_output_bytes),
            ("max_input_bytes", self.max_input_bytes),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if not isinstance(self.input_payload, bytes):
            raise ValueError("input_payload must be bytes")
        if len(self.input_payload) > self.max_input_bytes:
            raise ValueError("input payload exceeds max_input_bytes")
        if self.user_uid == 0 or self.user_gid == 0:
            raise ValueError("container user must be non-root")
        if isinstance(self.cpu_limit, bool) or not isinstance(self.cpu_limit, (int, float)):
            raise ValueError("cpu_limit must be a positive finite number")
        if not math.isfinite(self.cpu_limit) or self.cpu_limit <= 0:
            raise ValueError("cpu_limit must be a positive finite number")

        if not isinstance(self.allow_host_mounts, bool):
            raise ValueError("allow_host_mounts must be boolean")
        if self.mounts and not self.allow_host_mounts:
            raise ValueError("host mounts are disabled; set allow_host_mounts=True only for trusted inputs")

        roots = tuple(_absolute_path(p, "allowed mount root") for p in self.allowed_mount_roots)
        if len(set(roots)) != len(roots):
            raise ValueError("duplicate allowed mount root")
        targets: set[str] = set()
        for mount in self.mounts:
            if not isinstance(mount, Mount):
                raise TypeError("mounts must contain Mount values")
            source = _absolute_path(mount.source, "mount source")
            target = _absolute_path(mount.target, "mount target")
            if "," in source or "," in target:
                raise ValueError("mount paths must not contain commas")
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
    def run_container(
        self, config: ContainerSandboxConfig, *, timeout_seconds: float,
        control: ExecutionControl | None,
    ) -> ContainerResult: ...


class DockerCLIContainerRuntime:
    """Run a pinned image through Docker CLI without a shell.

    Requires a trusted local Docker daemon and a preloaded image (--pull=never).
    Output is drained concurrently and retained only up to max_output_bytes.
    """

    def __init__(self, docker_executable: str = "docker") -> None:
        if (not isinstance(docker_executable, str) or not docker_executable
                or "\x00" in docker_executable):
            raise ValueError("docker_executable must be a non-empty executable path")
        self._docker = docker_executable

    def build_argv(self, config: ContainerSandboxConfig, cidfile: str) -> list[str]:
        if not os.path.isabs(cidfile):
            raise ValueError("cidfile path must be absolute")
        argv = [
            self._docker, "run", "--rm", "--pull=never", "--init",
            f"--cidfile={cidfile}",
            "--interactive", "--network=none", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            f"--user={config.user_uid}:{config.user_gid}",
            f"--memory={config.memory_bytes}",
            f"--cpus={config.cpu_limit}",
            f"--pids-limit={config.pids_limit}",
            f"--tmpfs=/tmp:rw,noexec,nosuid,nodev,size={config.tmpfs_bytes}",
            "--workdir=/tmp",
        ]
        for mount in config.mounts:
            source = os.path.realpath(mount.source)
            roots = tuple(os.path.realpath(root) for root in config.allowed_mount_roots)
            if not any(_is_within(source, root) for root in roots):
                raise ValueError("resolved mount source is outside allowed mount roots")
            try:
                mode = os.stat(source).st_mode
            except OSError as exc:
                raise ValueError("mount source does not exist or is inaccessible") from exc
            if stat.S_ISSOCK(mode):
                raise ValueError("Unix sockets cannot be mounted into the container")
            if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                raise ValueError("mount source must be a regular file or directory")
            mount_spec = f"type=bind,src={source},dst={mount.target}"
            if mount.read_only:
                mount_spec += ",readonly"
            argv.append(f"--mount={mount_spec}")
        argv.extend([config.image, *config.command])
        return argv

    def run_container(
        self, config: ContainerSandboxConfig, *, timeout_seconds: float,
        control: ExecutionControl | None,
    ) -> ContainerResult:
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
            raise ValueError("timeout_seconds must be a positive finite number")
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be a positive finite number")

        with tempfile.TemporaryDirectory(prefix="dorker-container-") as tmp:
            cidfile = os.path.join(tmp, "container.id")
            argv = self.build_argv(config, cidfile)
            try:
                process = subprocess.Popen(
                    argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, shell=False, close_fds=True,
                )
            except OSError as exc:
                raise ContainerSandboxError("unable to start Docker CLI") from exc

            output_lock = threading.Lock()
            output_size = 0
            output_overflow = threading.Event()
            stdout_parts: list[bytes] = []
            stderr_parts: list[bytes] = []

            def drain(stream, parts: list[bytes]) -> None:
                nonlocal output_size
                try:
                    while True:
                        chunk = stream.read(8192)
                        if not chunk:
                            break
                        with output_lock:
                            remaining = config.max_output_bytes - output_size
                            if len(chunk) > remaining:
                                output_overflow.set()
                            if remaining > 0:
                                parts.append(chunk[:remaining])
                                output_size += min(len(chunk), remaining)
                finally:
                    stream.close()

            out_thread = threading.Thread(target=drain, args=(process.stdout, stdout_parts), daemon=True)
            err_thread = threading.Thread(target=drain, args=(process.stderr, stderr_parts), daemon=True)
            out_thread.start()
            err_thread.start()

            def feed_stdin() -> None:
                try:
                    if process.stdin is not None:
                        view = memoryview(config.input_payload)
                        for offset in range(0, len(view), 65536):
                            process.stdin.write(view[offset:offset + 65536])
                        process.stdin.flush()
                except (BrokenPipeError, OSError):
                    pass
                finally:
                    if process.stdin is not None:
                        try:
                            process.stdin.close()
                        except OSError:
                            pass

            input_thread = threading.Thread(target=feed_stdin, daemon=True)
            input_thread.start()
            deadline = time.monotonic() + float(timeout_seconds)
            forced_stop = False
            try:
                while process.poll() is None:
                    if output_overflow.is_set():
                        forced_stop = True
                        self._stop_container(cidfile)
                        process.kill()
                        raise ContainerOutputLimitError("container output limit exceeded")
                    if control is not None:
                        try:
                            control.check()
                        except Exception:
                            forced_stop = True
                            self._stop_container(cidfile)
                            process.kill()
                            raise
                    if time.monotonic() >= deadline:
                        forced_stop = True
                        self._stop_container(cidfile)
                        process.kill()
                        raise ExecutionDeadlineExceeded("container execution deadline exceeded")
                    time.sleep(0.025)
                process.wait()
            finally:
                if process.poll() is None:
                    forced_stop = True
                    self._stop_container(cidfile)
                    process.kill()
                process.wait()
                input_thread.join(timeout=2)
                out_thread.join(timeout=2)
                err_thread.join(timeout=2)
                if forced_stop:
                    self._stop_container(cidfile)

            if output_overflow.is_set():
                raise ContainerOutputLimitError("container output limit exceeded")
            result = ContainerResult(
                process.returncode,
                b"".join(stdout_parts),
                b"".join(stderr_parts),
            )
            if result.exit_code != 0:
                raise ContainerExitError(f"container exited with status {result.exit_code}")
            return result

    def _stop_container(self, cidfile: str) -> None:
        try:
            with open(cidfile, "r", encoding="ascii") as handle:
                container_id = handle.read(128).strip()
        except OSError:
            return
        if not re.fullmatch(r"[0-9a-f]{12,64}", container_id):
            return
        try:
            subprocess.run(
                [self._docker, "kill", container_id],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, shell=False, check=False, timeout=3,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass


Ledger = InMemoryExecutionLedger | SQLiteExecutionStore


class ContainerSandboxRunner:
    """Validate policy, invoke runtime, and record execution lifecycle."""

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
                    result.stdout.decode("utf-8", errors="replace") or "<empty>",
                )
            return result
        except Exception as exc:
            if ledger is not None:
                ledger.fail(execution_id, exc)
            raise
