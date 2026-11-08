from __future__ import annotations

import unittest

from dorker_agent.container_sandbox import (
    ContainerExitError,
    ContainerOutputLimitError,
    ContainerResult,
    ContainerSandboxConfig,
    ContainerSandboxRunner,
    Mount,
)
from dorker_agent.execution import (
    ExecutionCancelledError,
    ExecutionControl,
    ExecutionState,
    InMemoryExecutionLedger,
)

IMAGE = "registry.example/dorker-worker@sha256:" + "a" * 64


class FakeRuntime:
    def __init__(self, result=None, error=None):
        self.result = result or ContainerResult(0, b"ok", b"")
        self.error = error
        self.calls = []

    def run_container(self, config, *, timeout_seconds, control):
        self.calls.append((config, timeout_seconds, control))
        if self.error:
            raise self.error
        return self.result


class ContainerSandboxConfigTests(unittest.TestCase):
    def test_restrictive_defaults_and_digest_pin(self):
        config = ContainerSandboxConfig(image=IMAGE, command=("python", "-I", "main.py"))
        self.assertEqual(config.user_uid, 10000)
        self.assertEqual(config.user_gid, 10000)
        self.assertEqual(config.mounts, ())

    def test_rejects_mutable_image_and_root_user(self):
        with self.assertRaises(ValueError):
            ContainerSandboxConfig(image="python:latest", command=("python",))
        with self.assertRaises(ValueError):
            ContainerSandboxConfig(image=IMAGE, command=("python",), user_uid=0)

    def test_mount_must_be_within_allowlisted_root(self):
        with self.assertRaises(ValueError):
            ContainerSandboxConfig(
                image=IMAGE, command=("python",),
                allowed_mount_roots=("/workspace",),
                mounts=(Mount("/etc", "/input"),),
            )

    def test_rejects_path_traversal_and_duplicate_targets(self):
        with self.assertRaises(ValueError):
            ContainerSandboxConfig(
                image=IMAGE, command=("python",),
                allowed_mount_roots=("/workspace",),
                mounts=(Mount("/workspace/../etc", "/input"),),
            )
        with self.assertRaises(ValueError):
            ContainerSandboxConfig(
                image=IMAGE, command=("python",),
                allowed_mount_roots=("/workspace",),
                mounts=(Mount("/workspace/a", "/input"), Mount("/workspace/b", "/input")),
            )


class ContainerSandboxRunnerTests(unittest.TestCase):
    def setUp(self):
        self.config = ContainerSandboxConfig(
            image=IMAGE, command=("python", "-I", "main.py"),
            max_output_bytes=8,
        )

    def test_success_and_ledger(self):
        runtime = FakeRuntime(ContainerResult(0, b"done", b""))
        ledger = InMemoryExecutionLedger()
        result = ContainerSandboxRunner(runtime, self.config).run(
            timeout_seconds=2, execution_id="job-1", ledger=ledger
        )
        self.assertEqual(result.stdout, b"done")
        self.assertEqual(ledger.get("job-1").state, ExecutionState.SUCCEEDED)

    def test_nonzero_exit_is_failed(self):
        ledger = InMemoryExecutionLedger()
        runner = ContainerSandboxRunner(
            FakeRuntime(ContainerResult(9, b"", b"failed")), self.config
        )
        with self.assertRaises(ContainerExitError):
            runner.run(timeout_seconds=2, execution_id="job-2", ledger=ledger)
        self.assertEqual(ledger.get("job-2").state, ExecutionState.FAILED)

    def test_output_limit_is_failed(self):
        ledger = InMemoryExecutionLedger()
        runner = ContainerSandboxRunner(
            FakeRuntime(ContainerResult(0, b"123456789", b"")), self.config
        )
        with self.assertRaises(ContainerOutputLimitError):
            runner.run(timeout_seconds=2, execution_id="job-3", ledger=ledger)
        self.assertEqual(ledger.get("job-3").state, ExecutionState.FAILED)

    def test_pre_cancelled_control_does_not_invoke_runtime(self):
        runtime = FakeRuntime()
        control = ExecutionControl()
        control.cancel()
        with self.assertRaises(ExecutionCancelledError):
            ContainerSandboxRunner(runtime, self.config).run(
                timeout_seconds=2, control=control
            )
        self.assertEqual(runtime.calls, [])

    def test_runtime_error_is_recorded(self):
        ledger = InMemoryExecutionLedger()
        runner = ContainerSandboxRunner(
            FakeRuntime(error=RuntimeError("runtime unavailable")), self.config
        )
        with self.assertRaises(RuntimeError):
            runner.run(timeout_seconds=2, execution_id="job-4", ledger=ledger)
        self.assertEqual(ledger.get("job-4").state, ExecutionState.FAILED)


if __name__ == "__main__":
    unittest.main()
