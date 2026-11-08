import sys
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dorker_agent.execution import InMemoryExecutionLedger, ExecutionState, ExecutionControl
from dorker_agent.isolated_worker import (
    IsolatedWorkerRunner,
    WorkerCancelledError,
    WorkerHandlerError,
    WorkerOutputLimitError,
    WorkerTimeoutError,
)


def echo_handler(context, payload):
    context.check()
    return {"echo": payload["value"]}


def slow_handler(context, payload):
    time.sleep(payload.get("seconds", 2))
    return "finished"


def cooperative_handler(context, payload):
    while True:
        context.check()
        time.sleep(0.01)


def large_handler(context, payload):
    return "x" * payload["size"]


def failing_handler(context, payload):
    raise RuntimeError("sensitive detail must not cross process boundary")


class IsolatedWorkerTests(unittest.TestCase):
    def _runner(self, **kwargs):
        return IsolatedWorkerRunner({
            "echo": echo_handler,
            "slow": slow_handler,
            "cooperative": cooperative_handler,
            "large": large_handler,
            "fail": failing_handler,
        }, **kwargs)

    def test_spawn_worker_returns_json_value_and_updates_ledger(self):
        ledger = InMemoryExecutionLedger()
        runner = self._runner()
        result = runner.run(
            "echo", {"value": "ok"}, timeout_seconds=5,
            execution_id="isolated-1", ledger=ledger,
        )
        self.assertEqual(result, {"echo": "ok"})
        record = ledger.get("isolated-1")
        self.assertEqual(record.state, ExecutionState.SUCCEEDED)
        self.assertEqual(record.result, '{"echo":"ok"}')

    def test_hard_timeout_terminates_and_reaps_worker(self):
        runner = self._runner(terminate_grace_seconds=0.05)
        started = time.monotonic()
        with self.assertRaises(WorkerTimeoutError):
            runner.run("slow", {"seconds": 5}, timeout_seconds=0.15)
        self.assertLess(time.monotonic() - started, 3)

    def test_external_cancellation_terminates_worker(self):
        runner = self._runner(terminate_grace_seconds=0.05)
        control = ExecutionControl()
        errors = []

        def invoke():
            try:
                runner.run(
                    "cooperative", {}, timeout_seconds=5, control=control
                )
            except Exception as exc:
                errors.append(exc)

        thread = threading.Thread(target=invoke)
        thread.start()
        time.sleep(0.2)
        control.cancel()
        thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], WorkerCancelledError)

    def test_output_limit_is_enforced(self):
        runner = self._runner(max_output_bytes=128)
        with self.assertRaises(WorkerOutputLimitError):
            runner.run("large", {"size": 1000}, timeout_seconds=5)

    def test_handler_exception_does_not_expose_message(self):
        runner = self._runner()
        with self.assertRaises(WorkerHandlerError) as caught:
            runner.run("fail", {}, timeout_seconds=5)
        self.assertNotIn("sensitive detail", str(caught.exception))

    def test_unknown_handler_rejected_before_start(self):
        runner = self._runner()
        with self.assertRaises(ValueError):
            runner.run("not-registered", {}, timeout_seconds=1)

    def test_payload_size_and_json_safety_are_enforced(self):
        runner = self._runner(max_payload_bytes=16)
        with self.assertRaises(ValueError):
            runner.run("echo", {"value": "this is too long"}, timeout_seconds=1)
        with self.assertRaises(ValueError):
            runner.run("echo", {"value": float("nan")}, timeout_seconds=1)


if __name__ == "__main__":
    unittest.main()
