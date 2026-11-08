import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dorker_agent.execution import (
    DuplicateExecutionError,
    ExecutionState,
    ExecutionControl,
    ExecutionCancelledError,
    ExecutionDeadlineExceeded,
    InMemoryExecutionLedger,
)


class ExecutionLedgerTests(unittest.TestCase):
    def test_lifecycle(self):
        ledger = InMemoryExecutionLedger()
        ledger.begin("task-1")
        self.assertEqual(ledger.get("task-1").state, ExecutionState.RUNNING)
        ledger.succeed("task-1", "done")
        record = ledger.get("task-1")
        self.assertEqual(record.state, ExecutionState.SUCCEEDED)
        self.assertEqual(record.result, "done")

    def test_duplicate_claim_rejected(self):
        ledger = InMemoryExecutionLedger()
        ledger.begin("task-1")
        with self.assertRaises(DuplicateExecutionError):
            ledger.begin("task-1")

    def test_failure_records_type_only(self):
        ledger = InMemoryExecutionLedger()
        ledger.begin("task-2")
        ledger.fail("task-2", ValueError("do not persist this message"))
        record = ledger.get("task-2")
        self.assertEqual(record.state, ExecutionState.FAILED)
        self.assertEqual(record.error_type, "ValueError")
        self.assertIsNone(record.result)

    def test_terminal_state_cannot_transition_again(self):
        ledger = InMemoryExecutionLedger()
        ledger.begin("task-3")
        ledger.succeed("task-3", "done")
        with self.assertRaises(RuntimeError):
            ledger.fail("task-3", RuntimeError())

    def test_capacity_is_bounded(self):
        ledger = InMemoryExecutionLedger(max_records=1)
        ledger.begin("task-1")
        with self.assertRaises(RuntimeError):
            ledger.begin("task-2")

    def test_invalid_ids_rejected(self):
        ledger = InMemoryExecutionLedger()
        with self.assertRaises(ValueError):
            ledger.begin(" ")


    def test_control_cancellation_is_observed(self):
        control = ExecutionControl()
        control.cancel()
        self.assertTrue(control.cancelled)
        with self.assertRaises(ExecutionCancelledError):
            control.check()

    def test_control_deadline_uses_monotonic_clock(self):
        import time

        control = ExecutionControl(timeout_seconds=0.01)
        self.assertGreaterEqual(control.remaining_seconds(), 0)
        time.sleep(0.02)
        self.assertEqual(control.remaining_seconds(), 0)
        with self.assertRaises(ExecutionDeadlineExceeded):
            control.check()

    def test_control_rejects_invalid_timeout(self):
        for value in (0, -1, True, "1", float("nan"), float("inf")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                ExecutionControl(timeout_seconds=value)


if __name__ == "__main__":
    unittest.main()
