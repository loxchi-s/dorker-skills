import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dorker_agent.execution import (
    DuplicateExecutionError,
    ExecutionState,
    SQLiteExecutionStore,
)


class SQLiteExecutionStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "state" / "executions.sqlite3"
        self.store = SQLiteExecutionStore(self.db)

    def tearDown(self):
        self.temp.cleanup()

    def test_lifecycle_survives_reopen(self):
        self.store.begin("job-1")
        self.store.succeed("job-1", "completed")
        reopened = SQLiteExecutionStore(self.db)
        record = reopened.get("job-1")
        self.assertEqual(record.state, ExecutionState.SUCCEEDED)
        self.assertEqual(record.result, "completed")

    def test_duplicate_execution_id_rejected_across_instances(self):
        self.store.begin("job-2")
        other = SQLiteExecutionStore(self.db)
        with self.assertRaises(DuplicateExecutionError):
            other.begin("job-2")

    def test_interrupted_work_is_marked_failed_not_replayed(self):
        self.store.begin("job-3")
        reopened = SQLiteExecutionStore(self.db)
        self.assertEqual(reopened.recover_interrupted(), 1)
        record = self.store.get("job-3")
        self.assertEqual(record.state, ExecutionState.FAILED)
        self.assertEqual(record.error_type, "ProcessInterrupted")
        with self.assertRaises(DuplicateExecutionError):
            reopened.begin("job-3")

    def test_failure_does_not_persist_exception_message(self):
        self.store.begin("job-4")
        self.store.fail("job-4", ValueError("secret token"))
        record = self.store.get("job-4")
        self.assertEqual(record.error_type, "ValueError")
        self.assertIsNone(record.result)

    def test_result_size_is_bounded(self):
        store = SQLiteExecutionStore(self.db, max_result_chars=4)
        store.begin("job-5")
        with self.assertRaises(ValueError):
            store.succeed("job-5", "12345")
        self.assertEqual(store.get("job-5").state, ExecutionState.RUNNING)

    def test_capacity_is_bounded(self):
        store = SQLiteExecutionStore(self.db, max_records=1)
        store.begin("job-6")
        with self.assertRaises(RuntimeError):
            store.begin("job-7")

    def test_memory_database_rejected(self):
        with self.assertRaises(ValueError):
            SQLiteExecutionStore(":memory:")


if __name__ == "__main__":
    unittest.main()
