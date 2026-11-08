"""Multiprocess safety and abrupt-process recovery tests for SQLite storage."""
import multiprocessing
import os
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dorker_agent.execution import (
    DuplicateExecutionError,
    ExecutionState,
    SQLiteExecutionStore,
)


def _race_claim(database, barrier, outcomes):
    store = SQLiteExecutionStore(database, busy_timeout_ms=15_000)
    barrier.wait(timeout=20)
    try:
        store.begin("shared-job")
    except DuplicateExecutionError:
        outcomes.put("duplicate")
    except Exception as exc:  # surfaced to the parent as a test failure
        outcomes.put(f"error:{type(exc).__name__}:{exc}")
    else:
        outcomes.put("claimed")


def _complete_batch(database, worker_id, count, outcomes):
    store = SQLiteExecutionStore(database, max_records=256, busy_timeout_ms=15_000)
    try:
        for index in range(count):
            execution_id = f"worker-{worker_id}-job-{index}"
            store.begin(execution_id)
            store.succeed(execution_id, "ok")
    except Exception as exc:
        outcomes.put(f"error:{type(exc).__name__}:{exc}")
    else:
        outcomes.put("completed")


def _crash_after_begin(database, ready):
    store = SQLiteExecutionStore(database, busy_timeout_ms=15_000)
    store.begin("crashed-job")
    ready.set()
    os._exit(17)


class SQLiteMultiprocessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.temp.name) / "executions.sqlite3")
        SQLiteExecutionStore(self.db, max_records=256)

    def tearDown(self):
        self.temp.cleanup()

    def _join_all(self, processes, timeout=40):
        for process in processes:
            process.join(timeout)
        alive = [process for process in processes if process.is_alive()]
        for process in alive:
            process.terminate()
            process.join(5)
        self.assertFalse(alive, "multiprocess worker timed out")
        self.assertTrue(all(p.exitcode == 0 for p in processes),
                        f"unexpected worker exit codes: {[p.exitcode for p in processes]}")

    def test_same_execution_id_is_claimed_by_exactly_one_process(self):
        ctx = multiprocessing.get_context("spawn")
        barrier = ctx.Barrier(6)
        outcomes = ctx.Queue()
        processes = [
            ctx.Process(target=_race_claim, args=(self.db, barrier, outcomes))
            for _ in range(6)
        ]
        for process in processes:
            process.start()
        self._join_all(processes)
        results = [outcomes.get(timeout=5) for _ in processes]
        self.assertEqual(results.count("claimed"), 1, results)
        self.assertEqual(results.count("duplicate"), 5, results)
        self.assertFalse(any(value.startswith("error:") for value in results), results)

    def test_distinct_jobs_complete_across_processes(self):
        ctx = multiprocessing.get_context("spawn")
        outcomes = ctx.Queue()
        worker_count = 4
        jobs_per_worker = 10
        processes = [
            ctx.Process(
                target=_complete_batch,
                args=(self.db, worker, jobs_per_worker, outcomes),
            )
            for worker in range(worker_count)
        ]
        for process in processes:
            process.start()
        self._join_all(processes)
        results = [outcomes.get(timeout=5) for _ in processes]
        self.assertEqual(results.count("completed"), worker_count, results)
        self.assertFalse(any(value.startswith("error:") for value in results), results)

        store = SQLiteExecutionStore(self.db, max_records=256)
        for worker in range(worker_count):
            for index in range(jobs_per_worker):
                record = store.get(f"worker-{worker}-job-{index}")
                self.assertEqual(record.state, ExecutionState.SUCCEEDED)

    def test_abrupt_process_exit_is_recovered_without_replay(self):
        ctx = multiprocessing.get_context("spawn")
        ready = ctx.Event()
        process = ctx.Process(target=_crash_after_begin, args=(self.db, ready))
        process.start()
        self.assertTrue(ready.wait(20), "worker did not commit its running record")
        process.join(20)
        self.assertEqual(process.exitcode, 17)

        store = SQLiteExecutionStore(self.db, max_records=256)
        self.assertEqual(store.recover_interrupted(), 1)
        record = store.get("crashed-job")
        self.assertEqual(record.state, ExecutionState.FAILED)
        self.assertEqual(record.error_type, "ProcessInterrupted")
        with self.assertRaises(DuplicateExecutionError):
            store.begin("crashed-job")


if __name__ == "__main__":
    unittest.main()
