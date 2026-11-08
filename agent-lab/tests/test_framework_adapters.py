import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dorker_agent.capabilities import CapabilityPolicy
from dorker_agent.framework_adapters import CrewAIAdapter, FrameworkExecutionError, LangChainAdapter
from dorker_agent.tasks import TaskRequest
from dorker_agent.execution import (
    DuplicateExecutionError, ExecutionState, InMemoryExecutionLedger, SQLiteExecutionStore,
    ExecutionControl, ExecutionCancelledError, ExecutionDeadlineExceeded,
)

TASK = TaskRequest("Fix parser", "Parser fails on empty input.", "bug")


class CrewOutput:
    raw = "Crew plan"


class FakeCrew:
    def __init__(self, result=None, error=None):
        self.result = result if result is not None else CrewOutput()
        self.error, self.calls, self.inputs = error, 0, None

    def kickoff(self, *, inputs):
        self.calls += 1
        self.inputs = inputs
        if self.error:
            raise self.error
        return self.result


class AIMessage:
    content = "Runnable result"


class FakeRunnable:
    def __init__(self, result=None, error=None):
        self.result = result if result is not None else AIMessage()
        self.error, self.calls, self.input = error, 0, None

    def invoke(self, input):
        self.calls += 1
        self.input = input
        if self.error:
            raise self.error
        return self.result



class ControlledRunnable:
    def __init__(self, action):
        self.action = action
        self.calls = 0

    def invoke_with_context(self, *, input, control):
        self.calls += 1
        return self.action(control)


class FrameworkAdapterTests(unittest.TestCase):
    def test_crewai_denied_by_default_without_invocation(self):
        crew = FakeCrew()
        with self.assertRaises(PermissionError):
            CrewAIAdapter(crew).run(TASK)
        self.assertEqual(crew.calls, 0)

    def test_crewai_explicit_capability_and_task_mapping(self):
        crew = FakeCrew()
        policy = CapabilityPolicy(frozenset({CrewAIAdapter.CAPABILITY}))
        self.assertEqual(CrewAIAdapter(crew, policy=policy).run(TASK), "Crew plan")
        self.assertEqual(crew.inputs["task_type"], "bug")
        self.assertEqual(crew.inputs["description"], TASK.body)

    def test_langchain_denied_by_default_without_invocation(self):
        runnable = FakeRunnable()
        with self.assertRaises(PermissionError):
            LangChainAdapter(runnable).run(TASK)
        self.assertEqual(runnable.calls, 0)

    def test_langchain_explicit_capability(self):
        runnable = FakeRunnable()
        policy = CapabilityPolicy(frozenset({LangChainAdapter.CAPABILITY}))
        self.assertEqual(LangChainAdapter(runnable, policy=policy).run(TASK), "Runnable result")
        self.assertEqual(runnable.input["task_type"], "bug")

    def test_invalid_task_rejected_before_invocation(self):
        crew = FakeCrew()
        policy = CapabilityPolicy(frozenset({CrewAIAdapter.CAPABILITY}))
        with self.assertRaises(TypeError):
            CrewAIAdapter(crew, policy=policy).run("not a task")
        self.assertEqual(crew.calls, 0)

    def test_langchain_plain_string_response(self):
        policy = CapabilityPolicy(frozenset({LangChainAdapter.CAPABILITY}))
        self.assertEqual(
            LangChainAdapter(FakeRunnable(result="plain text"), policy=policy).run(TASK),
            "plain text",
        )

    def test_crewai_plain_string_response(self):
        policy = CapabilityPolicy(frozenset({CrewAIAdapter.CAPABILITY}))
        self.assertEqual(
            CrewAIAdapter(FakeCrew(result="plain text"), policy=policy).run(TASK),
            "plain text",
        )

    def test_unsupported_response_rejected(self):
        policy = CapabilityPolicy(frozenset({LangChainAdapter.CAPABILITY}))
        with self.assertRaises(FrameworkExecutionError):
            LangChainAdapter(FakeRunnable(result=object()), policy=policy).run(TASK)

    def test_ledger_tracks_adapter_success_and_blocks_replay(self):
        policy = CapabilityPolicy(frozenset({CrewAIAdapter.CAPABILITY}))
        ledger = InMemoryExecutionLedger()
        crew = FakeCrew()
        adapter = CrewAIAdapter(crew, policy=policy, ledger=ledger)
        self.assertEqual(adapter.run(TASK, execution_id="issue-42"), "Crew plan")
        self.assertEqual(ledger.get("issue-42").state, ExecutionState.SUCCEEDED)
        with self.assertRaises(DuplicateExecutionError):
            adapter.run(TASK, execution_id="issue-42")
        self.assertEqual(crew.calls, 1)

    def test_ledger_records_adapter_failure(self):
        policy = CapabilityPolicy(frozenset({LangChainAdapter.CAPABILITY}))
        ledger = InMemoryExecutionLedger()
        adapter = LangChainAdapter(FakeRunnable(error=ValueError()), policy=policy, ledger=ledger)
        with self.assertRaises(FrameworkExecutionError):
            adapter.run(TASK, execution_id="issue-43")
        self.assertEqual(ledger.get("issue-43").state, ExecutionState.FAILED)

    def test_sqlite_ledger_adapter_integration(self):
        import tempfile
        from pathlib import Path

        policy = CapabilityPolicy(frozenset({LangChainAdapter.CAPABILITY}))
        with tempfile.TemporaryDirectory() as directory:
            ledger = SQLiteExecutionStore(Path(directory) / "agent.sqlite3")
            adapter = LangChainAdapter(FakeRunnable(result="durable"), policy=policy, ledger=ledger)
            self.assertEqual(adapter.run(TASK, execution_id="issue-99"), "durable")
            self.assertEqual(ledger.get("issue-99").state, ExecutionState.SUCCEEDED)

    def test_ledger_and_id_must_be_paired(self):
        policy = CapabilityPolicy(frozenset({CrewAIAdapter.CAPABILITY}))
        adapter = CrewAIAdapter(FakeCrew(), policy=policy, ledger=InMemoryExecutionLedger())
        with self.assertRaises(ValueError):
            adapter.run(TASK)

    def test_framework_exception_is_wrapped(self):
        policy = CapabilityPolicy(frozenset({CrewAIAdapter.CAPABILITY}))
        with self.assertRaises(FrameworkExecutionError) as caught:
            CrewAIAdapter(FakeCrew(error=ValueError("internal")), policy=policy).run(TASK)
        self.assertIsInstance(caught.exception.__cause__, ValueError)


    def test_pre_cancelled_control_prevents_framework_invocation(self):
        policy = CapabilityPolicy(frozenset({LangChainAdapter.CAPABILITY}))
        runnable = ControlledRunnable(lambda control: "should not run")
        control = ExecutionControl()
        control.cancel()
        with self.assertRaises(ExecutionCancelledError):
            LangChainAdapter(runnable, policy=policy).run(TASK, control=control)
        self.assertEqual(runnable.calls, 0)

    def test_cooperative_cancellation_is_recorded_as_failure(self):
        policy = CapabilityPolicy(frozenset({LangChainAdapter.CAPABILITY}))
        ledger = InMemoryExecutionLedger()
        def cancel_during_call(control):
            control.cancel()
            control.check()
        runnable = ControlledRunnable(cancel_during_call)
        adapter = LangChainAdapter(runnable, policy=policy, ledger=ledger)
        with self.assertRaises(ExecutionCancelledError):
            adapter.run(TASK, execution_id="cancelled-job", control=ExecutionControl())
        self.assertEqual(ledger.get("cancelled-job").state, ExecutionState.FAILED)
        self.assertEqual(ledger.get("cancelled-job").error_type, "ExecutionCancelledError")

    def test_deadline_expiry_is_recorded_as_failure(self):
        import time

        policy = CapabilityPolicy(frozenset({LangChainAdapter.CAPABILITY}))
        ledger = InMemoryExecutionLedger()
        def exceed_deadline(control):
            time.sleep(0.02)
            control.check()
        adapter = LangChainAdapter(
            ControlledRunnable(exceed_deadline), policy=policy, ledger=ledger
        )
        with self.assertRaises(ExecutionDeadlineExceeded):
            adapter.run(
                TASK, execution_id="timeout-job",
                control=ExecutionControl(timeout_seconds=0.005),
            )
        self.assertEqual(ledger.get("timeout-job").state, ExecutionState.FAILED)
        self.assertEqual(ledger.get("timeout-job").error_type, "ExecutionDeadlineExceeded")

    def test_control_requires_context_aware_framework_port(self):
        policy = CapabilityPolicy(frozenset({LangChainAdapter.CAPABILITY}))
        with self.assertRaises(FrameworkExecutionError):
            LangChainAdapter(FakeRunnable(), policy=policy).run(
                TASK, control=ExecutionControl()
            )


if __name__ == "__main__":
    unittest.main()
