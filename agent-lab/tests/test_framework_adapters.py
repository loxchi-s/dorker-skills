import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dorker_agent.capabilities import CapabilityPolicy
from dorker_agent.framework_adapters import CrewAIAdapter, FrameworkExecutionError, LangChainAdapter
from dorker_agent.tasks import TaskRequest

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

    def test_unsupported_response_rejected(self):
        policy = CapabilityPolicy(frozenset({LangChainAdapter.CAPABILITY}))
        with self.assertRaises(FrameworkExecutionError):
            LangChainAdapter(FakeRunnable(result=object()), policy=policy).run(TASK)

    def test_framework_exception_is_wrapped(self):
        policy = CapabilityPolicy(frozenset({CrewAIAdapter.CAPABILITY}))
        with self.assertRaises(FrameworkExecutionError) as caught:
            CrewAIAdapter(FakeCrew(error=ValueError("internal")), policy=policy).run(TASK)
        self.assertIsInstance(caught.exception.__cause__, ValueError)


if __name__ == "__main__":
    unittest.main()
