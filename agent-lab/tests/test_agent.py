import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dorker_agent import Agent, ModelMessage


class FakeModel:
    def __init__(self, response="Plan ready"):
        self.response = response
        self.messages = None

    def complete(self, messages):
        self.messages = tuple(messages)
        return self.response


class AgentTests(unittest.TestCase):
    def test_delegates_task_to_model(self):
        model = FakeModel("  Inspect the failing test.  ")
        agent = Agent(model, system_prompt="Act as a coding assistant.")

        self.assertEqual(agent.run(" Fix the unit test "), "Inspect the failing test.")
        self.assertEqual(model.messages[0], ModelMessage("system", "Act as a coding assistant."))
        self.assertEqual(model.messages[1], ModelMessage("user", "Fix the unit test"))

    def test_rejects_empty_task(self):
        agent = Agent(FakeModel(), system_prompt="Assistant")
        with self.assertRaises(ValueError):
            agent.run("  ")

    def test_rejects_empty_model_response(self):
        agent = Agent(FakeModel(" "), system_prompt="Assistant")
        with self.assertRaises(RuntimeError):
            agent.run("Review code")

    def test_rejects_empty_system_prompt(self):
        with self.assertRaises(ValueError):
            Agent(FakeModel(), system_prompt=" ")


if __name__ == "__main__":
    unittest.main()
