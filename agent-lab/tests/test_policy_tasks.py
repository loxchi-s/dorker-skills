import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dorker_agent.capabilities import CapabilityPolicy, DEFAULT_POLICY
from dorker_agent.tasks import TaskRequest


class PolicyTests(unittest.TestCase):
    def test_default_policy_denies_everything(self):
        for capability in ("shell", "filesystem_write", "network", "deploy"):
            self.assertFalse(DEFAULT_POLICY.permits(capability))

    def test_explicit_capability_allowlist(self):
        policy = CapabilityPolicy(frozenset({"filesystem_read"}))
        self.assertTrue(policy.permits("filesystem_read"))
        self.assertFalse(policy.permits("shell"))

    def test_require_raises_for_denied_capability(self):
        with self.assertRaises(PermissionError):
            DEFAULT_POLICY.require("shell")


class TaskRequestTests(unittest.TestCase):
    def test_accepts_valid_task(self):
        task = TaskRequest("Fix parser", "Parser crashes on empty input.", "bug")
        self.assertEqual(task.task_type, "bug")

    def test_rejects_invalid_type(self):
        with self.assertRaises(ValueError):
            TaskRequest("Run command", "Do something", "shell")

    def test_rejects_empty_title_or_body(self):
        with self.assertRaises(ValueError):
            TaskRequest(" ", "Description")
        with self.assertRaises(ValueError):
            TaskRequest("Title", " ")


if __name__ == "__main__":
    unittest.main()
