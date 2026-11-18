from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

from dorker_agent.domain.artifact_gc import (
    ArtifactDeletionPlan,
    ArtifactGCDryRun,
    ArtifactObjectInfo,
    ArtifactRetentionPolicy,
)


class ArtifactGCDomainContractTests(unittest.TestCase):
    def test_retention_policy_rejects_bool_and_non_positive_limits(self):
        for kwargs in (
            {"min_age_seconds": True},
            {"max_candidates": 0},
            {"max_scan_objects": -1},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                ArtifactRetentionPolicy(**kwargs)

    def test_retention_policy_is_immutable(self):
        policy = ArtifactRetentionPolicy()
        with self.assertRaises(AttributeError):
            policy.max_candidates = 10

    def test_gc_contracts_are_immutable_value_objects(self):
        item = ArtifactObjectInfo("a" * 64, 12, 100)
        plan = ArtifactDeletionPlan((item,), 12, 200, "b" * 64)
        report = ArtifactGCDryRun(1, 0, (item,), (), (), False)
        self.assertEqual(plan.total_bytes, 12)
        self.assertEqual(report.orphaned, (item,))
        with self.assertRaises(AttributeError):
            item.size_bytes = 13

    def test_domain_and_port_imports_do_not_load_storage_adapters(self):
        agent_lab = Path(__file__).resolve().parents[1]
        script = """
import sys
import dorker_agent.domain.artifact_gc
import dorker_agent.ports.artifact_gc_audit
assert "dorker_agent.artifacts" not in sys.modules
assert "sqlite3" not in sys.modules
"""
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=agent_lab,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=f"isolated imports failed: {completed.stdout}\n{completed.stderr}",
        )


if __name__ == "__main__":
    unittest.main()
