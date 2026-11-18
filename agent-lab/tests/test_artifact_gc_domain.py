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
    gc_plan_token,
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
        plan = ArtifactDeletionPlan((item,), 12, 200, gc_plan_token(200, (item,)))
        report = ArtifactGCDryRun(1, 0, (item,), (), (), False)
        self.assertEqual(plan.total_bytes, 12)
        self.assertEqual(report.orphaned, (item,))
        with self.assertRaises(AttributeError):
            item.size_bytes = 13

    def test_gc_plan_rejects_invalid_token_and_candidate_order(self):
        first = ArtifactObjectInfo("a" * 64, 3, 100)
        second = ArtifactObjectInfo("b" * 64, 4, 90)
        with self.assertRaisesRegex(ValueError, "approval token"):
            ArtifactDeletionPlan((first,), 3, 200, "b" * 64)
        with self.assertRaisesRegex(ValueError, "canonically ordered"):
            ArtifactDeletionPlan(
                (first, second),
                7,
                200,
                gc_plan_token(200, (first, second)),
            )

    def test_gc_plan_rejects_duplicate_candidates_and_wrong_total(self):
        item = ArtifactObjectInfo("c" * 64, 5, 100)
        duplicate_candidates = (item, item)
        with self.assertRaisesRegex(ValueError, "duplicate candidate"):
            ArtifactDeletionPlan(
                duplicate_candidates,
                10,
                200,
                gc_plan_token(200, duplicate_candidates),
            )
        with self.assertRaisesRegex(ValueError, "total_bytes"):
            ArtifactDeletionPlan(
                (item,),
                6,
                200,
                gc_plan_token(200, (item,)),
            )

    def test_gc_object_and_dry_run_reject_invalid_contract_values(self):
        with self.assertRaises(ValueError):
            ArtifactObjectInfo("A" * 64, 1, 1)
        with self.assertRaises(ValueError):
            ArtifactObjectInfo("a" * 64, True, 1)
        with self.assertRaises(ValueError):
            ArtifactGCDryRun(-1, 0, (), (), (), False)

    def test_execution_domain_and_adapters_respect_layer_boundaries(self):
        agent_lab = Path(__file__).resolve().parents[1]
        domain_script = """
import sys
import dorker_agent.domain.execution
import dorker_agent.ports.execution_ledger
assert "sqlite3" not in sys.modules
assert "dorker_agent.execution" not in sys.modules
"""
        domain_result = subprocess.run(
            [sys.executable, "-c", domain_script],
            cwd=agent_lab,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            domain_result.returncode,
            0,
            msg=f"execution domain isolation failed: {domain_result.stdout}\\n{domain_result.stderr}",
        )

        adapter_script = """
import sys
from dorker_agent.adapters.persistence.sqlite_execution_store import SQLiteExecutionStore
assert SQLiteExecutionStore is not None
assert "dorker_agent.execution" not in sys.modules
"""
        adapter_result = subprocess.run(
            [sys.executable, "-c", adapter_script],
            cwd=agent_lab,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            adapter_result.returncode,
            0,
            msg=f"execution adapter isolation failed: {adapter_result.stdout}\\n{adapter_result.stderr}",
        )

    def test_storage_adapters_do_not_import_compatibility_facade(self):
        agent_lab = Path(__file__).resolve().parents[1]
        script = """
import sys
from dorker_agent.adapters.persistence.sqlite_artifact_index import SQLiteArtifactIndex
from dorker_agent.adapters.storage.content_addressed_artifact_store import ContentAddressedArtifactStore
assert SQLiteArtifactIndex is not None
assert ContentAddressedArtifactStore is not None
assert "dorker_agent.artifacts" not in sys.modules
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
            msg=f"adapter isolation failed: {completed.stdout}\\n{completed.stderr}",
        )

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
