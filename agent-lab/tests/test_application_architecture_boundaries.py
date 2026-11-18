"""Subprocess checks for inward-only application dependencies."""
from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path


class ApplicationBoundaryTests(unittest.TestCase):
    def test_remote_audit_application_does_not_load_infrastructure_adapters(self):
        agent_lab_root = Path(__file__).resolve().parents[1]
        script = """
import sys
from dorker_agent.application.remote_audit_service import RemoteAuditApplicationService

forbidden = (
    "dorker_agent.adapters",
    "dorker_agent.github_oidc",
    "dorker_agent.postgres_audit_repository",
)
loaded = sorted(
    name for name in sys.modules
    if any(name == prefix or name.startswith(prefix + ".") for prefix in forbidden)
)
if loaded:
    raise SystemExit("application imported infrastructure modules: " + ", ".join(loaded))
"""
        env = os.environ.copy()
        env["PYTHONPATH"] = str(agent_lab_root)
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=agent_lab_root,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_sqlite_artifact_index_depends_on_blob_store_port(self):
        agent_lab_root = Path(__file__).resolve().parents[1]
        script = """
import sys
from dorker_agent.adapters.persistence.sqlite_artifact_index import SQLiteArtifactIndex
from dorker_agent.ports.artifact_blob_store import ArtifactBlobStore

assert SQLiteArtifactIndex is not None
assert ArtifactBlobStore is not None
assert "dorker_agent.adapters.storage.content_addressed_artifact_store" not in sys.modules
"""
        env = os.environ.copy()
        env["PYTHONPATH"] = str(agent_lab_root)
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=agent_lab_root,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_runtime_adapters_depend_on_execution_port_not_compatibility_facade(self):
        agent_lab_root = Path(__file__).resolve().parents[1]
        script = """
import sys
import dorker_agent.container_sandbox
import dorker_agent.framework_adapters
import dorker_agent.isolated_worker
from dorker_agent.ports.execution_ledger import ExecutionLedger

assert ExecutionLedger is not None
assert "dorker_agent.execution" not in sys.modules
assert "sqlite3" not in sys.modules
"""
        env = os.environ.copy()
        env["PYTHONPATH"] = str(agent_lab_root)
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=agent_lab_root,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
