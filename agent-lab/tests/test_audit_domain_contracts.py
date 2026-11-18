from __future__ import annotations

import os
import subprocess
import sys
import unittest

from dorker_agent.application.errors import AuditServiceError
from dorker_agent.domain.audit import AuthorizationResult, VerifiedApprovalEvidence
from dorker_agent.domain.audit_hashing import ZERO_HASH, canonical_hash, event_hash
from dorker_agent.domain.identity import GitHubActorClaim, VerifiedGitHubActor
from dorker_agent.remote_audit_service import (
    AuditServiceError as LegacyAuditServiceError,
    AuthorizationResult as LegacyAuthorizationResult,
    VerifiedApprovalEvidence as LegacyVerifiedApprovalEvidence,
    _ZERO_HASH,
    _event_hash,
)


class AuditDomainContractTests(unittest.TestCase):
    def test_legacy_service_imports_remain_compatible(self):
        self.assertIs(LegacyAuditServiceError, AuditServiceError)
        self.assertIs(LegacyAuthorizationResult, AuthorizationResult)
        self.assertIs(LegacyVerifiedApprovalEvidence, VerifiedApprovalEvidence)
        self.assertEqual(_ZERO_HASH, ZERO_HASH)

    def test_hashing_is_deterministic_and_excludes_hash_field(self):
        event = {
            "repository_id": 123,
            "event_type": "plan_created",
            "details": {"b": 2, "a": 1},
        }
        expected = event_hash(event)
        self.assertEqual(expected, event_hash({**event, "event_hash": "ignored"}))
        self.assertEqual(expected, _event_hash(event))
        self.assertEqual(canonical_hash(event), expected)

    def test_remote_client_uses_the_same_canonical_hash_primitive(self):
        event = {
            "sequence": 1,
            "event_id": "evt-1",
            "event_type": "plan_created",
            "actor_id": 42,
            "actor_login": "octocat",
            "timestamp": "2026-11-18T00:00:00.000Z",
            "details": {"plan": {"size": 10}},
            "idempotency_key": "key-1",
            "request_hash": "a" * 64,
            "previous_hash": ZERO_HASH,
        }
        from dorker_agent.remote_audit import RemoteAuditHttpClient

        expected = canonical_hash(event)
        self.assertEqual(
            RemoteAuditHttpClient.compute_event_hash({**event, "event_hash": "ignored"}),
            expected,
        )

    def test_identity_values_are_provider_neutral(self):
        claim = GitHubActorClaim(42, "octocat", "short-lived-token")
        actor = VerifiedGitHubActor(42, "octocat")
        self.assertEqual((claim.github_id, claim.login), (actor.github_id, actor.login))

    def test_domain_import_does_not_load_database_or_network_adapters(self):
        code = (
            "import sys; "
            "from dorker_agent.domain.audit import AuthorizationResult; "
            "from dorker_agent.domain.identity import VerifiedGitHubActor; "
            "assert 'sqlite3' not in sys.modules; "
            "assert 'urllib.request' not in sys.modules; "
            "assert 'dorker_agent.remote_audit_service' not in sys.modules"
        )
        env = dict(os.environ)
        completed = subprocess.run(
            [sys.executable, "-c", code],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_postgres_adapter_does_not_import_service_implementation(self):
        code = (
            "import sys; "
            "from dorker_agent.postgres_audit_repository import PostgresAuditRepository; "
            "assert 'dorker_agent.remote_audit_service' not in sys.modules"
        )
        completed = subprocess.run(
            [sys.executable, "-c", code],
            check=False,
            capture_output=True,
            text=True,
            env=dict(os.environ),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
