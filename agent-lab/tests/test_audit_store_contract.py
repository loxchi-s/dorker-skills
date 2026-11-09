from __future__ import annotations

import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

from dorker_agent.artifacts import (
    ArtifactRetentionPolicy,
    AuditStore,
    ContentAddressedArtifactStore,
    GitHubActorClaim,
    SQLiteArtifactIndex,
    VerifiedGitHubActor,
)


class FakeGitHubIdentityVerifier:
    def verify(self, claim: GitHubActorClaim) -> VerifiedGitHubActor:
        expected = f"test-oidc:{claim.github_id}:{claim.login}"
        if claim.oidc_token != expected:
            raise ValueError("invalid test OIDC proof")
        return VerifiedGitHubActor(claim.github_id, claim.login)


def claim(actor_id: int, login: str) -> GitHubActorClaim:
    return GitHubActorClaim(actor_id, login, f"test-oidc:{actor_id}:{login}")


class SQLiteAuditStoreContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = os.path.join(self.temp.name, "objects")
        os.mkdir(root)
        self.blobs = ContentAddressedArtifactStore(root)
        self.database = os.path.join(self.temp.name, "audit.sqlite3")
        self.verifier = FakeGitHubIdentityVerifier()
        self.store = SQLiteArtifactIndex(
            self.database, self.blobs, identity_verifier=self.verifier,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_store(self) -> SQLiteArtifactIndex:
        return SQLiteArtifactIndex(
            self.database, self.blobs, identity_verifier=self.verifier,
        )

    def make_plan(self):
        return self.store.build_gc_plan(
            ArtifactRetentionPolicy(min_age_seconds=1),
            now_unix_ns=10_000_000_000,
        )

    def test_sqlite_adapter_satisfies_audit_store_protocol(self) -> None:
        self.assertIsInstance(self.store, AuditStore)

    def test_append_reopen_read_and_verify(self) -> None:
        plan = self.make_plan()
        created_hash = self.store.record_gc_plan(plan, claim=claim(11, "creator"), idempotency_key="contract-store-9")
        self.store.record_gc_approval(
            plan.approval_token, claim=claim(12, "approver"), approved=True,
        idempotency_key="contract-store-8")

        reopened = self.make_store()
        events = reopened.list_audit_events()
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["event_hash"], created_hash)
        self.assertEqual(events[0]["action"], "gc_plan_created")
        self.assertEqual(events[1]["action"], "gc_plan_approved")
        self.assertTrue(reopened.verify_audit_log())

    def test_duplicate_plan_and_terminal_decision_are_rejected(self) -> None:
        plan = self.make_plan()
        self.store.record_gc_plan(plan, claim=claim(11, "creator"), idempotency_key="contract-store-7")
        with self.assertRaisesRegex(ValueError, "already been recorded"):
            self.store.record_gc_plan(plan, claim=claim(13, "other"), idempotency_key="contract-store-6")

        self.store.record_gc_approval(
            plan.approval_token, claim=claim(12, "approver"), approved=True,
        idempotency_key="contract-store-5")
        with self.assertRaisesRegex(ValueError, "already has a recorded decision"):
            self.store.record_gc_approval(
                plan.approval_token, claim=claim(14, "another"), approved=False,
            idempotency_key="contract-store-4")
        self.assertEqual(len(self.store.list_audit_events()), 2)

    def test_creator_cannot_approve_own_plan(self) -> None:
        plan = self.make_plan()
        self.store.record_gc_plan(plan, claim=claim(11, "creator"), idempotency_key="contract-store-3")
        with self.assertRaisesRegex(ValueError, "different GitHub actor"):
            self.store.record_gc_approval(
                plan.approval_token, claim=claim(11, "creator"), approved=True,
            idempotency_key="contract-store-2")
        self.assertEqual(len(self.store.list_audit_events()), 1)

    def test_concurrent_terminal_decisions_allow_exactly_one_writer(self) -> None:
        plan = self.make_plan()
        self.store.record_gc_plan(plan, claim=claim(11, "creator"), idempotency_key="contract-store-1")
        stores = [self.make_store(), self.make_store()]

        def decide(args):
            store, actor_id = args
            try:
                store.record_gc_approval(
                    plan.approval_token,
                    claim=claim(actor_id, f"approver{actor_id}"),
                    approved=True,
                idempotency_key=f"concurrent-decision-{actor_id}")
                return "committed"
            except ValueError:
                return "rejected"

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(decide, [(stores[0], 12), (stores[1], 13)]))

        self.assertCountEqual(outcomes, ["committed", "rejected"])
        self.assertEqual(len(self.store.list_audit_events()), 2)
        self.assertTrue(self.store.verify_audit_log())


if __name__ == "__main__":
    unittest.main()
