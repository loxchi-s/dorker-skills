from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from dataclasses import replace

from dorker_agent.container_sandbox import ArtifactManifest
from dorker_agent.artifacts import (
    ArtifactIntegrityError,
    ArtifactNotFoundError,
    ArtifactDeletionPlan,
    ArtifactRetentionPolicy,
    ContentAddressedArtifactStore,
    GitHubActorClaim,
    VerifiedGitHubActor,
    SQLiteArtifactIndex,
)


class ContentAddressedArtifactStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = os.path.join(self.temp.name, "objects")
        os.mkdir(self.root)
        self.store = ContentAddressedArtifactStore(self.root, max_artifact_bytes=1024)

    def tearDown(self):
        self.temp.cleanup()

    def put(self, data=b"artifact"):
        return self.store.put(
            data, name="result.bin", media_type="application/octet-stream",
            source="unit-test", execution_id="exec-1", created_at_unix_ms=123,
        )

    def test_put_get_and_content_address(self):
        manifest = self.put()
        self.assertEqual(self.store.get(manifest.sha256), b"artifact")
        self.assertTrue(self.store.contains(manifest.sha256))
        path = os.path.join(self.root, manifest.sha256[:2], manifest.sha256[2:])
        self.assertTrue(os.path.isfile(path))
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_duplicate_content_is_idempotent(self):
        first = self.put()
        second = self.put()
        self.assertEqual(first.sha256, second.sha256)
        self.assertEqual(self.store.get(first.sha256), b"artifact")

    def test_distinct_content_has_distinct_addresses(self):
        first = self.put(b"one")
        second = self.put(b"two")
        self.assertNotEqual(first.sha256, second.sha256)

    def test_per_artifact_size_limit(self):
        with self.assertRaisesRegex(ValueError, "max_artifact_bytes"):
            self.put(b"x" * 1025)

    def test_non_bytes_rejected(self):
        with self.assertRaises(TypeError):
            self.put("not-bytes")

    def test_missing_object(self):
        digest = hashlib.sha256(b"missing").hexdigest()
        self.assertFalse(self.store.contains(digest))
        with self.assertRaises(ArtifactNotFoundError):
            self.store.get(digest)

    def test_invalid_digest_rejected(self):
        for digest in ("../etc/passwd", "A" * 64, "0" * 63):
            with self.subTest(digest=digest), self.assertRaises(ValueError):
                self.store.get(digest)

    def test_corrupted_object_detected(self):
        manifest = self.put()
        path = os.path.join(self.root, manifest.sha256[:2], manifest.sha256[2:])
        with open(path, "wb") as handle:
            handle.write(b"tampered")
        with self.assertRaises(ArtifactIntegrityError):
            self.store.get(manifest.sha256)

    def test_symlink_object_rejected(self):
        manifest = self.put()
        path = os.path.join(self.root, manifest.sha256[:2], manifest.sha256[2:])
        os.unlink(path)
        target = os.path.join(self.temp.name, "outside")
        with open(target, "wb") as handle:
            handle.write(b"artifact")
        os.symlink(target, path)
        with self.assertRaises(OSError):
            self.store.get(manifest.sha256)

    def test_symlink_shard_rejected(self):
        data = b"shard-symlink"
        digest = hashlib.sha256(data).hexdigest()
        shard = os.path.join(self.root, digest[:2])
        os.symlink(self.temp.name, shard)
        with self.assertRaises(OSError):
            self.store.put(data, name="x", media_type="x", source="test")

    def test_rejects_symlink_root(self):
        link = os.path.join(self.temp.name, "root-link")
        os.symlink(self.root, link)
        with self.assertRaises(ValueError):
            ContentAddressedArtifactStore(link)

    def test_concurrent_put_is_idempotent(self):
        errors = []
        digests = []

        def worker():
            try:
                digests.append(self.put(b"shared").sha256)
            except Exception as exc:  # surfaced in parent test
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=3)
        self.assertFalse(errors)
        self.assertEqual(len(digests), 8)
        self.assertEqual(len(set(digests)), 1)
        self.assertEqual(self.store.get(digests[0]), b"shared")



class FakeGitHubIdentityVerifier:
    def verify(self, claim):
        expected = f"test-oidc:{claim.github_id}:{claim.login}"
        if claim.oidc_token != expected:
            raise ValueError("invalid test OIDC proof")
        return VerifiedGitHubActor(claim.github_id, claim.login)


def github_claim(actor_id, login):
    return GitHubActorClaim(actor_id, login, f"test-oidc:{actor_id}:{login}")


class SQLiteArtifactIndexTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = os.path.join(self.temp.name, "objects")
        os.mkdir(root)
        self.blobs = ContentAddressedArtifactStore(root, max_artifact_bytes=1024)
        self.db = os.path.join(self.temp.name, "index", "artifacts.sqlite3")
        self.index = SQLiteArtifactIndex(
            self.db, self.blobs, max_records=10,
            identity_verifier=FakeGitHubIdentityVerifier(),
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_put_and_retrieve_manifest_and_verified_bytes(self):
        artifact_id = self.index.put(
            b"report-data", name="report.bin", media_type="application/octet-stream",
            source="test", execution_id="exec-42", created_at_unix_ms=42,
        )
        manifest, data = self.index.get(artifact_id)
        self.assertEqual(data, b"report-data")
        self.assertEqual(manifest.execution_id, "exec-42")
        self.assertEqual(manifest.sha256, hashlib.sha256(data).hexdigest())

    def test_manifest_and_blob_survive_reopen(self):
        artifact_id = self.index.put(
            b"persistent", name="persist.bin", media_type="application/octet-stream",
            source="test", execution_id="exec-43",
        )
        reopened = SQLiteArtifactIndex(
            self.db, self.blobs, identity_verifier=FakeGitHubIdentityVerifier(),
        )
        self.assertEqual(reopened.get(artifact_id)[1], b"persistent")

    def test_same_manifest_registration_is_idempotent(self):
        first = self.index.put(
            b"same", name="same.bin", media_type="application/octet-stream",
            source="test", execution_id="exec-44", created_at_unix_ms=44,
        )
        second = self.index.put(
            b"same", name="same.bin", media_type="application/octet-stream",
            source="test", execution_id="exec-44", created_at_unix_ms=44,
        )
        self.assertEqual(first, second)

    def test_same_blob_can_have_multiple_execution_manifests(self):
        first = self.index.put(
            b"shared", name="shared.bin", media_type="application/octet-stream",
            source="test", execution_id="exec-A",
        )
        second = self.index.put(
            b"shared", name="shared.bin", media_type="application/octet-stream",
            source="test", execution_id="exec-B",
        )
        self.assertNotEqual(first, second)
        self.assertEqual(len(self.index.list_for_execution("exec-A")), 1)
        self.assertEqual(len(self.index.list_for_execution("exec-B")), 1)

    def test_index_capacity_is_bounded(self):
        index = SQLiteArtifactIndex(self.db, self.blobs, max_records=1)
        index.put(b"one", name="one", media_type="x", source="test")
        with self.assertRaisesRegex(RuntimeError, "capacity"):
            index.put(b"two", name="two", media_type="x", source="test")

    def test_register_rejects_manifest_without_published_blob(self):
        manifest = ArtifactManifest.from_bytes(
            name="missing.bin", media_type="application/octet-stream",
            data=b"not-published", source="test",
        )
        with self.assertRaises(ArtifactNotFoundError):
            self.index.register(manifest)

    def test_unknown_and_invalid_ids(self):
        self.assertIsNone(self.index.get("0" * 64))
        with self.assertRaises(ValueError):
            self.index.get("../invalid")

    def test_execution_query_limit_is_validated(self):
        with self.assertRaises(ValueError):
            self.index.list_for_execution("exec", limit=0)

    def test_gc_dry_run_reports_only_verified_unreferenced_blobs(self):
        orphan = self.blobs.put(
            b"orphan", name="orphan.bin", media_type="application/octet-stream",
            source="test",
        )
        self.index.put(
            b"referenced", name="kept.bin", media_type="application/octet-stream",
            source="test", execution_id="exec-keep",
        )
        report = self.index.dry_run_gc()
        self.assertEqual([item.sha256 for item in report.orphaned], [orphan.sha256])
        self.assertEqual(report.referenced_objects, 1)
        self.assertEqual(report.scanned_objects, 2)
        self.assertFalse(report.truncated)
        self.assertEqual(self.blobs.get(orphan.sha256), b"orphan")

    def test_gc_dry_run_reports_missing_and_corrupt_objects(self):
        missing_id = self.index.put(
            b"missing", name="missing.bin", media_type="x", source="test",
        )
        corrupt_id = self.index.put(
            b"corrupt", name="corrupt.bin", media_type="x", source="test",
        )
        missing_manifest = self.index.get_manifest(missing_id)
        corrupt_manifest = self.index.get_manifest(corrupt_id)
        os.unlink(os.path.join(
            self.blobs._root, missing_manifest.sha256[:2], missing_manifest.sha256[2:]
        ))
        corrupt_path = os.path.join(
            self.blobs._root, corrupt_manifest.sha256[:2], corrupt_manifest.sha256[2:]
        )
        with open(corrupt_path, "wb") as handle:
            handle.write(b"tampered")
        report = self.index.dry_run_gc()
        self.assertEqual(report.missing_digests, (missing_manifest.sha256,))
        self.assertEqual(report.corrupt_digests, (corrupt_manifest.sha256,))
        self.assertEqual(report.orphaned, ())

    def test_gc_dry_run_is_bounded_and_never_deletes(self):
        first = self.blobs.put(b"one", name="one", media_type="x", source="test")
        self.blobs.put(b"two", name="two", media_type="x", source="test")
        report = self.index.dry_run_gc(max_scan_objects=1)
        self.assertEqual(report.scanned_objects, 1)
        self.assertTrue(report.truncated)
        self.assertTrue(self.blobs.contains(first.sha256))

    def test_retention_plan_includes_only_old_orphan_blobs(self):
        old = self.blobs.put(b"old-orphan", name="old", media_type="x", source="test")
        recent = self.blobs.put(b"recent-orphan", name="recent", media_type="x", source="test")
        self.index.put(b"referenced", name="keep", media_type="x", source="test")
        old_path = os.path.join(self.blobs._root, old.sha256[:2], old.sha256[2:])
        os.utime(old_path, ns=(1_000_000_000, 1_000_000_000))
        now = 10_000_000_000
        plan = self.index.build_gc_plan(
            ArtifactRetentionPolicy(min_age_seconds=5, max_candidates=10),
            now_unix_ns=now,
        )
        self.assertEqual([item.sha256 for item in plan.candidates], [old.sha256])
        self.assertEqual(plan.total_bytes, len(b"old-orphan"))
        self.assertEqual(len(plan.approval_token), 64)
        self.assertTrue(self.blobs.contains(old.sha256))
        self.assertTrue(self.blobs.contains(recent.sha256))

    def test_retention_plan_is_deterministic_for_same_snapshot_and_cutoff(self):
        self.blobs.put(b"orphan", name="old", media_type="x", source="test")
        now = 100_000_000_000
        policy = ArtifactRetentionPolicy(min_age_seconds=1, max_candidates=5)
        first = self.index.build_gc_plan(policy, now_unix_ns=now)
        second = self.index.build_gc_plan(policy, now_unix_ns=now)
        self.assertEqual(first, second)

    def test_retention_plan_rejects_truncated_scan(self):
        for value in (b"a", b"b"):
            self.blobs.put(value, name="x", media_type="x", source="test")
        with self.assertRaisesRegex(RuntimeError, "truncated"):
            self.index.build_gc_plan(
                ArtifactRetentionPolicy(max_scan_objects=1),
                now_unix_ns=100_000_000_000,
            )

    def test_retention_policy_validates_bounds(self):
        with self.assertRaises(ValueError):
            ArtifactRetentionPolicy(min_age_seconds=0)
        with self.assertRaises(ValueError):
            ArtifactRetentionPolicy(max_candidates=True)

    def test_gc_dry_run_rejects_invalid_scan_limit(self):
        with self.assertRaises(ValueError):
            self.index.dry_run_gc(max_scan_objects=0)

    def test_gc_audit_rejects_forged_candidate_metadata_and_token(self):
        blob = self.blobs.put(b"orphan", name="x", media_type="x", source="test")
        path = os.path.join(self.blobs._root, blob.sha256[:2], blob.sha256[2:])
        os.utime(path, ns=(1_000_000_000, 1_000_000_000))
        plan = self.index.build_gc_plan(
            ArtifactRetentionPolicy(min_age_seconds=1),
            now_unix_ns=10_000_000_000,
        )
        altered = replace(plan.candidates[0], size_bytes=plan.candidates[0].size_bytes + 1)
        forged = replace(
            plan, candidates=(altered,), total_bytes=plan.total_bytes + 1,
        )
        with self.assertRaisesRegex(ValueError, "approval token"):
            self.index.record_gc_plan(forged, claim=github_claim(101, "creator"))
        self.assertEqual(self.index.list_audit_events(), [])

    def test_gc_approval_rejects_tampered_recorded_candidate_metadata(self):
        blob = self.blobs.put(b"orphan", name="x", media_type="x", source="test")
        path = os.path.join(self.blobs._root, blob.sha256[:2], blob.sha256[2:])
        os.utime(path, ns=(1_000_000_000, 1_000_000_000))
        plan = self.index.build_gc_plan(
            ArtifactRetentionPolicy(min_age_seconds=1),
            now_unix_ns=10_000_000_000,
        )
        self.index.record_gc_plan(plan, claim=github_claim(101, "creator"))
        with sqlite3.connect(self.db) as db:
            row = db.execute(
                "SELECT details_json FROM artifact_audit_log WHERE action='gc_plan_created'"
            ).fetchone()
            details = json.loads(row[0])
            details["candidates"][0]["mtime_unix_ns"] += 1
            db.execute(
                "UPDATE artifact_audit_log SET details_json=? WHERE action='gc_plan_created'",
                (json.dumps(details, sort_keys=True, separators=(",", ":")),),
            )
        with self.assertRaisesRegex(ValueError, "recorded GC plan metadata"):
            self.index.record_gc_approval(
                plan.approval_token, claim=github_claim(202, "approver"), approved=True,
            )
        self.assertEqual(len(self.index.list_audit_events()), 1)

    def test_gc_audit_records_plan_and_approval_with_valid_hash_chain(self):
        blob = self.blobs.put(b"old-orphan", name="old", media_type="x", source="test")
        path = os.path.join(self.blobs._root, blob.sha256[:2], blob.sha256[2:])
        os.utime(path, ns=(1_000_000_000, 1_000_000_000))
        plan = self.index.build_gc_plan(
            ArtifactRetentionPolicy(min_age_seconds=1),
            now_unix_ns=10_000_000_000,
        )
        created_hash = self.index.record_gc_plan(plan, claim=github_claim(101, "creator"))
        approved_hash = self.index.record_gc_approval(
            plan.approval_token, claim=github_claim(202, "approver"), approved=True,
        )
        events = self.index.list_audit_events()
        self.assertEqual([event["action"] for event in events], [
            "gc_plan_created", "gc_plan_approved",
        ])
        self.assertEqual(events[0]["actor"], "github:101:creator")
        self.assertEqual(events[1]["actor"], "github:202:approver")
        self.assertEqual(events[0]["event_hash"], created_hash)
        self.assertEqual(events[1]["event_hash"], approved_hash)
        self.assertTrue(self.index.verify_audit_log())
        self.assertTrue(self.blobs.contains(blob.sha256))

    def test_gc_audit_rejects_duplicate_plan_and_second_decision(self):
        blob = self.blobs.put(b"orphan", name="x", media_type="x", source="test")
        path = os.path.join(self.blobs._root, blob.sha256[:2], blob.sha256[2:])
        os.utime(path, ns=(1_000_000_000, 1_000_000_000))
        plan = self.index.build_gc_plan(
            ArtifactRetentionPolicy(min_age_seconds=1),
            now_unix_ns=10_000_000_000,
        )
        self.index.record_gc_plan(plan, claim=github_claim(101, "creator"))
        with self.assertRaisesRegex(ValueError, "already been recorded"):
            self.index.record_gc_plan(plan, claim=github_claim(202, "other"))
        self.index.record_gc_approval(
            plan.approval_token, claim=github_claim(202, "approver"), approved=True,
        )
        with self.assertRaisesRegex(ValueError, "already has a recorded decision"):
            self.index.record_gc_approval(
                plan.approval_token, claim=github_claim(303, "another"), approved=False,
            )
        self.assertEqual(len(self.index.list_audit_events()), 2)

    def test_gc_audit_requires_distinct_verified_github_actor(self):
        blob = self.blobs.put(b"orphan", name="x", media_type="x", source="test")
        path = os.path.join(self.blobs._root, blob.sha256[:2], blob.sha256[2:])
        os.utime(path, ns=(1_000_000_000, 1_000_000_000))
        plan = self.index.build_gc_plan(
            ArtifactRetentionPolicy(min_age_seconds=1),
            now_unix_ns=10_000_000_000,
        )
        self.index.record_gc_plan(plan, claim=github_claim(101, "creator"))
        with self.assertRaisesRegex(ValueError, "different GitHub actor"):
            self.index.record_gc_approval(
                plan.approval_token, claim=github_claim(101, "creator"), approved=True,
            )
        with self.assertRaisesRegex(ValueError, "invalid test OIDC proof"):
            self.index.record_gc_approval(
                plan.approval_token,
                claim=GitHubActorClaim(202, "approver", "forged"),
                approved=True,
            )
        self.assertEqual(len(self.index.list_audit_events()), 1)

    def test_gc_audit_fails_closed_without_identity_verifier(self):
        index = SQLiteArtifactIndex(self.db, self.blobs)
        blob = self.blobs.put(b"orphan", name="x", media_type="x", source="test")
        path = os.path.join(self.blobs._root, blob.sha256[:2], blob.sha256[2:])
        os.utime(path, ns=(1_000_000_000, 1_000_000_000))
        plan = index.build_gc_plan(
            ArtifactRetentionPolicy(min_age_seconds=1),
            now_unix_ns=10_000_000_000,
        )
        with self.assertRaisesRegex(RuntimeError, "not configured"):
            index.record_gc_plan(plan, claim=github_claim(101, "creator"))

    def test_gc_audit_rejects_approval_without_recorded_plan(self):
        with self.assertRaisesRegex(ValueError, "no recorded GC plan"):
            self.index.record_gc_approval("a" * 64, claim=github_claim(101, "creator"), approved=True)

    def test_gc_audit_rejects_invalid_actor_and_approval_type(self):
        with self.assertRaises(ValueError):
            self.index.record_gc_approval("a" * 64, claim=GitHubActorClaim(0, " ", "bad"), approved=True)
        with self.assertRaises(TypeError):
            self.index.record_gc_approval("a" * 64, claim=github_claim(101, "creator"), approved=1)

    def test_gc_audit_log_capacity_is_bounded(self):
        index = SQLiteArtifactIndex(
            self.db, self.blobs, max_audit_records=1,
            identity_verifier=FakeGitHubIdentityVerifier(),
        )
        blob = self.blobs.put(b"orphan", name="x", media_type="x", source="test")
        path = os.path.join(self.blobs._root, blob.sha256[:2], blob.sha256[2:])
        os.utime(path, ns=(1_000_000_000, 1_000_000_000))
        plan = index.build_gc_plan(
            ArtifactRetentionPolicy(min_age_seconds=1),
            now_unix_ns=10_000_000_000,
        )
        index.record_gc_plan(plan, claim=github_claim(101, "creator"))
        with self.assertRaisesRegex(RuntimeError, "capacity"):
            index.record_gc_approval(plan.approval_token, claim=github_claim(202, "approver"), approved=False)

    def test_gc_audit_hash_chain_detects_database_tampering(self):
        blob = self.blobs.put(b"orphan", name="x", media_type="x", source="test")
        path = os.path.join(self.blobs._root, blob.sha256[:2], blob.sha256[2:])
        os.utime(path, ns=(1_000_000_000, 1_000_000_000))
        plan = self.index.build_gc_plan(
            ArtifactRetentionPolicy(min_age_seconds=1),
            now_unix_ns=10_000_000_000,
        )
        self.index.record_gc_plan(plan, claim=github_claim(101, "creator"))
        self.assertTrue(self.index.verify_audit_log())
        with sqlite3.connect(self.db) as db:
            db.execute(
                "UPDATE artifact_audit_log SET actor=? WHERE sequence=1",
                ("tampered",),
            )
        self.assertFalse(self.index.verify_audit_log())

    def test_index_detects_missing_blob(self):
        artifact_id = self.index.put(
            b"gone", name="gone", media_type="x", source="test",
        )
        manifest = self.index.get_manifest(artifact_id)
        os.unlink(os.path.join(self.blobs._root, manifest.sha256[:2], manifest.sha256[2:]))
        with self.assertRaises(ArtifactNotFoundError):
            self.index.get(artifact_id)


if __name__ == "__main__":
    unittest.main()
