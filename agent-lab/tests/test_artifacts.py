from __future__ import annotations

import hashlib
import os
import tempfile
import threading
import unittest

from dorker_agent.container_sandbox import ArtifactManifest
from dorker_agent.artifacts import (
    ArtifactIntegrityError,
    ArtifactNotFoundError,
    ContentAddressedArtifactStore,
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



class SQLiteArtifactIndexTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = os.path.join(self.temp.name, "objects")
        os.mkdir(root)
        self.blobs = ContentAddressedArtifactStore(root, max_artifact_bytes=1024)
        self.db = os.path.join(self.temp.name, "index", "artifacts.sqlite3")
        self.index = SQLiteArtifactIndex(self.db, self.blobs, max_records=10)

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
        reopened = SQLiteArtifactIndex(self.db, self.blobs)
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
