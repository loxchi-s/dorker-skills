from __future__ import annotations

import hashlib
import os
import tempfile
import threading
import unittest

from dorker_agent.artifacts import (
    ArtifactIntegrityError,
    ArtifactNotFoundError,
    ContentAddressedArtifactStore,
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


if __name__ == "__main__":
    unittest.main()
