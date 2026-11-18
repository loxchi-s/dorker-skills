from __future__ import annotations

import hashlib
import json
import unittest

from dorker_agent.domain.artifact_manifest import ArtifactManifest
from dorker_agent.container_sandbox import ArtifactManifest as LegacyArtifactManifest


class ArtifactManifestDomainTests(unittest.TestCase):
    def test_manifest_is_a_domain_value_object_with_no_adapter_dependency(self):
        self.assertIs(ArtifactManifest, LegacyArtifactManifest)

    def test_from_bytes_computes_content_metadata(self):
        payload = b"domain-owned-artifact"
        manifest = ArtifactManifest.from_bytes(
            name="result.bin",
            media_type="application/octet-stream",
            data=payload,
            source="unit-test",
        )

        self.assertEqual(manifest.size_bytes, len(payload))
        self.assertEqual(manifest.sha256, hashlib.sha256(payload).hexdigest())

    def test_verify_enforces_size_and_digest(self):
        payload = b"verified"
        manifest = ArtifactManifest.from_bytes(
            name="result.bin",
            media_type="application/octet-stream",
            data=payload,
            source="unit-test",
        )

        self.assertTrue(manifest.verify(payload, max_bytes=len(payload)))
        self.assertFalse(manifest.verify(payload + b"x", max_bytes=len(payload) + 1))
        self.assertFalse(manifest.verify(payload, max_bytes=len(payload) - 1))
        self.assertFalse(manifest.verify("verified", max_bytes=100))

    def test_to_json_is_deterministic_and_preserves_optional_fields(self):
        manifest = ArtifactManifest.from_bytes(
            name="result.bin",
            media_type="application/octet-stream",
            data=b"payload",
            source="unit-test",
            execution_id="exec-1",
            created_at_unix_ms=123,
        )

        encoded = manifest.to_json()
        self.assertEqual(encoded, manifest.to_json())
        self.assertEqual(json.loads(encoded)["execution_id"], "exec-1")
        self.assertEqual(json.loads(encoded)["created_at_unix_ms"], 123)

    def test_rejects_path_like_artifact_names(self):
        with self.assertRaisesRegex(ValueError, "plain filename"):
            ArtifactManifest(
                name="../escape",
                media_type="application/octet-stream",
                size_bytes=0,
                sha256="0" * 64,
                source="unit-test",
            )


if __name__ == "__main__":
    unittest.main()
