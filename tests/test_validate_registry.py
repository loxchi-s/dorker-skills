import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from validate_registry import parse_skill, validate


class RegistryValidatorTests(unittest.TestCase):
    def test_valid_skill_frontmatter(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "SKILL.md"
            path.write_text("---\nname: demo-skill\ndescription: A test skill\n---\n# Demo\n", encoding="utf-8")
            metadata, errors = parse_skill(path)
            self.assertEqual(metadata["name"], "demo-skill")
            self.assertEqual(errors, [])

    def test_missing_frontmatter_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "SKILL.md"
            path.write_text("# No metadata\n", encoding="utf-8")
            _, errors = parse_skill(path)
            self.assertTrue(errors)

    def test_catalog_runtime_must_remain_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "skills" / "demo-skill").mkdir(parents=True)
            (root / "skills" / "demo-skill" / "SKILL.md").write_text(
                "---\nname: demo-skill\ndescription: Demo\n---\n# Demo\n", encoding="utf-8"
            )
            (root / "catalog.json").write_text(json.dumps({
                "schema_version": 1, "runtime_enabled": True,
                "skills": [{"name": "demo-skill", "path": "skills/demo-skill/SKILL.md"}]
            }), encoding="utf-8")
            self.assertTrue(any("runtime_enabled" in e for e in validate(root)))


if __name__ == "__main__":
    unittest.main()
