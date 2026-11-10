import json
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from validate_registry import parse_skill, validate


class RegistryValidatorTests(unittest.TestCase):
    def _make_registry(self, root: Path, *, yaml_text: str | None = None) -> None:
        skill_dir = root / "skills" / "demo-skill"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(
            "---\nname: demo-skill\ndescription: Demo\n---\n# Demo\n", encoding="utf-8"
        )
        catalog = {
            "schema_version": 1,
            "registry": "dorker-skills",
            "status": "draft",
            "runtime_enabled": False,
            "skill_format": "agentskills",
            "default_capabilities": [],
            "skills": [{
                "name": "demo-skill",
                "category": "core",
                "status": "draft",
                "path": "skills/demo-skill/SKILL.md",
            }],
        }
        (root / "catalog.json").write_text(json.dumps(catalog), encoding="utf-8")
        rendered_yaml = yaml.safe_dump(catalog, sort_keys=False)
        (root / "catalog.yaml").write_text(
            yaml_text if yaml_text is not None else rendered_yaml, encoding="utf-8"
        )

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
            self._make_registry(root)
            catalog = json.loads((root / "catalog.json").read_text(encoding="utf-8"))
            catalog["runtime_enabled"] = True
            (root / "catalog.json").write_text(json.dumps(catalog), encoding="utf-8")
            self.assertTrue(any("runtime_enabled" in e for e in validate(root)))

    def test_yaml_json_parity_passes_for_matching_catalogs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._make_registry(root)
            self.assertEqual(validate(root), [])

    def test_yaml_json_parity_rejects_missing_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._make_registry(root)
            catalog = yaml.safe_load((root / "catalog.yaml").read_text(encoding="utf-8"))
            catalog["skills"].clear()
            (root / "catalog.yaml").write_text(yaml.safe_dump(catalog), encoding="utf-8")
            self.assertTrue(any("does not match" in e for e in validate(root)))

    def test_yaml_json_parity_rejects_changed_metadata(self):
        for field, value in (("category", "advanced"), ("status", "active"), ("path", "skills/other/SKILL.md")):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self._make_registry(root)
                catalog = yaml.safe_load((root / "catalog.yaml").read_text(encoding="utf-8"))
                catalog["skills"][0][field] = value
                (root / "catalog.yaml").write_text(yaml.safe_dump(catalog), encoding="utf-8")
                self.assertTrue(any("does not match" in e for e in validate(root)))

    def test_yaml_json_parity_rejects_extra_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._make_registry(root)
            catalog = yaml.safe_load((root / "catalog.yaml").read_text(encoding="utf-8"))
            catalog["skills"].append({
                "name": "extra-skill", "category": "core", "status": "draft",
                "path": "skills/extra-skill/SKILL.md",
            })
            (root / "catalog.yaml").write_text(yaml.safe_dump(catalog), encoding="utf-8")
            self.assertTrue(any("does not match" in e for e in validate(root)))

    def test_yaml_duplicate_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._make_registry(root, yaml_text="schema_version: 1\nschema_version: 1\n")
            self.assertTrue(any("cannot parse" in e for e in validate(root)))


if __name__ == "__main__":
    unittest.main()
