import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from skill_manager import ManagerError, inspect_skill, make_pin, verify_pins, write_pins


class SkillManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        skill_dir = self.root / "skills" / "demo-skill"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(
            "---\nname: demo-skill\ndescription: Demo\n---\n# Demo\n",
            encoding="utf-8",
        )
        (self.root / "catalog.json").write_text(json.dumps({
            "schema_version": 1,
            "runtime_enabled": False,
            "skills": [{
                "name": "demo-skill",
                "category": "core",
                "status": "reviewed",
                "path": "skills/demo-skill/SKILL.md",
            }],
        }), encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_inspect_reports_content_hash(self):
        result = inspect_skill(self.root, "demo-skill")
        self.assertEqual(len(result["sha256"]), 64)

    def test_pin_requires_review_confirmation(self):
        with self.assertRaises(ManagerError):
            make_pin(self.root, "demo-skill", "a" * 40,
                     "https://github.com/example/demo", "MIT", False)

    def test_pin_and_verify(self):
        record = make_pin(self.root, "demo-skill", "a" * 40,
                          "https://github.com/example/demo", "MIT", True)
        write_pins(self.root, {"schema_version": 1, "pins": {"demo-skill": record}})
        self.assertEqual(verify_pins(self.root), [])

    def test_verify_detects_content_change(self):
        record = make_pin(self.root, "demo-skill", "a" * 40,
                          "https://github.com/example/demo", "MIT", True)
        write_pins(self.root, {"schema_version": 1, "pins": {"demo-skill": record}})
        skill = self.root / "skills" / "demo-skill" / "SKILL.md"
        skill.write_text(skill.read_text(encoding="utf-8") + "\nchanged\n", encoding="utf-8")
        self.assertTrue(any("content hash mismatch" in e for e in verify_pins(self.root)))

    def test_pin_rejects_unreviewed_status(self):
        catalog_path = self.root / "catalog.json"
        data = json.loads(catalog_path.read_text(encoding="utf-8"))
        data["skills"][0]["status"] = "draft"
        catalog_path.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaises(ManagerError):
            make_pin(self.root, "demo-skill", "a" * 40,
                     "https://github.com/example/demo", "MIT", True)


if __name__ == "__main__":
    unittest.main()
