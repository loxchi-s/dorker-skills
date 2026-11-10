import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = REPO_ROOT / "tools" / "install_skill.py"


class InstallSkillTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "registry"
        self.dest = Path(self.tmp.name) / "destination"
        skill_dir = self.root / "skills" / "demo-skill"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(
            "---\nname: demo-skill\ndescription: Demo\n---\n# Demo\n",
            encoding="utf-8",
        )
        self.catalog_path = self.root / "catalog.json"
        self.write_catalog("reviewed")

    def tearDown(self):
        self.tmp.cleanup()

    def write_catalog(self, status):
        self.catalog_path.write_text(json.dumps({
            "schema_version": 1,
            "runtime_enabled": False,
            "skills": [{
                "name": "demo-skill",
                "category": "core",
                "status": status,
                "path": "skills/demo-skill/SKILL.md",
            }],
        }), encoding="utf-8")

    def run_installer(self):
        return subprocess.run(
            [
                sys.executable, str(INSTALLER), "demo-skill",
                "--root", str(self.root), "--dest", str(self.dest),
                "--revision", "a" * 40,
            ],
            capture_output=True, text=True, check=False,
        )

    def test_reviewed_skill_dry_run_succeeds_without_writing(self):
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"status": "dry_run"', result.stdout)
        self.assertFalse((self.dest / "demo-skill" / "SKILL.md").exists())

    def test_draft_skill_is_rejected(self):
        self.write_catalog("draft")
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("only reviewed or tested", result.stderr)

    def test_unknown_status_is_rejected(self):
        self.write_catalog("enabled")
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)

    def test_symlinked_manifest_is_rejected(self):
        self.dest.mkdir(parents=True)
        outside = Path(self.tmp.name) / "outside.json"
        outside.write_text("{}", encoding="utf-8")
        (self.dest / "installed.json").symlink_to(outside)
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("installed.json symlink", result.stderr)

    def test_non_object_manifest_is_rejected(self):
        self.dest.mkdir(parents=True)
        (self.dest / "installed.json").write_text("[]", encoding="utf-8")
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must contain a JSON object", result.stderr)


if __name__ == "__main__":
    unittest.main()
