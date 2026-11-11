import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from dorker_daily_audit import AuditError, SLOT_ENDPOINTS, collect_report, render_markdown, resolve_slot


class SlotResolutionTests(unittest.TestCase):
    def test_all_five_crons_map_to_slots(self):
        expected = {
            "0 23 * * *": "repo_ci",
            "0 3 * * *": "security",
            "0 7 * * *": "quality",
            "0 11 * * *": "pr_readiness",
            "0 15 * * *": "daily_summary",
        }
        for cron, slot in expected.items():
            with self.subTest(cron=cron):
                self.assertEqual(resolve_slot(cron, None), slot)

    def test_dispatch_slot_is_validated(self):
        self.assertEqual(resolve_slot(None, "security"), "security")
        with self.assertRaises(AuditError):
            resolve_slot(None, "unknown")

    def test_unknown_schedule_fails_closed(self):
        with self.assertRaises(AuditError):
            resolve_slot("0 0 * * *", None)


class FakeClient:
    def __init__(self):
        self.calls = []

    def get(self, path):
        self.calls.append(("get", path))
        return {"default_branch": "main"}

    def list(self, path):
        self.calls.append(("list", path))
        return [], False


class ReportTests(unittest.TestCase):
    def test_repo_ci_slot_uses_expected_read_endpoints(self):
        client = FakeClient()
        report = collect_report(client, "owner/repo", "repo_ci")
        self.assertTrue(report["read_only"])
        self.assertTrue(report["complete"])
        self.assertEqual(set(report["endpoints"]), set(SLOT_ENDPOINTS["repo_ci"]))
        self.assertEqual(len(client.calls), 3)

    def test_workflow_runs_object_payload_is_supported(self):
        from dorker_daily_audit import GitHubClient

        client = GitHubClient("test-token")
        client._request = lambda url: ({"total_count": 2, "workflow_runs": [{"id": 1}, {"id": 2}]}, None)
        items, truncated = client.list("/repos/owner/repo/actions/runs?per_page=100")
        self.assertEqual(len(items), 2)
        self.assertFalse(truncated)

    def test_missing_security_permission_is_incomplete(self):
        from dorker_daily_audit import GitHubAPIError

        class RestrictedClient(FakeClient):
            def list(self, path):
                if "dependabot/alerts" in path:
                    raise GitHubAPIError(403)
                return super().list(path)

        report = collect_report(RestrictedClient(), "owner/repo", "security")
        self.assertFalse(report["complete"])
        self.assertEqual(report["endpoints"]["dependabot_alerts"]["status"], "unavailable")

    def test_markdown_escapes_table_delimiters(self):
        report = {
            "repository": "owner/repo", "slot": "repo_ci", "task": "task | injected",
            "generated_at": "2026-01-01T00:00:00+00:00", "complete": True,
            "summary": {"signal|injected": 1}, "endpoints": {"repository": {"status": "ok"}},
        }
        rendered = render_markdown(report)
        self.assertIn(r"task \| injected", rendered)
        self.assertIn(r"signal\|injected", rendered)


if __name__ == "__main__":
    unittest.main()
