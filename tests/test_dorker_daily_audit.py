import http.client
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from dorker_daily_audit import (
    MAX_PAGES,
    AuditError,
    GitHubClient,
    GitHubAPIError,
    SLOT_ENDPOINTS,
    collect_report,
    render_markdown,
    resolve_slot,
)


class SlotResolutionTests(unittest.TestCase):
    """Verify deterministic cron and manual slot routing."""

    def test_all_five_crons_map_to_slots(self):
        """Map each configured UTC cron to its Asia/Bangkok audit slot."""
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
        """Accept only explicitly supported manual audit slots."""
        self.assertEqual(resolve_slot(None, "security"), "security")
        with self.assertRaises(AuditError):
            resolve_slot(None, "unknown")

    def test_unknown_schedule_fails_closed(self):
        """Reject an unknown cron rather than guessing the requested task."""
        with self.assertRaises(AuditError):
            resolve_slot("0 0 * * *", None)


class FakeClient:
    """Provide predictable read-only responses for report tests."""

    def __init__(self):
        """Initialize the recorded request list."""
        self.calls = []

    def get(self, path):
        """Return a minimal repository object."""
        self.calls.append(("get", path))
        return {"default_branch": "main"}

    def list(self, path):
        """Return an empty, complete list response."""
        self.calls.append(("list", path))
        return [], False


class ReportTests(unittest.TestCase):
    """Verify report completeness and data minimization."""

    def test_repo_ci_slot_uses_expected_read_endpoints(self):
        """Collect only the endpoints assigned to the repo CI slot."""
        client = FakeClient()
        report = collect_report(client, "owner/repo", "repo_ci")
        self.assertTrue(report["read_only"])
        self.assertTrue(report["complete"])
        self.assertEqual(set(report["endpoints"]), set(SLOT_ENDPOINTS["repo_ci"]))
        self.assertEqual(len(client.calls), 3)

    def test_workflow_runs_object_payload_is_supported(self):
        """Accept the object envelope used by GitHub Actions workflow runs."""
        client = GitHubClient("test-token")
        client._request = lambda url: ({"total_count": 2, "workflow_runs": [{"id": 1}, {"id": 2}]}, None)
        items, truncated = client.list("/repos/owner/repo/actions/runs?per_page=100")
        self.assertEqual(len(items), 2)
        self.assertFalse(truncated)

    def test_list_follows_next_link_until_inventory_is_complete(self):
        """Follow Link rel=next headers and stop when no next page exists."""
        client = GitHubClient("test-token")
        responses = [
            ([{"id": 1}], '<https://api.github.com/repos/owner/repo/pulls?page=2>; rel="next"'),
            ([{"id": 2}], None),
        ]
        calls = []
        def fake_request(url):
            calls.append(url)
            return responses.pop(0)
        client._request = fake_request
        items, truncated = client.list("/repos/owner/repo/pulls?per_page=100")
        self.assertEqual([item["id"] for item in items], [1, 2])
        self.assertFalse(truncated)
        self.assertEqual(len(calls), 2)

    def test_list_reports_truncation_at_page_limit(self):
        """Stop after MAX_PAGES and report that more pages remain."""
        client = GitHubClient("test-token")
        calls = []
        def fake_request(url):
            calls.append(url)
            page = len(calls)
            return ([{"id": page}], f'<https://api.github.com/repos/owner/repo/pulls?page={page + 1}>; rel="next"')
        client._request = fake_request
        items, truncated = client.list("/repos/owner/repo/pulls?per_page=100")
        self.assertEqual(len(items), MAX_PAGES)
        self.assertTrue(truncated)
        self.assertEqual(len(calls), MAX_PAGES)

    def test_list_rejects_non_object_items(self):
        """Reject malformed list entries instead of producing a traceback."""
        client = GitHubClient("test-token")
        client._request = lambda url: ([{"id": 1}, "unexpected"], None)
        with self.assertRaises(AuditError):
            client.list("/repos/owner/repo/pulls")

    def test_get_rejects_non_object_payload(self):
        """Reject a non-object repository payload."""
        client = GitHubClient("test-token")
        client._request = lambda url: ([], None)
        with self.assertRaises(AuditError):
            client.get("/repos/owner/repo")

    def test_invalid_utf8_response_is_classified(self):
        """Convert invalid UTF-8 API response bodies into AuditError."""
        class FakeResponse:
            headers = {}
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self, limit):
                return b"\xff"

        client = GitHubClient("test-token")
        with patch("dorker_daily_audit.urllib.request.urlopen", return_value=FakeResponse()):
            with self.assertRaises(AuditError):
                client._request("https://api.github.com/repos/owner/repo")

    def test_interrupted_response_read_is_classified(self):
        """Convert interrupted HTTP response reads into AuditError."""
        class FakeResponse:
            headers = {}
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self, limit):
                raise http.client.IncompleteRead(b"partial")

        client = GitHubClient("test-token")
        with patch("dorker_daily_audit.urllib.request.urlopen", return_value=FakeResponse()):
            with self.assertRaises(AuditError):
                client._request("https://api.github.com/repos/owner/repo")

    def test_truncated_inventory_is_incomplete(self):
        """Propagate client pagination truncation into report completeness."""
        class TruncatedClient(FakeClient):
            def list(self, path):
                self.calls.append(("list", path))
                return [], True

        report = collect_report(TruncatedClient(), "owner/repo", "repo_ci")
        self.assertFalse(report["complete"])
        self.assertTrue(report["endpoints"]["workflow_runs"]["truncated"])

    def test_security_alert_payloads_are_not_persisted(self):
        """Keep alert counts but exclude vulnerability details from reports."""
        class AlertClient(FakeClient):
            def list(self, path):
                if "dependabot/alerts" in path:
                    return [{"secret_advisory_detail": "private-dependency-data"}], False
                if "code-scanning/alerts" in path:
                    return [{"secret_rule_detail": "private-code-location"}], False
                return super().list(path)

        report = collect_report(AlertClient(), "owner/repo", "security")
        self.assertEqual(report["summary"]["dependabot_alerts_open"], 1)
        self.assertEqual(report["summary"]["code_scanning_alerts_open"], 1)
        self.assertNotIn("items", report["endpoints"]["dependabot_alerts"])
        self.assertNotIn("items", report["endpoints"]["code_scanning_alerts"])
        self.assertNotIn("private-dependency-data", str(report))
        self.assertNotIn("private-code-location", str(report))

    def test_missing_security_permission_is_incomplete_and_count_unknown(self):
        """Do not misreport inaccessible alert endpoints as zero alerts."""
        class RestrictedClient(FakeClient):
            def list(self, path):
                if "dependabot/alerts" in path:
                    raise GitHubAPIError(403)
                return super().list(path)

        report = collect_report(RestrictedClient(), "owner/repo", "security")
        self.assertFalse(report["complete"])
        self.assertEqual(report["endpoints"]["dependabot_alerts"]["status"], "unavailable")
        self.assertIsNone(report["summary"]["dependabot_alerts_open"])

    def test_markdown_escapes_table_delimiters(self):
        """Escape untrusted text before inserting it into Markdown tables."""
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
