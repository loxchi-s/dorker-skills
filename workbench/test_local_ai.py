import unittest
from unittest.mock import patch

import json
from unittest.mock import Mock

from local_ai import (
    MAX_CONTEXT_BYTES,
    REVIEW_SYSTEM_PROMPT,
    ask_model,
    collect_context,
    redact_secrets,
    validate_review_output,
)


class RedactionTests(unittest.TestCase):
    def test_github_token_is_redacted(self):
        value = "token=ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        self.assertNotIn("ghp_", redact_secrets(value))
        self.assertIn("[REDACTED", redact_secrets(value))

    def test_private_key_is_redacted(self):
        value = "-----BEGIN PRIVATE KEY-----\\nsecret\\n-----END PRIVATE KEY-----"
        self.assertNotIn("secret", redact_secrets(value))

    def test_secret_assignment_is_redacted(self):
        self.assertEqual("api_key=[REDACTED]", redact_secrets("api_key=abc123"))

    def test_quoted_json_key_and_value_are_redacted(self):
        value = '{"password": "a sensitive value with spaces"}'
        self.assertEqual('{"password": [REDACTED]}', redact_secrets(value))
        self.assertNotIn("a sensitive value", redact_secrets(value))

    def test_quoted_value_with_spaces_is_redacted(self):
        value = 'password="a sensitive value with spaces"'
        self.assertEqual("password=[REDACTED]", redact_secrets(value))
        self.assertNotIn("a sensitive value", redact_secrets(value))

    def test_single_quoted_json_secret_is_redacted(self):
        value = "{'client_secret': 'sensitive value'}"
        self.assertEqual("{'client_secret': [REDACTED]}", redact_secrets(value))


class ModelPromptTests(unittest.TestCase):
    @patch("local_ai.urllib.request.urlopen")
    def test_model_request_uses_evidence_based_review_contract(self, urlopen):
        response = Mock()
        response.read.return_value = json.dumps({"response": "Verdict: INCOMPLETE"}).encode()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        urlopen.return_value = response

        result = ask_model("test-model", "Review this patch", "diff --git a/a.py b/a.py")

        self.assertEqual("Verdict: INCOMPLETE", result)
        request = urlopen.call_args.args[0]
        payload = json.loads(request.data.decode("utf-8"))
        self.assertEqual(REVIEW_SYSTEM_PROMPT, payload["system"])
        self.assertIn("diff --git a/a.py b/a.py", payload["prompt"])
        self.assertIn("Do not summarize files", payload["system"])
        self.assertIn("file and line", payload["system"])


class ReviewOutputValidationTests(unittest.TestCase):
    def test_rejects_generic_repository_summary(self):
        generic = "This script contains redaction, context collection, and tests."
        self.assertFalse(validate_review_output(generic))

    def test_accepts_evidence_based_actionable_finding(self):
        review = """## Verdict
REVIEW_REQUIRED

## Findings
- Severity: High
- File: workbench/local_ai.py:42
- Evidence: The function returns before closing the response stream.
- Impact: Repeated requests may leak resources.
- Fix: Use a context manager for the response.

## Risks and Unknowns
The behavior under network interruption is not verified.

## Tests Needed
Add a mocked response-close test.
"""
        self.assertTrue(validate_review_output(review))

    def test_accepts_no_actionable_findings_with_required_sections(self):
        review = """## Verdict
NO_ACTIONABLE_FINDINGS

## Findings
No actionable findings were identified in the supplied diff.

## Risks and Unknowns
Runtime behavior was not exercised.

## Tests Needed
Run integration tests in the target environment.
"""
        self.assertTrue(validate_review_output(review))



class ContextBoundsTests(unittest.TestCase):
    def test_context_limit_is_fixed(self):
        self.assertEqual(24_000, MAX_CONTEXT_BYTES)

    def test_collect_context_returns_text(self):
        self.assertIsInstance(collect_context(), str)

    @patch("local_ai._git_output")
    def test_collect_context_enforces_utf8_byte_limit(self, git_output):
        git_output.return_value = "界" * MAX_CONTEXT_BYTES
        context = collect_context("main")
        self.assertLessEqual(len(context.encode("utf-8")), MAX_CONTEXT_BYTES)


if __name__ == "__main__":
    unittest.main()
