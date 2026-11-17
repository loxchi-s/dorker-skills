import unittest
from unittest.mock import patch

import json
from unittest.mock import Mock

from local_ai import (
    MAX_CONTEXT_BYTES,
    NUM_CTX,
    NUM_PREDICT,
    REVIEW_SYSTEM_PROMPT,
    ModelResponse,
    ask_model,
    collect_context,
    model_response_incomplete_reason,
    redact_secrets,
    validate_review_output,
)


class RedactionTests(unittest.TestCase):
    def test_github_token_is_redacted(self):
        value = "token=ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        self.assertNotIn("ghp_", redact_secrets(value))
        self.assertIn("[REDACTED", redact_secrets(value))

    def test_fine_grained_github_pat_in_bearer_header_is_redacted(self):
        token = "github_pat_" + "A" * 40
        value = f"Authorization: Bearer {token}"
        redacted = redact_secrets(value)
        self.assertNotIn(token, redacted)
        self.assertIn("[REDACTED GITHUB TOKEN]", redacted)

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
        response.read.return_value = json.dumps({
            "response": "Verdict: INCOMPLETE",
            "done_reason": "stop",
            "prompt_eval_count": 100,
            "eval_count": 20,
        }).encode()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        urlopen.return_value = response

        result = ask_model("test-model", "Review this patch", "diff --git a/a.py b/a.py")

        self.assertEqual("Verdict: INCOMPLETE", result.text)
        self.assertEqual("stop", result.done_reason)
        self.assertEqual(100, result.prompt_eval_count)
        self.assertEqual(20, result.eval_count)
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

    def test_rejects_empty_or_invalid_finding_fields(self):
        review = """## Verdict
REVIEW_REQUIRED

## Findings
- Severity:
- File: workbench/local_ai.py:42
- Evidence:
- Impact: Some impact
- Fix: Some fix

## Risks and Unknowns
Unknown

## Tests Needed
Add test
"""
        self.assertFalse(validate_review_output(review))

    def test_rejects_second_finding_missing_required_fields(self):
        review = """## Verdict
REVIEW_REQUIRED

## Findings
#### Finding 1
- Severity: High
- File: workbench/local_ai.py:42
- Evidence: Concrete evidence
- Impact: Concrete impact
- Fix: Concrete fix

#### Finding 2
- Severity: Medium
- File: workbench/test_local_ai.py:10

## Risks and Unknowns
Unknown

## Tests Needed
Add regression test
"""
        self.assertFalse(validate_review_output(review))

    def test_rejects_empty_field_without_consuming_next_line(self):
        review = """## Verdict
REVIEW_REQUIRED

## Findings
#### Finding 1
- Severity: High
- File: workbench/local_ai.py:42
- Evidence:
- Impact: Concrete impact
- Fix: Concrete fix

## Risks and Unknowns
Unknown

## Tests Needed
Add regression test
"""
        self.assertFalse(validate_review_output(review))

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



class ModelResponseStatusTests(unittest.TestCase):
    def test_output_limit_marks_review_incomplete(self):
        result = ModelResponse(
            text="partial review",
            done_reason="length",
            prompt_eval_count=100,
            eval_count=NUM_PREDICT,
        )
        self.assertIn("done_reason=length", model_response_incomplete_reason(result))

    def test_context_budget_pressure_marks_review_incomplete(self):
        result = ModelResponse(
            text="review",
            done_reason="stop",
            prompt_eval_count=NUM_CTX - NUM_PREDICT,
            eval_count=20,
        )
        self.assertIn("context tokens", model_response_incomplete_reason(result))

    def test_missing_completion_metadata_marks_review_incomplete(self):
        result = ModelResponse(
            text="review",
            done_reason=None,
            prompt_eval_count=None,
            eval_count=None,
        )
        self.assertIn("cannot be verified", model_response_incomplete_reason(result))


class ContextBoundsTests(unittest.TestCase):
    def test_context_limit_is_fixed(self):
        self.assertEqual(6_000, MAX_CONTEXT_BYTES)

    def test_collect_context_returns_text(self):
        self.assertIsInstance(collect_context().text, str)

    @patch("local_ai._git_output")
    def test_collect_context_redacts_bearer_github_pat(self, git_output):
        token = "github_pat_" + "B" * 40
        git_output.return_value = f"Authorization: Bearer {token}"
        context = collect_context("main")
        self.assertNotIn(token, context.text)
        self.assertIn("[REDACTED GITHUB TOKEN]", context.text)

    @patch("local_ai._git_output")
    def test_collect_context_enforces_utf8_byte_limit(self, git_output):
        git_output.return_value = "界" * MAX_CONTEXT_BYTES
        context = collect_context("main")
        self.assertLessEqual(len(context.text.encode("utf-8")), MAX_CONTEXT_BYTES)
        self.assertTrue(context.truncated)


if __name__ == "__main__":
    unittest.main()
