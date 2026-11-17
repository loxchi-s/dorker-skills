import http.client
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from local_ai import (
    MAX_CONTEXT_BYTES,
    MAX_REVIEW_FILES,
    MAX_REVIEW_CHUNKS,
    MAX_TOTAL_CONTEXT_BYTES,
    NUM_CTX,
    NUM_PREDICT,
    REVIEW_SYSTEM_PROMPT,
    ChunkReview,
    ContextChunk,
    ModelResponse,
    ask_model,
    build_aggregate_report,
    collect_context,
    model_response_incomplete_reason,
    redact_secrets,
    review_context_chunks,
    validate_review_output,
    _diff_position_at_offset,
    _changed_diff_lines,
    _decode_git_path,
    _split_utf8_text,
)
from token_budget import calculate_token_budget, estimate_tokens_upper_bound


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


    def test_common_credential_assignments_are_redacted(self):
        secrets = {
            "SECRET_KEY": "secret-value",
            "AWS_SECRET_ACCESS_KEY": "aws-secret-value",
            "auth_token": "auth-token-value",
            "token": "plain-token-value",
            "private_key": "private-key-value",
            "AWS_ACCESS_KEY_ID": "AKIA1234567890ABCDEF",
            "client_secret": "client-secret-value",
        }
        for name, secret in secrets.items():
            with self.subTest(name=name):
                redacted = redact_secrets(f"{name}={secret}")
                self.assertNotIn(secret, redacted)
                self.assertIn("[REDACTED", redacted)

    def test_authorization_bearer_and_basic_credentials_are_redacted(self):
        for scheme in ("Bearer", "Basic"):
            with self.subTest(scheme=scheme):
                credential = "QWxhZGRpbjpvcGVuIHNlc2FtZQ"
                redacted = redact_secrets(f"Authorization: {scheme} {credential}")
                self.assertNotIn(credential, redacted)
                self.assertIn(f"{scheme} [REDACTED]", redacted)

    def test_non_secret_max_tokens_setting_is_not_redacted(self):
        self.assertEqual("max_tokens=4096", redact_secrets("max_tokens=4096"))


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
    @patch("local_ai.urllib.request.urlopen")
    def test_model_request_converts_incomplete_http_response(self, urlopen):
        response = Mock()
        response.read.side_effect = http.client.IncompleteRead(b"{", 10)
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        urlopen.return_value = response
        with self.assertRaisesRegex(RuntimeError, "Local model request failed"):
            ask_model("test-model", "Review", "diff")

    @patch("local_ai.urllib.request.urlopen")
    def test_model_request_rejects_non_object_json(self, urlopen):
        response = Mock()
        response.read.return_value = b"[]"
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        urlopen.return_value = response
        with self.assertRaisesRegex(RuntimeError, "non-object JSON"):
            ask_model("test-model", "Review", "diff")

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

    def test_accepts_finding_with_exact_changed_line_and_matching_path(self):
        review = """## Verdict
REVIEW_REQUIRED

## Findings
- Severity: High
- File: workbench/local_ai.py:42
- Evidence: +with urllib.request.urlopen(request) as response:
- Impact: Repeated requests may exhaust resources.
- Fix: Close the response stream.

## Risks and Unknowns
Runtime behavior is unknown.

## Tests Needed
Add a response-close test.
"""
        diff = "diff --git a/workbench/local_ai.py b/workbench/local_ai.py\n@@ -41,0 +42,1 @@\n+with urllib.request.urlopen(request) as response:"
        self.assertTrue(validate_review_output(
            review, diff_context=diff, expected_path="workbench/local_ai.py"
        ))

    def test_rejects_finding_without_exact_changed_line_evidence(self):
        review = """## Verdict
REVIEW_REQUIRED

## Findings
- Severity: High
- File: workbench/local_ai.py:42
- Evidence: The response stream is leaked on every request.
- Impact: Repeated requests may exhaust resources.
- Fix: Close the response stream.

## Risks and Unknowns
Runtime behavior is unknown.

## Tests Needed
Add a response-close test.
"""
        diff = "diff --git a/workbench/local_ai.py b/workbench/local_ai.py\n+with urllib.request.urlopen(request) as response:"
        self.assertFalse(validate_review_output(
            review, diff_context=diff, expected_path="workbench/local_ai.py"
        ))


    def test_rejects_short_changed_line_as_evidence(self):
        review = """## Verdict
REVIEW_REQUIRED

## Findings
- Severity: Medium
- File: workbench/local_ai.py:42
- Evidence: Missing check (see line 42)
- Impact: A weak evidence match could validate an unsupported finding.
- Fix: Require a sufficiently long changed line as evidence.

## Risks and Unknowns
Runtime behavior is unknown.

## Tests Needed
Add a short-line evidence regression test.
"""
        diff = "diff --git a/workbench/local_ai.py b/workbench/local_ai.py\n@@ -41,0 +42,1 @@\n+)\n"
        self.assertFalse(validate_review_output(
            review, diff_context=diff, expected_path="workbench/local_ai.py"
        ))

    def test_accepts_plus_prefixed_long_changed_line_as_evidence(self):
        review = """## Verdict
REVIEW_REQUIRED

## Findings
- Severity: Medium
- File: workbench/local_ai.py:42
- Evidence: +with urllib.request.urlopen(request) as response:
- Impact: Repeated requests may exhaust resources.
- Fix: Close the response stream.

## Risks and Unknowns
Runtime behavior is unknown.

## Tests Needed
Add a response-close test.
"""
        diff = "diff --git a/workbench/local_ai.py b/workbench/local_ai.py\n@@ -41,0 +42,1 @@\n+with urllib.request.urlopen(request) as response:\n"
        self.assertTrue(validate_review_output(
            review, diff_context=diff, expected_path="workbench/local_ai.py"
        ))

    def test_rejects_finding_for_a_different_file(self):
        review = """## Verdict
REVIEW_REQUIRED

## Findings
- Severity: High
- File: other.py:42
- Evidence: +with urllib.request.urlopen(request) as response:
- Impact: Repeated requests may exhaust resources.
- Fix: Close the response stream.

## Risks and Unknowns
Runtime behavior is unknown.

## Tests Needed
Add a response-close test.
"""
        diff = "diff --git a/workbench/local_ai.py b/workbench/local_ai.py\n+with urllib.request.urlopen(request) as response:"
        self.assertFalse(validate_review_output(
            review, diff_context=diff, expected_path="workbench/local_ai.py"
        ))

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

    def test_accepts_finding_fields_in_different_order(self):
        review = """## Verdict
REVIEW_REQUIRED

## Findings
- File: workbench/local_ai.py:42
- Severity: High
- Evidence: A concrete defect exists on this changed line.
- Impact: The review result may be incorrect.
- Fix: Correct the affected branch.

## Risks and Unknowns
Runtime behavior is unknown.

## Tests Needed
Add a regression test.
"""
        self.assertTrue(validate_review_output(review))

    def test_splits_findings_when_a_field_repeats(self):
        review = """## Verdict
REVIEW_REQUIRED

## Findings
- File: workbench/local_ai.py:42
- Severity: High
- Evidence: First concrete defect.
- Impact: First impact.
- Fix: First fix.
- Severity: Medium
- File: workbench/test_local_ai.py:10
- Evidence: Second concrete defect.
- Impact: Second impact.
- Fix: Second fix.

## Risks and Unknowns
Runtime behavior is unknown.

## Tests Needed
Add regression tests.
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
            prompt_eval_count=NUM_CTX - NUM_PREDICT + 1,
            eval_count=20,
        )
        self.assertIn("context tokens", model_response_incomplete_reason(result))

    def test_prompt_at_safe_boundary_is_not_rejected(self):
        result = ModelResponse(
            text="review",
            done_reason="stop",
            prompt_eval_count=min(int(NUM_CTX * 0.90), NUM_CTX - NUM_PREDICT),
            eval_count=20,
        )
        self.assertIsNone(model_response_incomplete_reason(result))

    @patch("local_ai.urllib.request.urlopen")
    def test_oversized_request_is_rejected_before_network_call(self, urlopen):
        with self.assertRaisesRegex(RuntimeError, "rejected before inference"):
            ask_model("test-model", "review", "x" * 20_000)
        urlopen.assert_not_called()

    @patch("local_ai._git_output")
    def test_longer_user_prompt_reduces_available_diff_context(self, git_output):
        git_output.return_value = (
            "diff --git a/sample.py b/sample.py\n"
            + ("+x" * 20_000)
        )
        short = collect_context("main", "")
        long = collect_context("main", "x" * 2_000)
        short_max = max(len(chunk.text.encode("utf-8")) for chunk in short.chunks)
        long_max = max(len(chunk.text.encode("utf-8")) for chunk in long.chunks)
        self.assertLess(long_max, short_max)

class ContextBoundsTests(unittest.TestCase):
    def test_context_limit_is_fixed(self):
        self.assertEqual(6_000, MAX_CONTEXT_BYTES)

    @patch("local_ai._git_output")
    def test_manual_review_uses_first_parent_diff_for_merge_commit(self, git_output):
        git_output.return_value = "diff --git a/a.py b/a.py\\n+change"
        collect_context()
        args = git_output.call_args.args[0]
        self.assertIn("--diff-merges=first-parent", args)

    def test_manual_review_includes_non_conflicting_second_parent_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo_path = Path(temporary)

            def git(*args):
                subprocess.run(
                    ["git", *args],
                    cwd=repo_path,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )

            git("init", "-b", "main")
            git("config", "user.email", "test@example.invalid")
            git("config", "user.name", "Workbench Test")
            (repo_path / "base.txt").write_text("base\\n", encoding="utf-8")
            git("add", "base.txt")
            git("commit", "-m", "base")

            git("branch", "side")
            (repo_path / "main.py").write_text("main change\\n", encoding="utf-8")
            git("add", "main.py")
            git("commit", "-m", "main-side change")

            git("checkout", "side")
            (repo_path / "side.py").write_text("side change\\n", encoding="utf-8")
            git("add", "side.py")
            git("commit", "-m", "side change")

            git("checkout", "main")
            git("merge", "--no-ff", "side", "-m", "merge without conflicts")

            real_run = subprocess.run

            def run_in_repo(command, **kwargs):
                return real_run(command, cwd=repo_path, **kwargs)

            with patch("local_ai.subprocess.run", side_effect=run_in_repo):
                result = collect_context()

            self.assertIn("side.py", result.text)
            self.assertIn("+side change", result.text)
            self.assertNotIn("main.py", result.text)

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
    def test_collect_context_enforces_utf8_chunk_and_total_byte_limits(self, git_output):
        git_output.return_value = "界" * MAX_CONTEXT_BYTES
        context = collect_context("main")
        self.assertGreater(len(context.chunks), 1)
        self.assertTrue(all(
            len(chunk.text.encode("utf-8")) <= MAX_CONTEXT_BYTES
            for chunk in context.chunks
        ))
        self.assertLessEqual(len(context.text.encode("utf-8")), MAX_TOTAL_CONTEXT_BYTES)
        self.assertFalse(context.truncated)
        self.assertEqual(
            "界" * MAX_CONTEXT_BYTES,
            "".join(chunk.text.split("\n", 2)[-1] for chunk in context.chunks),
        )


class PerFileChunkingTests(unittest.TestCase):
    @patch("local_ai._git_output")
    def test_collect_context_splits_changed_files(self, git_output):
        git_output.return_value = (
            "diff --git a/one.py b/one.py\n+one\n"
            "diff --git a/two.py b/two.py\n+two\n"
        )
        result = collect_context("main")
        self.assertEqual(2, len(result.chunks))
        self.assertEqual("one.py", result.chunks[0].path)
        self.assertEqual("two.py", result.chunks[1].path)
        self.assertFalse(result.truncated)

    @patch("local_ai._git_output")
    def test_collect_context_splits_large_file_and_reviews_later_files(self, git_output):
        first = "diff --git a/large.py b/large.py\n" + ("x" * (MAX_CONTEXT_BYTES + 100))
        second = "diff --git a/next.py b/next.py\n+next"
        git_output.return_value = first + "\n" + second
        result = collect_context("main")
        self.assertFalse(result.truncated)
        large_chunks = [chunk for chunk in result.chunks if chunk.path == "large.py"]
        next_chunks = [chunk for chunk in result.chunks if chunk.path == "next.py"]
        self.assertEqual(3, len(large_chunks))
        self.assertEqual(1, len(next_chunks))
        self.assertTrue(all(not chunk.truncated for chunk in result.chunks))
        self.assertIn("x" * (MAX_CONTEXT_BYTES + 100), "".join(
            chunk.text.split("\n", 2)[-1] for chunk in large_chunks
        ))
        self.assertEqual(0, result.omitted_files)
        self.assertLessEqual(len(result.text.encode("utf-8")), MAX_TOTAL_CONTEXT_BYTES)

    @patch("local_ai._git_output")
    def test_collect_context_keeps_normal_diff_lines_whole(self, git_output):
        diff = "diff --git a/lines.py b/lines.py\n" + "".join(
            f"+line-{index:04d}-" + ("x" * 80) + "\n"
            for index in range(100)
        )
        git_output.return_value = diff
        result = collect_context("main")
        self.assertGreater(len(result.chunks), 1)
        segments = [chunk.text.split("\n", 2)[-1] for chunk in result.chunks]
        self.assertTrue(all(segment.endswith("\n") for segment in segments[:-1]))

    @patch("local_ai._git_output")
    def test_collect_context_marks_file_incomplete_when_chunk_count_exhausted(self, git_output):
        huge = "diff --git a/huge.py b/huge.py\n" + ("z" * (MAX_CONTEXT_BYTES * (MAX_REVIEW_CHUNKS + 1)))
        later = "diff --git a/later.py b/later.py\n+later"
        git_output.return_value = huge + "\n" + later
        result = collect_context("main")
        self.assertTrue(result.truncated)
        self.assertGreaterEqual(result.omitted_files, 1)
        self.assertTrue(any(chunk.truncated for chunk in result.chunks))
        self.assertLessEqual(len(result.chunks), MAX_REVIEW_CHUNKS)

    @patch("local_ai._git_output")
    def test_large_first_file_does_not_exclude_later_changed_files(self, git_output):
        huge = (
            "diff --git a/huge.py b/huge.py\n"
            + ("z" * (MAX_CONTEXT_BYTES * (MAX_REVIEW_CHUNKS + 1)))
        )
        later_one = "diff --git a/later_one.py b/later_one.py\n+later_one"
        later_two = "diff --git a/later_two.py b/later_two.py\n+later_two"
        git_output.return_value = huge + "\n" + later_one + "\n" + later_two

        result = collect_context("main")

        self.assertTrue(result.truncated)
        self.assertLessEqual(len(result.chunks), MAX_REVIEW_CHUNKS)
        self.assertIn("huge.py", {chunk.path for chunk in result.chunks})
        self.assertIn("later_one.py", {chunk.path for chunk in result.chunks})
        self.assertIn("later_two.py", {chunk.path for chunk in result.chunks})
        self.assertTrue(
            any(chunk.truncated for chunk in result.chunks if chunk.path == "huge.py")
        )
        self.assertFalse(
            any(chunk.truncated for chunk in result.chunks if chunk.path == "later_one.py")
        )
        self.assertFalse(
            any(chunk.truncated for chunk in result.chunks if chunk.path == "later_two.py")
        )
        self.assertEqual(1, result.omitted_files)

    @patch("local_ai.ask_model")
    def test_review_runs_once_per_file_and_passes_timeout(self, ask_model_mock):
        valid = """## Verdict
NO_ACTIONABLE_FINDINGS

## Findings
No actionable findings were identified in this file.

## Risks and Unknowns
Runtime behavior was not exercised.

## Tests Needed
Run relevant unit tests.
"""
        ask_model_mock.return_value = ModelResponse(
            text=valid,
            done_reason="stop",
            prompt_eval_count=100,
            eval_count=50,
        )
        chunks = (
            ContextChunk("one.py", "diff one", False),
            ContextChunk("two.py", "diff two", False),
        )
        results = review_context_chunks(chunks, "test-model", "Review")
        self.assertEqual(2, ask_model_mock.call_count)
        self.assertEqual(
            ["one.py", "two.py"],
            [item.path for item in results],
        )
        self.assertTrue(all(item.status == "NO_ACTIONABLE_FINDINGS" for item in results))
        self.assertGreater(ask_model_mock.call_args.kwargs["timeout_seconds"], 0)

    def test_aggregate_is_incomplete_when_any_file_is_incomplete(self):
        complete = ChunkReview(
            path="safe.py",
            status="NO_ACTIONABLE_FINDINGS",
            text="",
            reason=None,
            model_response=None,
        )
        incomplete = ChunkReview(
            path="large.py",
            status="INCOMPLETE",
            text="partial",
            reason="context truncated",
            model_response=None,
        )
        report = build_aggregate_report((complete, incomplete), omitted_files=1)
        self.assertIn("INCOMPLETE", report)
        self.assertIn("large.py", report)
        self.assertIn("additional file(s) were not reviewed", report)

    def test_aggregate_preserves_findings_without_markdown_hash_headings(self):
        finding = """Verdict:
REVIEW_REQUIRED

Findings:
- Severity: High
- File: workbench/local_ai.py:42
- Evidence: exact changed line
- Impact: concrete impact
- Fix: concrete fix

Risks and Unknowns:
Runtime behavior is unknown.

Tests Needed:
Add a regression test.
"""
        item = ChunkReview(
            path="workbench/local_ai.py",
            status="REVIEW_REQUIRED",
            text=finding,
            reason=None,
            model_response=None,
        )
        report = build_aggregate_report((item,), omitted_files=0)
        self.assertIn("Severity: High", report)
        self.assertIn("exact changed line", report)

    def test_aggregate_preserves_validated_findings(self):
        finding = """## Verdict
REVIEW_REQUIRED

## Findings
- Severity: High
- File: workbench/local_ai.py:42
- Evidence: A concrete defect exists on this changed line.
- Impact: The review result may be incorrect.
- Fix: Correct the affected branch.

## Risks and Unknowns
Runtime behavior is unknown.

## Tests Needed
Add a regression test.
"""
        item = ChunkReview(
            path="workbench/local_ai.py",
            status="REVIEW_REQUIRED",
            text=finding,
            reason=None,
            model_response=None,
        )
        report = build_aggregate_report((item,), omitted_files=0)
        self.assertIn("REVIEW_REQUIRED", report)
        self.assertIn("Severity: High", report)
        self.assertIn("concrete defect", report)


class CodeRabbitRegressionTests(unittest.TestCase):
    def test_secret_assignment_does_not_consume_following_diff_line(self):
        diff = "+TOKEN=\n+TIMEOUT=30\n+RETRY_COUNT=3\n+token=abc123\n"
        redacted = redact_secrets(diff)
        self.assertIn("+TIMEOUT=30", redacted)
        self.assertIn("+RETRY_COUNT=3", redacted)
        self.assertNotIn("abc123", redacted)
        self.assertEqual(diff.count("\n"), redacted.count("\n"))

    def test_no_actionable_verdict_rejects_structured_finding_fields(self):
        review = """## Verdict
NO_ACTIONABLE_FINDINGS
## Findings
No actionable findings were identified.
- Severity: High
- File: sample.py:1
- Evidence: a sufficiently long changed line
- Impact: The issue is exploitable.
- Fix: Validate the input.
## Risks and Unknowns
Unknown
## Tests Needed
Add a regression test.
"""
        self.assertFalse(validate_review_output(review))

    def test_git_quoted_path_decodes_spaces_and_utf8(self):
        slash = chr(92)
        token = '"b/my file' + slash + '303' + slash + '251.py"'
        self.assertEqual("my fileé.py", _decode_git_path(token))

    def test_collect_context_parses_quoted_git_path(self):
        slash = chr(92)
        header = 'diff --git "a/my file' + slash + '303' + slash + '251.py" "b/my file' + slash + '303' + slash + '251.py"'
        diff = header + "\n@@ -0,0 +1,1 @@\n+dangerous_call_with_context();\n"
        with patch("local_ai._git_output", return_value=diff):
            result = collect_context("main")
        self.assertEqual("my fileé.py", result.chunks[0].path)

    def test_second_segment_keeps_hunk_line_coordinates(self):
        diff = "diff --git a/sample.py b/sample.py\n@@ -10,2 +10,2 @@\n a\n+b\n c\n"
        second_offset = diff.index(" c\n")
        self.assertEqual((11, 12, False), _diff_position_at_offset(diff, second_offset))

    def test_validator_rejects_line_number_outside_changed_hunk(self):
        diff = "File: sample.py\n@@ -10,1 +10,1 @@\n-old_value = 0\n+new_value = 123\n"
        review = """## Verdict
REVIEW_REQUIRED
## Findings
- Severity: High
- File: sample.py:999
- Evidence: new_value = 123
- Impact: wrong value
- Fix: correct assignment
## Risks and Unknowns
Unknown
## Tests Needed
Add regression test
"""
        self.assertFalse(validate_review_output(review, diff, "sample.py"))

    def test_validator_accepts_backticks_inside_changed_line_evidence(self):
        tick = chr(96)
        changed = "const command = " + tick + "rm -rf ${target}" + tick + ";"
        diff = "File: sample.py\n@@ -1,1 +1,1 @@\n-old\n+" + changed + "\n"
        review = """## Verdict
REVIEW_REQUIRED
## Findings
- Severity: Medium
- File: sample.py:1
- Evidence: const command = `rm -rf ${target}`;
- Impact: command is unsafe
- Fix: validate target
## Risks and Unknowns
Unknown
## Tests Needed
Add test
"""
        self.assertTrue(validate_review_output(review, diff, "sample.py"))

    def test_aggregate_keeps_source_specific_risks_and_tests(self):
        model_text = """## Verdict
NO_ACTIONABLE_FINDINGS
## Findings
No actionable findings were identified.
## Risks and Unknowns
Parser may mishandle CRLF input.
## Tests Needed
Run test_parser_crlf_round_trip.
"""
        item = ChunkReview("parser.py", "NO_ACTIONABLE_FINDINGS", model_text, None, None)
        report = build_aggregate_report((item,), omitted_files=0)
        self.assertIn("Risks and Unknowns — parser.py", report)
        self.assertIn("CRLF input", report)
        self.assertIn("Tests Needed — parser.py", report)
        self.assertIn("test_parser_crlf_round_trip", report)

    def test_aggregate_extracts_lowercase_findings_heading(self):
        model_text = """## Verdict
REVIEW_REQUIRED
## findings:
- Severity: Medium
- File: parser.py:12
- Evidence: a sufficiently long changed line
- Impact: The parser may discard the result.
- Fix: Preserve the extracted section.
## Risks and Unknowns
Runtime behavior is unknown.
## Tests Needed
Add a regression test.
"""
        item = ChunkReview("parser.py", "REVIEW_REQUIRED", model_text, None, None)
        report = build_aggregate_report((item,), omitted_files=0)
        self.assertIn("Severity: Medium", report)
        self.assertIn("sufficiently long changed line", report)

    def test_changed_diff_lines_counts_plus_prefixed_source_lines(self):
        diff = (
            "diff --git a/sample.cpp b/sample.cpp\n"
            "+++ b/sample.cpp\n"
            "@@ -9,0 +10,2 @@\n"
            "+++requestCount;\n"
            "+send(requestCount);\n"
        )
        self.assertEqual(
            [("new", 10, "++requestCount;"), ("new", 11, "send(requestCount);")],
            _changed_diff_lines(diff),
        )

    def test_diff_position_counts_plus_prefixed_source_lines(self):
        diff = (
            "diff --git a/sample.cpp b/sample.cpp\n"
            "+++ b/sample.cpp\n"
            "@@ -9,0 +10,2 @@\n"
            "+++requestCount;\n"
            "+send(requestCount);\n"
        )
        offset = diff.index("+send(requestCount);")
        self.assertEqual((9, 11, False), _diff_position_at_offset(diff, offset))

    def test_pem_redaction_preserves_diff_line_coordinates(self):
        diff = (
            "diff --git a/key.py b/key.py\n"
            "@@ -0,0 +1,4 @@\n"
            "+-----BEGIN PRIVATE KEY-----\n"
            "+secret-material\n"
            "+-----END PRIVATE KEY-----\n"
            "+dangerous_call();\n"
        )
        redacted = redact_secrets(diff)
        self.assertNotIn("secret-material", redacted)
        self.assertEqual(diff.count("\n"), redacted.count("\n"))
        self.assertEqual(("new", 4, "dangerous_call();"), _changed_diff_lines(redacted)[-1])

    def test_validator_accepts_file_paths_with_spaces(self):
        diff = (
            "diff --git a/my file.py b/my file.py\n"
            "@@ -0,0 +1,1 @@\n"
            "+dangerous_call_with_context();\n"
        )
        review = """## Verdict
REVIEW_REQUIRED
## Findings
- Severity: Medium
- File: my file.py:1
- Evidence: dangerous_call_with_context();
- Impact: The changed call may be unsafe.
- Fix: Validate the argument before use.
## Risks and Unknowns
Runtime behavior is unknown.
## Tests Needed
Add a path-with-spaces regression test.
"""
        self.assertTrue(validate_review_output(review, diff, "my file.py"))


    def test_patch_line_parsing_treats_u2028_as_source_content(self):
        source_line = 'value = "alpha\u2028+dangerous_call_with_context();"'
        diff = (
            "diff --git a/sample.py b/sample.py\n"
            "@@ -0,0 +1,1 @@\n"
            "+" + source_line + "\n"
        )
        self.assertEqual([("new", 1, source_line)], _changed_diff_lines(diff))
        self.assertEqual([diff], _split_utf8_text(diff, 4096))

    def test_lf_segmenter_preserves_crlf_and_does_not_split_u2028(self):
        value = "first\r\nsecond\u2028still-second\nthird"
        parts = _split_utf8_text(value, 4096)
        self.assertEqual(value, "".join(parts))
        self.assertEqual(1, len(parts))

    def test_segmenter_stops_after_requested_prefix_of_huge_line(self):
        value = "x" * 1_000_000
        parts = _split_utf8_text(value, 1024, max_parts=3)
        self.assertEqual(3, len(parts))
        self.assertEqual(3_072, sum(len(part.encode("utf-8")) for part in parts))

    def test_diff_positions_do_not_copy_a_huge_line_before_requested_offset(self):
        value = "x" * 1_000_000
        self.assertEqual((None, None, True), _diff_position_at_offset(value, 1))

    @patch("local_ai._git_output")
    def test_every_context_chunk_fits_conservative_token_budget(self, git_output):
        git_output.return_value = (
            "diff --git a/sample.py b/sample.py\n"
            "@@ -0,0 +1,1 @@\n"
            "+" + ("x" * 200_000) + "\n"
        )
        prompt = "Review this patch."
        result = collect_context("main", prompt)
        budget = calculate_token_budget(
            system_prompt=REVIEW_SYSTEM_PROMPT,
            user_prompt=prompt,
            context_window=NUM_CTX,
            output_reserve=NUM_PREDICT,
            safety_ratio=0.90,
        )
        self.assertTrue(result.truncated)
        self.assertTrue(all(
            estimate_tokens_upper_bound(chunk.text) <= budget.diff_token_budget
            for chunk in result.chunks
        ))


    def test_direct_test_execution_includes_all_regression_classes(self):
        source = Path(__file__).read_text(encoding="utf-8")
        self.assertGreater(
            source.rfind('if __name__ == "__main__":'),
            source.find("class CodeRabbitRegressionTests"),
        )

if __name__ == "__main__":
    unittest.main()
