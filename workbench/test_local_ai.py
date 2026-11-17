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
            "".join(chunk.text.split("\\n", 1)[-1] for chunk in context.chunks),
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
        first = "diff --git a/large.py b/large.py\\n" + ("x" * (MAX_CONTEXT_BYTES + 100))
        second = "diff --git a/next.py b/next.py\\n+next"
        git_output.return_value = first + "\\n" + second
        result = collect_context("main")
        self.assertFalse(result.truncated)
        large_chunks = [chunk for chunk in result.chunks if chunk.path == "large.py"]
        next_chunks = [chunk for chunk in result.chunks if chunk.path == "next.py"]
        self.assertEqual(2, len(large_chunks))
        self.assertEqual(1, len(next_chunks))
        self.assertTrue(all(not chunk.truncated for chunk in result.chunks))
        self.assertIn("x" * (MAX_CONTEXT_BYTES + 100), "".join(
            chunk.text.split("\\n", 1)[-1] for chunk in large_chunks
        ))
        self.assertEqual(0, result.omitted_files)
        self.assertLessEqual(len(result.text.encode("utf-8")), MAX_TOTAL_CONTEXT_BYTES)

    @patch("local_ai._git_output")
    def test_collect_context_marks_file_incomplete_when_chunk_count_exhausted(self, git_output):
        huge = "diff --git a/huge.py b/huge.py\\n" + ("z" * (MAX_CONTEXT_BYTES * (MAX_REVIEW_CHUNKS + 1)))
        later = "diff --git a/later.py b/later.py\\n+later"
        git_output.return_value = huge + "\\n" + later
        result = collect_context("main")
        self.assertTrue(result.truncated)
        self.assertGreaterEqual(result.omitted_files, 1)
        self.assertTrue(any(chunk.truncated for chunk in result.chunks))
        self.assertLessEqual(len(result.chunks), MAX_REVIEW_CHUNKS)

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


if __name__ == "__main__":
    unittest.main()
