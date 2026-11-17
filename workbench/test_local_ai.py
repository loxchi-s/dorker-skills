import unittest

from local_ai import MAX_CONTEXT_BYTES, collect_context, redact_secrets


class RedactionTests(unittest.TestCase):
    def test_github_token_is_redacted(self):
        value = "token=ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        self.assertNotIn("ghp_", redact_secrets(value))
        self.assertIn("[REDACTED", redact_secrets(value))

    def test_private_key_is_redacted(self):
        value = "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"
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


class ContextBoundsTests(unittest.TestCase):
    def test_context_limit_is_fixed(self):
        self.assertEqual(24_000, MAX_CONTEXT_BYTES)

    def test_collect_context_returns_text(self):
        self.assertIsInstance(collect_context(), str)


if __name__ == "__main__":
    unittest.main()
