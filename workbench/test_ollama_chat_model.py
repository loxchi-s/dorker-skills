import json
import unittest
from unittest.mock import Mock, patch

from dorker_agent import ModelMessage
from ollama_chat_model import OllamaChatModel


class OllamaChatModelTests(unittest.TestCase):
    @patch("ollama_chat_model.urllib.request.urlopen")
    def test_translates_agent_messages_and_preserves_completion_metadata(self, urlopen):
        response = Mock()
        response.read.return_value = json.dumps({
            "response": "review complete",
            "done_reason": "stop",
            "prompt_eval_count": 321,
            "eval_count": 45,
        }).encode("utf-8")
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        urlopen.return_value = response

        provider = OllamaChatModel(
            model="test-model",
            base_url="http://127.0.0.1:11434/",
            timeout_seconds=30,
            num_ctx=8192,
            num_predict=1024,
        )
        result = provider.complete((
            ModelMessage("system", "Act as a reviewer."),
            ModelMessage("user", "Review this patch."),
            ModelMessage("user", "Diff content."),
        ))

        request = urlopen.call_args.args[0]
        payload = json.loads(request.data)
        self.assertEqual("review complete", result)
        self.assertEqual("Act as a reviewer.", payload["system"])
        self.assertEqual("Review this patch.\n\nDiff content.", payload["prompt"])
        self.assertEqual("stop", provider.last_response.done_reason)
        self.assertEqual(321, provider.last_response.prompt_eval_count)
        self.assertEqual(45, provider.last_response.eval_count)

    @patch("ollama_chat_model.urllib.request.urlopen")
    def test_rejects_unsupported_message_role_before_network_call(self, urlopen):
        provider = OllamaChatModel(
            model="test-model",
            base_url="http://127.0.0.1:11434",
            timeout_seconds=30,
            num_ctx=8192,
            num_predict=1024,
        )
        with self.assertRaisesRegex(ValueError, "does not support role"):
            provider.complete((
                ModelMessage("system", "System"),
                ModelMessage("assistant", "Unsupported"),
            ))
        urlopen.assert_not_called()

    @patch("ollama_chat_model.urllib.request.urlopen")
    def test_requires_exactly_one_system_message(self, urlopen):
        provider = OllamaChatModel(
            model="test-model",
            base_url="http://127.0.0.1:11434",
            timeout_seconds=30,
            num_ctx=8192,
            num_predict=1024,
        )
        with self.assertRaisesRegex(ValueError, "exactly one system"):
            provider.complete((
                ModelMessage("system", "First"),
                ModelMessage("system", "Second"),
                ModelMessage("user", "Task"),
            ))
        urlopen.assert_not_called()

    def test_rejects_non_http_endpoint(self):
        with self.assertRaisesRegex(ValueError, "HTTP"):
            OllamaChatModel(
                model="test-model",
                base_url="file:///tmp/ollama",
                timeout_seconds=30,
                num_ctx=8192,
                num_predict=1024,
            )


if __name__ == "__main__":
    unittest.main()
