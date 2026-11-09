from __future__ import annotations

import json
import unittest

from dorker_agent.remote_audit import (
    AuditClientError,
    AuditOutcomeIndeterminate,
    AuditRequestRejected,
    HttpResponse,
    RemoteAuditHttpClient,
)


def success(key: str, *, replayed: bool = False) -> bytes:
    return json.dumps({
        "request_id": "req-1",
        "idempotency_key": key,
        "event_id": "evt-1",
        "sequence": 7,
        "event_hash": "a" * 64,
        "replayed": replayed,
    }).encode()


class RemoteAuditHttpClientTests(unittest.TestCase):
    def make_client(self, transport, *, attempts=3):
        sleeps = []
        client = RemoteAuditHttpClient(
            "https://audit.example.test",
            lambda: "test-oidc-token",
            transport=transport,
            max_attempts=attempts,
            backoff_base_seconds=0.01,
            sleeper=sleeps.append,
            jitter=lambda low, high: high,
        )
        return client, sleeps

    def test_commit_then_timeout_retries_same_key_and_body(self):
        calls = []
        def transport(method, url, headers, body, timeout):
            calls.append((method, url, headers.copy(), body, timeout))
            if len(calls) == 1:
                # Simulates a committed request whose response was lost.
                raise TimeoutError("response lost after commit")
            return HttpResponse(200, success("plan-key-1", replayed=True))

        client, sleeps = self.make_client(transport)
        result = client.record_plan(
            idempotency_key="plan-key-1",
            plan={"approval_token": "b" * 64, "candidates": []},
        )
        self.assertTrue(result["replayed"])
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][3], calls[1][3])
        self.assertEqual(calls[0][2]["Idempotency-Key"], calls[1][2]["Idempotency-Key"])
        self.assertEqual(calls[0][3], json.dumps({
            "idempotency_key": "plan-key-1",
            "plan": {"approval_token": "b" * 64, "candidates": []},
        }, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode())
        self.assertEqual(len(sleeps), 1)

    def test_exhausted_write_timeout_is_indeterminate(self):
        calls = []
        def transport(*args):
            calls.append(args)
            raise TimeoutError("network timeout")
        client, _ = self.make_client(transport, attempts=2)
        with self.assertRaises(AuditOutcomeIndeterminate):
            client.record_decision(
                idempotency_key="decision-1",
                approval_token="c" * 64,
                decision="approve",
            )
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][3], calls[1][3])

    def test_non_retryable_conflict_is_not_retried(self):
        calls = []
        body = json.dumps({"error": {
            "code": "idempotency_conflict",
            "retryable": False,
        }}).encode()
        def transport(*args):
            calls.append(args)
            return HttpResponse(409, body)
        client, sleeps = self.make_client(transport)
        with self.assertRaises(AuditRequestRejected):
            client.record_plan(idempotency_key="same-key", plan={"x": 1})
        self.assertEqual(len(calls), 1)
        self.assertEqual(sleeps, [])

    def test_retries_retryable_503_with_same_payload(self):
        calls = []
        failure = json.dumps({"error": {"code": "unavailable", "retryable": True}}).encode()
        def transport(method, url, headers, body, timeout):
            calls.append(body)
            if len(calls) == 1:
                return HttpResponse(503, failure)
            return HttpResponse(200, success("plan-key-2"))
        client, _ = self.make_client(transport)
        client.record_plan(idempotency_key="plan-key-2", plan={"x": 1})
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0], calls[1])

    def test_rejects_duplicate_json_keys_and_oversized_response(self):
        duplicate = b'{"request_id":"a","request_id":"b"}'
        client, _ = self.make_client(lambda *args: HttpResponse(200, duplicate))
        with self.assertRaises(AuditClientError):
            client.lookup_idempotency("lookup-1")
        client, _ = self.make_client(lambda *args: HttpResponse(200, b" " * (256 * 1024 + 1)))
        with self.assertRaises(AuditClientError):
            client.lookup_idempotency("lookup-2")

    def test_rejects_insecure_or_credentialed_base_url(self):
        for url in (
            "http://audit.example.test",
            "https://user:secret@audit.example.test",
            "https://audit.example.test?token=x",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                RemoteAuditHttpClient(url, lambda: "token")

    def test_decision_enum_and_key_are_validated(self):
        client, _ = self.make_client(lambda *args: HttpResponse(200, success("key")))
        with self.assertRaises(ValueError):
            client.record_decision(
                idempotency_key="key", approval_token="d" * 64, decision="maybe",
            )
        with self.assertRaises(ValueError):
            client.record_plan(idempotency_key="unsafe/key", plan={})



    def test_paginates_events_and_verifies_contiguous_chain(self):
        calls = []
        def event(sequence, previous, digest, event_id):
            item = {
                "sequence": sequence, "event_id": event_id,
                "event_type": "gc_plan_created", "actor_id": 123,
                "actor_login": "test-actor", "timestamp": "2026-11-09T00:00:00.000Z",
                "details": {}, "idempotency_key": f"key-{sequence}",
                "request_hash": "a" * 64, "previous_hash": previous,
                "event_hash": "",
            }
            item["event_hash"] = RemoteAuditHttpClient.compute_event_hash(item)
            return item
        def transport(method, url, headers, body, timeout):
            calls.append(url)
            if len(calls) == 1:
                return HttpResponse(200, json.dumps({
                    "events": [event(1, "0" * 64, "", "evt-1")],
                    "next_cursor": "cursor/one",
                }).encode())
            return HttpResponse(200, json.dumps({
                "events": [event(2, event(1, "0" * 64, "", "evt-1")["event_hash"], "", "evt-2")],
                "next_cursor": None,
            }).encode())
        client, _ = self.make_client(transport)
        events = client.list_all_audit_events(limit=1)
        self.assertEqual([item["sequence"] for item in events], [1, 2])
        self.assertIn("cursor%2Fone", calls[1])

    def test_rejects_sequence_gap_and_broken_previous_hash(self):
        def event(sequence, previous, digest, event_id):
            item = {
                "sequence": sequence, "event_id": event_id,
                "event_type": "gc_plan_created", "actor_id": 123,
                "actor_login": "test-actor", "timestamp": "2026-11-09T00:00:00.000Z",
                "details": {}, "idempotency_key": f"key-{sequence}",
                "request_hash": "a" * 64, "previous_hash": previous,
                "event_hash": "",
            }
            item["event_hash"] = RemoteAuditHttpClient.compute_event_hash(item)
            return item
        first = event(1, "0" * 64, "1" * 64, "evt-1")
        with self.assertRaises(AuditClientError):
            RemoteAuditHttpClient.verify_event_chain([
                first, event(3, "1" * 64, "3" * 64, "evt-3")
            ])
        with self.assertRaises(AuditClientError):
            RemoteAuditHttpClient.verify_event_chain([
                first, event(2, "f" * 64, "2" * 64, "evt-2")
            ])

    def test_rejects_checkpoint_head_mismatch_and_duplicate_event_id(self):
        def event(sequence, previous, digest, event_id):
            item = {
                "sequence": sequence, "event_id": event_id,
                "event_type": "gc_plan_created", "actor_id": 123,
                "actor_login": "test-actor", "timestamp": "2026-11-09T00:00:00.000Z",
                "details": {}, "idempotency_key": f"key-{sequence}",
                "request_hash": "a" * 64, "previous_hash": previous,
                "event_hash": "",
            }
            item["event_hash"] = RemoteAuditHttpClient.compute_event_hash(item)
            return item
        first = event(1, "0" * 64, "1" * 64, "evt-1")
        with self.assertRaises(AuditClientError):
            RemoteAuditHttpClient.verify_event_chain([first], expected_head_hash="f" * 64)
        duplicate = event(2, first["event_hash"], "2" * 64, "evt-1")
        with self.assertRaises(AuditClientError):
            RemoteAuditHttpClient.verify_event_chain([first, duplicate])

    def test_rejects_repeated_pagination_cursor(self):
        body = json.dumps({"events": [], "next_cursor": "same-cursor"}).encode()
        client, _ = self.make_client(lambda *args: HttpResponse(200, body))
        with self.assertRaises(AuditClientError):
            client.list_all_audit_events(max_pages=3)

    def test_rejects_malformed_event_page(self):
        body = json.dumps({"events": [{"sequence": True}]}).encode()
        client, _ = self.make_client(lambda *args: HttpResponse(200, body))
        with self.assertRaises(AuditClientError):
            client.list_audit_events()


    def test_canonical_hash_vector_and_payload_tampering(self):
        event = {
            "sequence": 1, "event_id": "evt-1",
            "event_type": "gc_plan_created", "actor_id": 123,
            "actor_login": "test-actor", "timestamp": "2026-11-09T00:00:00.000Z",
            "details": {}, "idempotency_key": "key-1",
            "request_hash": "a" * 64, "previous_hash": "0" * 64,
            "event_hash": "",
        }
        event["event_hash"] = RemoteAuditHttpClient.compute_event_hash(event)
        self.assertEqual(
            event["event_hash"],
            "17e28036da076b4525c94aae117e95987fa2fc5da820c7ee856e7300587ce1e1",
        )
        self.assertTrue(RemoteAuditHttpClient.verify_event_chain([event]))
        altered = dict(event, details={"approval": "forged"})
        with self.assertRaises(AuditClientError):
            RemoteAuditHttpClient.verify_event_chain([altered])

    def test_verifies_partial_chain_from_trusted_anchor(self):
        previous = "f" * 64
        event = {
            "sequence": 42, "event_id": "evt-42",
            "event_type": "gc_plan_approved", "actor_id": 456,
            "actor_login": "approver", "timestamp": "2026-11-09T00:00:00.000Z",
            "details": {"approved": True}, "idempotency_key": "decision-42",
            "request_hash": "b" * 64, "previous_hash": previous,
            "event_hash": "",
        }
        event["event_hash"] = RemoteAuditHttpClient.compute_event_hash(event)
        self.assertTrue(RemoteAuditHttpClient.verify_event_chain(
            [event], expected_start_sequence=42,
            expected_previous_hash=previous, expected_head_hash=event["event_hash"],
        ))

    def test_validates_pagination_bounds(self):
        client, _ = self.make_client(lambda *args: HttpResponse(200, b'{"events":[]}'))
        with self.assertRaises(ValueError):
            client.list_audit_events(limit=0)
        with self.assertRaises(ValueError):
            client.list_audit_events(cursor="bad cursor")

if __name__ == "__main__":
    unittest.main()
