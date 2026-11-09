from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from dorker_agent.artifacts import VerifiedGitHubActor
from dorker_agent.github_oidc import GitHubActionsOIDCVerifier, GitHubOIDCPolicy
from dorker_agent.remote_audit import RemoteAuditHttpClient
from dorker_agent.remote_audit_service import (
    AuthorizationResult,
    InMemoryAuditRepository,
    RemoteAuditService,
)


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def fake_token(actor_id: int, login: str) -> str:
    header = b64url(b'{"alg":"RS256","kid":"fake"}')
    payload = b64url(json.dumps({"actor_id": actor_id, "actor": login}).encode())
    return f"{header}.{payload}.test-signature"


class TestIdentityVerifier:
    def __init__(self):
        self.allowed = {
            fake_token(101, "creator"): VerifiedGitHubActor(101, "creator"),
            fake_token(202, "approver-a"): VerifiedGitHubActor(202, "approver-a"),
            fake_token(303, "approver-b"): VerifiedGitHubActor(303, "approver-b"),
        }

    def verify(self, claim):
        actor = self.allowed.get(claim.oidc_token)
        if actor is None or (claim.github_id, claim.login) != (actor.github_id, actor.login):
            from dorker_agent.github_oidc import OIDCVerificationError
            raise OIDCVerificationError("fake identity not allowed")
        return actor


class TestAllowAuthorizationPolicy:
    def authorize(self, *, actor, operation, repository_id, plan_token):
        return AuthorizationResult(
            allowed=True,
            decision_id="test-allow",
            policy_version="test-only-v1",
        )


class RemoteAuditServiceTests(unittest.TestCase):
    def setUp(self):
        self.repository = InMemoryAuditRepository()
        self.service = RemoteAuditService(
            repository_id=1450173940,
            identity_verifier=TestIdentityVerifier(),
            repository=self.repository,
            authorization_policy=TestAllowAuthorizationPolicy(),
        )
        self.creator = fake_token(101, "creator")
        self.approver_a = fake_token(202, "approver-a")
        self.approver_b = fake_token(303, "approver-b")

    def request(self, method, path, *, token=None, body=None):
        headers = {}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        raw = body if isinstance(body, bytes) else json.dumps(body).encode() if body is not None else b""
        status, response_headers, payload = self.service.handle(method, path, headers, raw)
        return status, json.loads(payload)

    @staticmethod
    def make_plan(*, size=128, digest="a" * 64):
        cutoff = 1_800_000_000_000_000_000
        candidates = [{
            "sha256": digest,
            "size_bytes": size,
            "mtime_unix_ns": cutoff - 1,
        }]
        canonical = json.dumps(
            {"cutoff_unix_ns": cutoff, "candidates": candidates},
            sort_keys=True, separators=(",", ":"),
        ).encode()
        return {
            "approval_token": hashlib.sha256(canonical).hexdigest(),
            "cutoff_unix_ns": cutoff,
            "total_bytes": size,
            "candidates": candidates,
        }

    def create_plan(self, *, key="plan-key", token=None, plan=None):
        return self.request(
            "POST", "/v1/audit/plans", token=token or self.creator,
            body={"idempotency_key": key, "plan": plan or self.make_plan()},
        )

    def test_plan_commit_replay_and_idempotency_conflict(self):
        plan = self.make_plan()
        status, first = self.create_plan(plan=plan)
        self.assertEqual(status, 200)
        self.assertEqual(first["sequence"], 1)
        self.assertFalse(first["replayed"])

        status, replay = self.create_plan(plan=plan)
        self.assertEqual(status, 200)
        self.assertTrue(replay["replayed"])
        self.assertEqual(first["event_hash"], replay["event_hash"])
        self.assertEqual(len(self.repository.list_events(1450173940, 0, 10)), 1)

        status, conflict = self.create_plan(plan=self.make_plan(size=256))
        self.assertEqual(status, 409)
        self.assertEqual(conflict["error"]["code"], "idempotency_conflict")
        self.assertEqual(len(self.repository.list_events(1450173940, 0, 10)), 1)

    def test_plan_token_mismatch_and_duplicate_json_rejected(self):
        plan = self.make_plan()
        plan["approval_token"] = "b" * 64
        status, error = self.create_plan(plan=plan)
        self.assertEqual(status, 422)
        self.assertEqual(error["error"]["code"], "integrity_violation")

        raw = b'{"idempotency_key":"x","idempotency_key":"y","plan":{}}'
        status, error = self.request("POST", "/v1/audit/plans", token=self.creator, body=raw)
        self.assertEqual(status, 400)
        self.assertEqual(len(self.repository.list_events(1450173940, 0, 10)), 0)

    def test_unverified_identity_fails_closed(self):
        status, error = self.create_plan(token=fake_token(999, "intruder"))
        self.assertEqual(status, 401)
        self.assertEqual(error["error"]["code"], "unauthenticated")
        self.assertEqual(self.repository.list_events(1450173940, 0, 10), [])

    def test_creator_cannot_approve_and_decision_is_terminal(self):
        status, created = self.create_plan()
        self.assertEqual(status, 200)
        plan = self.make_plan()
        status, denied = self.request(
            "POST", "/v1/audit/decisions", token=self.creator,
            body={"idempotency_key": "creator-decision", "approval_token": plan["approval_token"], "decision": "approve"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(denied["error"]["code"], "forbidden")

        status, approved = self.request(
            "POST", "/v1/audit/decisions", token=self.approver_a,
            body={"idempotency_key": "approver-decision", "approval_token": plan["approval_token"], "decision": "approve"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(approved["sequence"], 2)

        status, conflict = self.request(
            "POST", "/v1/audit/decisions", token=self.approver_b,
            body={"idempotency_key": "second-decision", "approval_token": plan["approval_token"], "decision": "reject"},
        )
        self.assertEqual(status, 409)
        self.assertEqual(conflict["error"]["code"], "decision_conflict")
        self.assertTrue(self.repository.verify(1450173940))

    def test_concurrent_decisions_commit_exactly_one(self):
        _, _ = self.create_plan()
        plan = self.make_plan()
        barrier = threading.Barrier(2)

        def decide(token, key, decision):
            barrier.wait()
            return self.request(
                "POST", "/v1/audit/decisions", token=token,
                body={"idempotency_key": key, "approval_token": plan["approval_token"], "decision": decision},
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(decide, self.approver_a, "race-a", "approve"),
                pool.submit(decide, self.approver_b, "race-b", "reject"),
            ]
            results = [future.result(timeout=5) for future in futures]
        self.assertEqual(sorted(status for status, _ in results), [200, 409])
        events = self.repository.list_events(1450173940, 0, 10)
        self.assertEqual(len(events), 2)
        self.assertTrue(self.repository.verify(1450173940))

    def test_event_pagination_hash_chain_and_idempotency_lookup(self):
        _, plan_result = self.create_plan()
        plan = self.make_plan()
        self.request(
            "POST", "/v1/audit/decisions", token=self.approver_a,
            body={"idempotency_key": "decision-a", "approval_token": plan["approval_token"], "decision": "approve"},
        )
        status, first_page = self.request(
            "GET", "/v1/audit/events?limit=1", token=self.creator,
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(first_page["events"]), 1)
        cursor = first_page["next_cursor"]
        status, second_page = self.request(
            "GET", f"/v1/audit/events?limit=1&cursor={cursor}", token=self.creator,
        )
        self.assertEqual(status, 200)
        self.assertIsNone(second_page["next_cursor"])
        all_events = first_page["events"] + second_page["events"]
        self.assertTrue(RemoteAuditHttpClient.verify_event_chain(all_events))

        status, lookup = self.request(
            "GET", "/v1/audit/idempotency/plan-key", token=self.creator,
        )
        self.assertEqual(status, 200)
        self.assertEqual(lookup["event_hash"], plan_result["event_hash"])
        self.assertTrue(lookup["replayed"])


    def test_event_page_is_server_bounded_even_when_client_requests_1000(self):
        for index in range(11):
            digest = f"{index + 1:064x}"
            status, _ = self.create_plan(
                key=f"plan-{index}", plan=self.make_plan(digest=digest),
            )
            self.assertEqual(status, 200)
        status, page = self.request(
            "GET", "/v1/audit/events?limit=1000", token=self.creator,
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(page["events"]), 10)
        self.assertIsNotNone(page["next_cursor"])

    def test_default_policy_denies_authenticated_operations_without_mutation(self):
        service = RemoteAuditService(
            repository_id=1450173940,
            identity_verifier=TestIdentityVerifier(),
            repository=self.repository,
        )
        status, error = service.handle(
            "GET", "/v1/audit/events",
            {"Authorization": f"Bearer {self.creator}"}, b"",
        )
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(error)["error"]["code"], "forbidden")
        self.assertEqual(self.repository.list_events(1450173940, 0, 10), [])

    def test_authorization_policy_exception_fails_closed(self):
        class BrokenPolicy:
            def authorize(self, **kwargs):
                raise RuntimeError("policy backend unavailable")

        service = RemoteAuditService(
            repository_id=1450173940,
            identity_verifier=TestIdentityVerifier(),
            repository=self.repository,
            authorization_policy=BrokenPolicy(),
        )
        status, payload = service.handle(
            "GET", "/v1/audit/events",
            {"Authorization": f"Bearer {self.creator}"}, b"",
        )
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(payload)["error"]["code"], "authorization_unavailable")
        self.assertEqual(self.repository.list_events(1450173940, 0, 10), [])

    def test_malformed_authorization_result_fails_closed(self):
        class MalformedPolicy:
            def authorize(self, **kwargs):
                return {"allowed": True}

        service = RemoteAuditService(
            repository_id=1450173940,
            identity_verifier=TestIdentityVerifier(),
            repository=self.repository,
            authorization_policy=MalformedPolicy(),
        )
        status, payload = service.handle(
            "GET", "/v1/audit/events",
            {"Authorization": f"Bearer {self.creator}"}, b"",
        )
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(payload)["error"]["code"], "authorization_unavailable")

    def test_health_reports_test_only_and_chain_readiness(self):
        status, health = self.request("GET", "/v1/audit/health", token=self.creator)
        self.assertEqual(status, 200)
        self.assertTrue(health["ready"])
        self.assertEqual(health["mode"], "in-memory-test-only")



    def test_health_endpoint_requires_authenticated_workflow_identity(self):
        status, error = self.request("GET", "/v1/audit/health")
        self.assertEqual(status, 401)
        self.assertEqual(error["error"]["code"], "unauthenticated")

    def test_corrupted_chain_blocks_reads_and_writes(self):
        self.assertEqual(self.create_plan()[0], 200)
        self.repository._events[1450173940][0]["details"]["tampered"] = True
        status, error = self.request(
            "GET", "/v1/audit/events?limit=10", token=self.creator,
        )
        self.assertEqual(status, 422)
        self.assertEqual(error["error"]["code"], "integrity_violation")
        status, error = self.create_plan(key="after-tamper")
        self.assertEqual(status, 422)
        self.assertEqual(error["error"]["code"], "integrity_violation")

    def test_unauthenticated_request_and_oversized_body_rejected(self):
        status, error = self.request("GET", "/v1/audit/events")
        self.assertEqual(status, 401)
        status, headers, payload = self.service.handle(
            "POST", "/v1/audit/plans", {}, b"x" * (64 * 1024 + 1),
        )
        self.assertEqual(status, 413)


    def test_malformed_request_shapes_and_oversized_targets_fail_closed(self):
        cases = [
            ("GET", "/v1/audit/events?limit=1&cursor=MQ&extra=x", {"Authorization": f"Bearer {self.creator}"}, b""),
            ("GET", "/" + "x" * 4096, {"Authorization": f"Bearer {self.creator}"}, b""),
            ("GET", "/v1/audit/events", {"Authorization": 7}, b""),
            ("GET", "/v1/audit/events", {}, "not-bytes"),
        ]
        for method, target, headers, body in cases:
            status, payload_headers, payload = self.service.handle(method, target, headers, body)
            self.assertEqual(status, 400)
            self.assertEqual(json.loads(payload)["error"]["code"], "invalid_request")

    def test_invalid_base64url_bearer_segment_is_rejected_before_verifier(self):
        token = self.creator.split(".")
        token[1] += "!"
        status, error = self.request("GET", "/v1/audit/events", token=".".join(token))
        self.assertEqual(status, 401)
        self.assertEqual(error["error"]["code"], "unauthenticated")
        self.assertEqual(self.repository.list_events(1450173940, 0, 10), [])

    def test_deeply_nested_json_is_rejected_without_worker_exception(self):
        raw = b'{"idempotency_key":"deep","plan":' + b"[" * 2000 + b"0" + b"]" * 2000 + b"}"
        status, headers, payload = self.service.handle(
            "POST", "/v1/audit/plans", {"Authorization": f"Bearer {self.creator}"}, raw,
        )
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(payload)["error"]["code"], "invalid_request")
        self.assertEqual(self.repository.list_events(1450173940, 0, 10), [])

    def test_wsgi_adapter(self):
        import io
        body = json.dumps({
            "idempotency_key": "wsgi-plan",
            "plan": self.make_plan(),
        }).encode()
        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/v1/audit/plans",
            "QUERY_STRING": "",
            "CONTENT_LENGTH": str(len(body)),
            "HTTP_AUTHORIZATION": f"Bearer {self.creator}",
            "wsgi.input": io.BytesIO(body),
        }
        captured = {}
        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = headers
        payload = b"".join(self.service(environ, start_response))
        self.assertEqual(captured["status"], "200 OK")
        self.assertEqual(json.loads(payload)["sequence"], 1)



class StaticJWKS:
    def __init__(self, document):
        self.document = document

    def load(self):
        return self.document


class SignedOIDCServiceTests(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time())
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = self.private_key.public_key().public_numbers()
        self.policy = GitHubOIDCPolicy(
            audience="dorker-artifact-gc",
            repository="loxchi-s/dorker-skills",
            repository_id=1450173940,
            allowed_workflow_refs=(
                "loxchi-s/dorker-skills/.github/workflows/artifact-gc-audit.yml@refs/heads/main",
            ),
            allowed_subjects=("repo:loxchi-s/dorker-skills:environment:artifact-gc",),
            clock_skew_seconds=0,
            max_token_age_seconds=600,
        )
        self.verifier = GitHubActionsOIDCVerifier(
            self.policy,
            StaticJWKS({"keys": [{
                "kty": "RSA", "kid": "service-test", "alg": "RS256", "use": "sig",
                "n": b64url(public.n.to_bytes((public.n.bit_length() + 7) // 8, "big")),
                "e": b64url(public.e.to_bytes((public.e.bit_length() + 7) // 8, "big")),
            }]}),
            clock=lambda: self.now,
        )
        self.repository = InMemoryAuditRepository()
        self.service = RemoteAuditService(
            repository_id=1450173940,
            identity_verifier=self.verifier,
            repository=self.repository,
        )

    def signed_token(self, **overrides):
        claims = {
            "iss": "https://token.actions.githubusercontent.com",
            "aud": "dorker-artifact-gc",
            "exp": self.now + 300,
            "iat": self.now,
            "nbf": self.now,
            "repository": "loxchi-s/dorker-skills",
            "repository_id": "1450173940",
            "workflow_ref": "loxchi-s/dorker-skills/.github/workflows/artifact-gc-audit.yml@refs/heads/main",
            "sub": "repo:loxchi-s/dorker-skills:environment:artifact-gc",
            "actor_id": "101",
            "actor": "signed-creator",
        }
        claims.update(overrides)
        header = b64url(b'{"alg":"RS256","kid":"service-test","typ":"JWT"}')
        payload = b64url(json.dumps(claims, separators=(",", ":")).encode())
        signing_input = f"{header}.{payload}".encode("ascii")
        signature = self.private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        return f"{header}.{payload}.{b64url(signature)}"

    def post_plan(self, token):
        cutoff = 1_800_000_000_000_000_000
        candidates = []
        canonical = json.dumps(
            {"cutoff_unix_ns": cutoff, "candidates": candidates},
            sort_keys=True, separators=(",", ":"),
        ).encode()
        plan = {
            "approval_token": hashlib.sha256(canonical).hexdigest(),
            "cutoff_unix_ns": cutoff, "total_bytes": 0, "candidates": candidates,
        }
        status, headers, payload = self.service.handle(
            "POST", "/v1/audit/plans", {"Authorization": f"Bearer {token}"},
            json.dumps({"idempotency_key": "signed-plan", "plan": plan}).encode(),
        )
        return status, json.loads(payload)

    def test_service_verifies_real_rs256_signature_and_policy(self):
        status, result = self.post_plan(self.signed_token())
        self.assertEqual(status, 200)
        self.assertEqual(result["sequence"], 1)
        self.assertEqual(self.repository.list_events(1450173940, 0, 10)[0]["actor_login"], "signed-creator")

    def test_service_rejects_wrong_repository_workflow_and_subject(self):
        for overrides in (
            {"repository_id": "999"},
            {"workflow_ref": "loxchi-s/dorker-skills/.github/workflows/agent-lab-ci.yml@refs/heads/main"},
            {"sub": "repo:loxchi-s/dorker-skills:ref:refs/heads/main"},
            {"aud": "wrong-audience"},
        ):
            status, result = self.post_plan(self.signed_token(**overrides))
            self.assertEqual(status, 401)
            self.assertEqual(result["error"]["code"], "unauthenticated")
        self.assertEqual(self.repository.list_events(1450173940, 0, 10), [])

    def test_service_rejects_modified_jwt_signature(self):
        token = self.signed_token()
        parts = token.split(".")
        signature = bytearray(base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4)))
        signature[0] ^= 0x01
        parts[2] = b64url(bytes(signature))
        status, result = self.post_plan(".".join(parts))
        self.assertEqual(status, 401)
        self.assertEqual(result["error"]["code"], "unauthenticated")
        self.assertEqual(self.repository.list_events(1450173940, 0, 10), [])


if __name__ == "__main__":
    unittest.main()
