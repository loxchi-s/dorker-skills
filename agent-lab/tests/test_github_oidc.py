from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from dorker_agent.artifacts import (
    ArtifactDeletionPlan,
    ContentAddressedArtifactStore,
    GitHubActorClaim,
    VerifiedGitHubActor,
    SQLiteArtifactIndex,
)
_TEST_RSA_N = int(
    "9de13f2b9d901fdf6af7d16b254303c65c2b8544f3bd26d3f0d1cb76469bf8ec5d143c85f6780bed18d2d0ec6b615d96550b2d62579b813a0f18d97be8d730af07273002745dc051fcf9433b3aca9389c4ef11ea82f6396238f26b34b3a39299a2fa4d674d146c2721d92ca73d44ebc444be71225d5d0cd1885b595458bdcd3fabfa19e29d177dfb8eb72fb5750c924938a99a71996bc5a6adfc28aa28316fc7e6d4d9c2f7aa3509c8b03adac670f9a6e1c8249cb85c1c62137dcb207ff3e674f2c4b73bd797c3b9462345223c25ff5aea1da95c6abcbf5550d41ecf9e17f84953588648cad06bafa21fc0ba29fc032372c407839b40f882844151e20a61c341",
    16,
)
_TEST_RSA_D = int(
    "837844905f5edb0bc319a6ac2095539964bb60f8f0373d14145fbf9c38643dbf262b69d2ec513f2d2b14b2a18d31c12b249a702a8a659610f0ed727dba8127ab38bbab410001e9dadc5bfd5e5f30bdf765a4e7386fe1f61b12ecdbd5411a1f440cf17e6f5d427a6583cc4360e8a671e6389095c95611dc50c7c9b9f3810a5cd52b8ebfcb79d3e536f3d1f45c0a7a90a0343dfe6e30062fa5b0996a462e06424cc303113491740fe09184d3a476fecf087e40d06d7adff037eb290fbd5a8ff0571de1ff0f86cc80ad136604dc164cf59e442fb3f831b765736c9094888392667de67a86e2e04ba25db0378ee76e9d2682ecdfd5842f0546bbb6f8e7a62e0b8419",
    16,
)
_TEST_RSA_E = 65537
_SHA256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


from dorker_agent.github_oidc import (
    GitHubActionsOIDCVerifier,
    GitHubActionsOIDCIdentityProvider,
    GitHubActionsOIDCTokenProvider,
    GitHubOIDCPolicy,
    OIDCVerificationError,
)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class FakeJWKS:
    def __init__(self):
        self.document = {
            "keys": [{
                "kty": "RSA", "kid": "test-key", "alg": "RS256", "use": "sig",
                "n": b64url(_TEST_RSA_N.to_bytes(256, "big")), "e": b64url(bytes.fromhex("010001")),
            }]
        }

    def load(self):
        return self.document


def token_for(payload):
    header = {"alg": "RS256", "kid": "test-key", "typ": "JWT"}
    encoded_header = b64url(json.dumps(header, separators=(",", ":")).encode())
    encoded_payload = b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    digest_info = _SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(signing_input).digest()
    padding = bytes([0xff]) * (256 - len(digest_info) - 3)
    encoded_message = bytes([0x00, 0x01]) + padding + bytes([0x00]) + digest_info
    signature_int = pow(int.from_bytes(encoded_message, "big"), _TEST_RSA_D, _TEST_RSA_N)
    signature = signature_int.to_bytes(256, "big")
    return f"{encoded_header}.{encoded_payload}.{b64url(signature)}"


def claims(**overrides):
    value = {
        "iss": "https://token.actions.githubusercontent.com",
        "aud": "dorker-artifact-gc",
        "exp": 1_800_000_300,
        "iat": 1_800_000_000,
        "nbf": 1_800_000_000,
        "repository": "loxchi-s/dorker-skills",
        "repository_id": "123456",
        "workflow_ref": "loxchi-s/dorker-skills/.github/workflows/agent-lab-ci.yml@refs/heads/main",
        "sub": "repo:loxchi-s/dorker-skills:ref:refs/heads/main",
        "actor_id": "101",
        "actor": "creator",
    }
    value.update(overrides)
    return value


class FakeHTTPResponse:
    def __init__(self, body, final_url):
        self._body = body
        self._final_url = final_url
        self.read_limit = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, limit):
        self.read_limit = limit
        return self._body

    def geturl(self):
        return self._final_url


class FakeHTTPOpener:
    def __init__(self, response):
        self.response = response
        self.request = None
        self.timeout = None

    def open(self, request, timeout):
        self.request = request
        self.timeout = timeout
        return self.response


class GitHubActionsOIDCTokenProviderTests(unittest.TestCase):
    def setUp(self):
        self.endpoint = "https://pipelines.actions.githubusercontent.com/oidc?api-version=2"
        self.token = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJnaXRodWIifQ.signature"
        self.environment = {
            "ACTIONS_ID_TOKEN_REQUEST_URL": self.endpoint,
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "runner-bootstrap-secret",
        }

    def test_requests_encoded_audience_and_returns_jwt_without_logging(self):
        response = FakeHTTPResponse(
            json.dumps({"value": self.token}).encode(), 
            self.endpoint + "&audience=https%3A%2F%2Fexample.test%2Foidc",
        )
        opener = FakeHTTPOpener(response)
        provider = GitHubActionsOIDCTokenProvider(
            "https://example.test/oidc", environ=self.environment, opener=opener,
        )
        self.assertEqual(provider.acquire(), self.token)
        self.assertIn("audience=https%3A%2F%2Fexample.test%2Foidc", opener.request.full_url)
        self.assertEqual(opener.request.get_header("Authorization"), "Bearer runner-bootstrap-secret")
        self.assertEqual(opener.timeout, 3.0)
        self.assertEqual(response.read_limit, 32 * 1024 + 1)

    def test_missing_credentials_fail_closed(self):
        provider = GitHubActionsOIDCTokenProvider("aud", environ={})
        with self.assertRaisesRegex(OIDCVerificationError, "credentials are unavailable"):
            provider.acquire()

    def test_rejects_insecure_or_malformed_endpoint(self):
        for endpoint in ("http://example.test/token", "https://attacker.test/token", "https://user:pass@pipelines.actions.githubusercontent.com/token", "https://pipelines.actions.githubusercontent.com:444/token", "https://pipelines.actions.githubusercontent.com/token#fragment", "https://pipelines.actions.githubusercontent.com:bad/token"):
            env = dict(self.environment, ACTIONS_ID_TOKEN_REQUEST_URL=endpoint)
            with self.subTest(endpoint=endpoint):
                provider = GitHubActionsOIDCTokenProvider("aud", environ=env, opener=FakeHTTPOpener(None))
                with self.assertRaisesRegex(OIDCVerificationError, "invalid GitHub Actions OIDC request endpoint"):
                    provider.acquire()

    def test_rejects_preexisting_audience_parameter(self):
        env = dict(self.environment, ACTIONS_ID_TOKEN_REQUEST_URL=self.endpoint + "&audience=other")
        provider = GitHubActionsOIDCTokenProvider("aud", environ=env, opener=FakeHTTPOpener(None))
        with self.assertRaisesRegex(OIDCVerificationError, "already contains an audience"):
            provider.acquire()

    def test_rejects_redirected_endpoint(self):
        response = FakeHTTPResponse(b'{"value":"a.b.c"}', "https://attacker.test/steal")
        opener = FakeHTTPOpener(response)
        provider = GitHubActionsOIDCTokenProvider("aud", environ=self.environment, opener=opener)
        with self.assertRaisesRegex(OIDCVerificationError, "redirected unexpectedly"):
            provider.acquire()

    def test_rejects_oversized_or_invalid_token_response(self):
        cases = (b"x" * (32 * 1024 + 1), b'{"value":"not-a-jwt"}', b'{"value":""}')
        for body in cases:
            response = FakeHTTPResponse(body, self.endpoint + "&audience=aud")
            provider = GitHubActionsOIDCTokenProvider("aud", environ=self.environment, opener=FakeHTTPOpener(response))
            with self.subTest(body_size=len(body)):
                with self.assertRaises(OIDCVerificationError):
                    provider.acquire()


class GitHubActionsOIDCIdentityProviderTests(unittest.TestCase):
    def setUp(self):
        self.policy = GitHubOIDCPolicy(
            audience="dorker-artifact-gc",
            repository="loxchi-s/dorker-skills",
            repository_id=123456,
            allowed_workflow_refs=(
                "loxchi-s/dorker-skills/.github/workflows/agent-lab-ci.yml@refs/heads/main",
            ),
            clock_skew_seconds=0,
            max_token_age_seconds=600,
        )
        self.verifier = GitHubActionsOIDCVerifier(
            self.policy, FakeJWKS(), clock=lambda: 1_800_000_100,
        )

    def test_acquires_claim_and_verifies_signed_actor(self):
        token = token_for(claims())
        class TokenSource:
            def acquire(self):
                return token
        identity = GitHubActionsOIDCIdentityProvider(TokenSource(), self.verifier)
        claim = identity.acquire_claim()
        self.assertEqual((claim.github_id, claim.login), (101, "creator"))
        self.assertEqual(identity.verify(claim), VerifiedGitHubActor(101, "creator"))

    def test_rejects_missing_or_invalid_actor_before_claim_creation(self):
        for payload in (claims(actor_id=True), claims(actor_id="0"), claims(actor=" ")):
            class TokenSource:
                def acquire(self):
                    return token_for(payload)
            identity = GitHubActionsOIDCIdentityProvider(TokenSource(), self.verifier)
            with self.assertRaises(OIDCVerificationError):
                identity.acquire_claim()

    def test_forged_claim_actor_fails_verification(self):
        class TokenSource:
            def acquire(self):
                return token_for(claims())
        identity = GitHubActionsOIDCIdentityProvider(TokenSource(), self.verifier)
        forged = GitHubActorClaim(202, "attacker", token_for(claims()))
        with self.assertRaisesRegex(OIDCVerificationError, "supplied GitHub actor"):
            identity.verify(forged)

    def test_sqlite_audit_index_uses_composed_verified_identity(self):
        token = token_for(claims())
        class TokenSource:
            def acquire(self):
                return token

        identity = GitHubActionsOIDCIdentityProvider(TokenSource(), self.verifier)
        with tempfile.TemporaryDirectory() as directory:
            blob_root = os.path.join(directory, "objects")
            os.mkdir(blob_root)
            blobs = ContentAddressedArtifactStore(blob_root)
            database = os.path.join(directory, "audit.sqlite3")
            index = SQLiteArtifactIndex(database, blobs, identity_verifier=identity)
            claim = identity.acquire_claim()
            plan = ArtifactDeletionPlan((), 0, 0, "a" * 64)

            index.record_gc_plan(plan, claim=claim)

            events = index.list_audit_events()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["actor"], "github:101:creator")
            self.assertEqual(events[0]["action"], "gc_plan_created")
            self.assertTrue(index.verify_audit_log())
            with open(database, "rb") as handle:
                self.assertNotIn(token.encode("ascii"), handle.read())


class GitHubActionsOIDCVerifierTests(unittest.TestCase):
    def setUp(self):
        self.policy = GitHubOIDCPolicy(
            audience="dorker-artifact-gc",
            repository="loxchi-s/dorker-skills",
            repository_id=123456,
            allowed_workflow_refs=(
                "loxchi-s/dorker-skills/.github/workflows/agent-lab-ci.yml@refs/heads/main",
            ),
            allowed_subjects=("repo:loxchi-s/dorker-skills:ref:refs/heads/main",),
            clock_skew_seconds=0,
            max_token_age_seconds=600,
        )
        self.verifier = GitHubActionsOIDCVerifier(
            self.policy, FakeJWKS(), clock=lambda: 1_800_000_100,
        )
        self.claim = GitHubActorClaim(101, "creator", token_for(claims()))

    def test_valid_signed_claim_policy_returns_canonical_actor(self):
        self.assertEqual(
            self.verifier.verify(self.claim),
            VerifiedGitHubActor(101, "creator"),
        )

    def test_rejects_bad_signature(self):
        header, payload, signature = self.claim.oidc_token.split(".")
        raw_signature = bytearray(base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)))
        raw_signature[0] ^= 1
        tampered = GitHubActorClaim(
            101, "creator", f"{header}.{payload}.{b64url(bytes(raw_signature))}",
        )
        with self.assertRaisesRegex(OIDCVerificationError, "signature verification failed"):
            self.verifier.verify(tampered)

    def test_rejects_wrong_repository_workflow_audience_and_actor(self):
        cases = (
            {"repository": "attacker/repo"},
            {"repository_id": "999"},
            {"workflow_ref": "attacker/workflow.yml@refs/heads/main"},
            {"aud": "other-audience"},
            {"actor_id": "202"},
            {"actor": "forged"},
            {"sub": "repo:other/repo:ref:refs/heads/main"},
        )
        for override in cases:
            with self.subTest(override=override):
                claim = GitHubActorClaim(101, "creator", token_for(claims(**override)))
                with patch.object(GitHubActionsOIDCVerifier, "_verify_rs256"):
                    with self.assertRaises(OIDCVerificationError):
                        self.verifier.verify(claim)

    def test_rejects_expired_and_old_tokens(self):
        for override in ({"exp": 1_800_000_099}, {"iat": 1_799_999_000, "nbf": 1_799_999_000}):
            claim = GitHubActorClaim(101, "creator", token_for(claims(**override)))
            with patch.object(GitHubActionsOIDCVerifier, "_verify_rs256"):
                with self.assertRaises(OIDCVerificationError):
                    self.verifier.verify(claim)

    def test_rejects_duplicate_json_keys(self):
        header = b64url(b'{"alg":"RS256","kid":"test-key"}')
        payload = b64url(b'{"iss":"one","iss":"two"}')
        claim = GitHubActorClaim(101, "creator", f"{header}.{payload}.{b64url(b'x')}")
        with self.assertRaisesRegex(OIDCVerificationError, "invalid JWT JSON segment"):
            self.verifier.verify(claim)

    def test_rejects_unknown_or_ambiguous_key_id(self):
        self.verifier._jwks.document["keys"].append(dict(self.verifier._jwks.document["keys"][0]))
        with patch.object(GitHubActionsOIDCVerifier, "_verify_rs256"):
            with self.assertRaisesRegex(OIDCVerificationError, "missing or ambiguous"):
                self.verifier.verify(self.claim)

    def test_rejects_non_finite_time_claims(self):
        claim = GitHubActorClaim(101, "creator", token_for(claims(exp=float("nan"))))
        with patch.object(GitHubActionsOIDCVerifier, "_verify_rs256"):
            with self.assertRaisesRegex(OIDCVerificationError, "invalid exp"):
                self.verifier.verify(claim)

    def test_rejects_weak_rsa_modulus(self):
        weak = dict(self.verifier._jwks.document["keys"][0])
        weak["n"] = b64url(bytes([0x7f]) * 128)
        self.verifier._jwks.document = {"keys": [weak]}
        with self.assertRaisesRegex(OIDCVerificationError, "unsafe RSA"):
            self.verifier.verify(self.claim)

    def test_rejects_oversized_jwks_key_set(self):
        self.verifier._jwks.document = {"keys": [{}] * 33}
        with self.assertRaisesRegex(OIDCVerificationError, "key count exceeds bounds"):
            self.verifier.verify(self.claim)

    def test_policy_rejects_wildcard_or_empty_workflow_allowlist(self):
        with self.assertRaises(ValueError):
            GitHubOIDCPolicy("aud", "owner/repo", 1, ())
        with self.assertRaises(ValueError):
            GitHubOIDCPolicy("aud", "owner/repo", 1, ("",))


if __name__ == "__main__":
    unittest.main()
