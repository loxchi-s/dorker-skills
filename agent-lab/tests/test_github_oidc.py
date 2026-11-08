from __future__ import annotations

import base64
import json
import unittest
from unittest.mock import patch

from dorker_agent.artifacts import GitHubActorClaim, VerifiedGitHubActor
from dorker_agent.github_oidc import (
    GitHubActionsOIDCVerifier,
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
                "n": b64url(b"\xff" * 256), "e": b64url(bytes.fromhex("010001")),
            }]
        }

    def load(self):
        return self.document


def token_for(payload):
    header = {"alg": "RS256", "kid": "test-key", "typ": "JWT"}
    encoded_header = b64url(json.dumps(header, separators=(",", ":")).encode())
    encoded_payload = b64url(json.dumps(payload, separators=(",", ":")).encode())
    signature = bytes(256)
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
        with patch.object(GitHubActionsOIDCVerifier, "_verify_rs256"):
            self.assertEqual(
                self.verifier.verify(self.claim),
                VerifiedGitHubActor(101, "creator"),
            )

    def test_rejects_bad_signature(self):
        with self.assertRaisesRegex(OIDCVerificationError, "signature verification failed"):
            self.verifier.verify(self.claim)

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
        weak["n"] = b64url(b"\\x7f" * 128)
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
