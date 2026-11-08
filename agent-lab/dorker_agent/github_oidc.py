"""GitHub Actions OIDC token verification using the standard library only."""
from __future__ import annotations

import base64
import hashlib
import json
import math
import hmac
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Mapping, Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .artifacts import GitHubActorClaim, VerifiedGitHubActor


ISSUER = "https://token.actions.githubusercontent.com"
JWKS_URL = f"{ISSUER}/.well-known/jwks"
_MAX_JWKS_BYTES = 256 * 1024
_MAX_TOKEN_BYTES = 16 * 1024


class OIDCVerificationError(ValueError):
    """OIDC token or GitHub identity did not satisfy the verifier policy."""


class JWKSProvider(Protocol):
    def load(self) -> dict[str, object]:
        """Return the GitHub Actions JSON Web Key Set."""


@dataclass(frozen=True, slots=True)
class GitHubOIDCPolicy:
    audience: str
    repository: str
    repository_id: int
    allowed_workflow_refs: tuple[str, ...]
    allowed_subjects: tuple[str, ...] = ()
    clock_skew_seconds: int = 60
    max_token_age_seconds: int = 600

    def __post_init__(self) -> None:
        if not self.audience or len(self.audience) > 256:
            raise ValueError("audience must be 1..256 characters")
        if not self.repository or len(self.repository) > 200 or "/" not in self.repository:
            raise ValueError("repository must be owner/name")
        if isinstance(self.repository_id, bool) or not isinstance(self.repository_id, int) or self.repository_id < 1:
            raise ValueError("repository_id must be a positive integer")
        if not self.allowed_workflow_refs or any(not item or len(item) > 512 for item in self.allowed_workflow_refs):
            raise ValueError("allowed_workflow_refs must contain exact workflow refs")
        if any(not item or len(item) > 512 for item in self.allowed_subjects):
            raise ValueError("allowed_subjects entries must be non-empty")
        for name in ("clock_skew_seconds", "max_token_age_seconds"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")


class GitHubActionsJWKSProvider:
    """Fetch only the fixed GitHub Actions JWKS endpoint with bounded I/O."""

    def __init__(self, *, timeout_seconds: float = 3.0) -> None:
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not 0 < timeout_seconds <= 10:
            raise ValueError("timeout_seconds must be in (0, 10]")
        self._timeout = float(timeout_seconds)

    def load(self) -> dict[str, object]:
        request = urllib.request.Request(
            JWKS_URL, headers={"Accept": "application/json", "User-Agent": "dorker-agent-lab"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                if response.geturl() != JWKS_URL:
                    raise OIDCVerificationError("JWKS endpoint redirected unexpectedly")
                raw = response.read(_MAX_JWKS_BYTES + 1)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise OIDCVerificationError("unable to retrieve GitHub JWKS") from exc
        if len(raw) > _MAX_JWKS_BYTES:
            raise OIDCVerificationError("GitHub JWKS exceeds size limit")
        value = _strict_json(raw)
        if not isinstance(value, dict) or not isinstance(value.get("keys"), list):
            raise OIDCVerificationError("invalid GitHub JWKS document")
        if not 1 <= len(value["keys"]) <= 32:
            raise OIDCVerificationError("GitHub JWKS key count exceeds bounds")
        return value


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


class GitHubActionsOIDCTokenProvider:
    """Acquire a short-lived token only from the runner-provided OIDC endpoint."""

    def __init__(
        self,
        audience: str,
        *,
        environ: Mapping[str, str] | None = None,
        timeout_seconds: float = 3.0,
        opener=None,
    ) -> None:
        if not isinstance(audience, str) or not audience or len(audience) > 256:
            raise ValueError("audience must be 1..256 characters")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not 0 < timeout_seconds <= 10:
            raise ValueError("timeout_seconds must be in (0, 10]")
        self._audience = audience
        self._environ = environ
        self._timeout = float(timeout_seconds)
        self._opener = opener or urllib.request.build_opener(_NoRedirectHandler())

    def acquire(self) -> str:
        import os

        environment = os.environ if self._environ is None else self._environ
        endpoint = environment.get("ACTIONS_ID_TOKEN_REQUEST_URL")
        bearer = environment.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        if not isinstance(endpoint, str) or not isinstance(bearer, str) or not endpoint or not bearer:
            raise OIDCVerificationError("GitHub Actions OIDC request credentials are unavailable")

        parsed = urlsplit(endpoint)
        if (
            parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.fragment or len(endpoint) > 4096
        ):
            raise OIDCVerificationError("invalid GitHub Actions OIDC request endpoint")
        try:
            parsed.port
        except ValueError as exc:
            raise OIDCVerificationError("invalid GitHub Actions OIDC request endpoint") from exc
        query = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=False)
        if any(key == "audience" for key, _ in query):
            raise OIDCVerificationError("OIDC request endpoint already contains an audience")
        query.append(("audience", self._audience))
        request_url = urlunsplit((
            parsed.scheme, parsed.netloc, parsed.path, urlencode(query), "",
        ))
        request = urllib.request.Request(
            request_url,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {bearer}",
                "User-Agent": "dorker-agent-lab",
            },
            method="GET",
        )
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                if response.geturl() != request_url:
                    raise OIDCVerificationError("OIDC token endpoint redirected unexpectedly")
                raw = response.read(32 * 1024 + 1)
        except OIDCVerificationError:
            raise
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise OIDCVerificationError("GitHub Actions OIDC token request failed") from exc
        if len(raw) > 32 * 1024:
            raise OIDCVerificationError("OIDC token response exceeds size limit")
        value = _strict_json(raw)
        if not isinstance(value, dict):
            raise OIDCVerificationError("invalid GitHub Actions OIDC response")
        token = value.get("value")
        if not isinstance(token, str) or not token or len(token) > _MAX_TOKEN_BYTES:
            raise OIDCVerificationError("invalid GitHub Actions OIDC token response")
        if len(token.split(".")) != 3:
            raise OIDCVerificationError("GitHub Actions response did not contain a JWT")
        return token


class GitHubActionsOIDCVerifier:
    """Verify RS256 GitHub Actions OIDC tokens and enforce repository/workflow policy."""

    def __init__(
        self, policy: GitHubOIDCPolicy, jwks_provider: JWKSProvider | None = None,
        *, clock=time.time,
    ) -> None:
        self._policy = policy
        self._jwks = jwks_provider or GitHubActionsJWKSProvider()
        self._clock = clock

    def verify(self, claim: GitHubActorClaim) -> VerifiedGitHubActor:
        if not isinstance(claim, GitHubActorClaim):
            raise TypeError("claim must be a GitHubActorClaim")
        if isinstance(claim.github_id, bool) or not isinstance(claim.github_id, int) or claim.github_id < 1:
            raise OIDCVerificationError("invalid supplied GitHub user ID")
        if not isinstance(claim.login, str) or not claim.login.strip() or len(claim.login) > 39:
            raise OIDCVerificationError("invalid supplied GitHub login")
        if not isinstance(claim.oidc_token, str) or not claim.oidc_token or len(claim.oidc_token) > _MAX_TOKEN_BYTES:
            raise OIDCVerificationError("invalid or oversized OIDC token")

        parts = claim.oidc_token.split(".")
        if len(parts) != 3:
            raise OIDCVerificationError("malformed JWT")
        header = _decode_segment(parts[0])
        payload = _decode_segment(parts[1])
        signature = _decode_bytes(parts[2])
        if not isinstance(header, dict) or not isinstance(payload, dict):
            raise OIDCVerificationError("JWT header and payload must be objects")
        if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
            raise OIDCVerificationError("only keyed RS256 tokens are accepted")
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")

        jwks = self._jwks.load()
        keys = jwks.get("keys")
        if not isinstance(keys, list):
            raise OIDCVerificationError("JWKS keys list is missing")
        if not 1 <= len(keys) <= 32:
            raise OIDCVerificationError("JWKS key count exceeds bounds")
        matching = [
            key for key in keys
            if isinstance(key, dict)
            and key.get("kid") == header["kid"]
            and key.get("kty") == "RSA"
            and key.get("alg", "RS256") == "RS256"
            and key.get("use", "sig") == "sig"
        ]
        if len(matching) != 1:
            raise OIDCVerificationError("JWKS key ID is missing or ambiguous")
        self._verify_rs256(signing_input, signature, matching[0])
        self._validate_claims(payload, claim)
        return VerifiedGitHubActor(claim.github_id, claim.login)

    def _validate_claims(self, payload: dict[str, object], claim: GitHubActorClaim) -> None:
        policy = self._policy
        if payload.get("iss") != ISSUER:
            raise OIDCVerificationError("unexpected OIDC issuer")
        audience = payload.get("aud")
        if not (
            audience == policy.audience
            or isinstance(audience, list) and policy.audience in audience
        ):
            raise OIDCVerificationError("OIDC audience mismatch")
        if payload.get("repository") != policy.repository:
            raise OIDCVerificationError("repository mismatch")
        if str(payload.get("repository_id", "")) != str(policy.repository_id):
            raise OIDCVerificationError("repository ID mismatch")
        workflow_ref = payload.get("workflow_ref")
        if workflow_ref not in policy.allowed_workflow_refs:
            raise OIDCVerificationError("workflow ref is not allowed")
        if policy.allowed_subjects and payload.get("sub") not in policy.allowed_subjects:
            raise OIDCVerificationError("OIDC subject is not allowed")
        actor_id = payload.get("actor_id")
        actor = payload.get("actor")
        if str(actor_id) != str(claim.github_id) or actor != claim.login:
            raise OIDCVerificationError("supplied GitHub actor does not match signed claims")

        now = self._clock()
        exp, issued = payload.get("exp"), payload.get("iat")
        nbf = payload.get("nbf", issued)
        for name, value in (("exp", exp), ("iat", issued), ("nbf", nbf)):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise OIDCVerificationError(f"invalid {name} claim")
        skew = policy.clock_skew_seconds
        if now > exp + skew:
            raise OIDCVerificationError("OIDC token has expired")
        if nbf > now + skew or issued > now + skew:
            raise OIDCVerificationError("OIDC token is not yet valid")
        if now - issued > policy.max_token_age_seconds + skew:
            raise OIDCVerificationError("OIDC token is too old")


    @staticmethod
    def _verify_rs256(signing_input: bytes, signature: bytes, jwk: dict[str, object]) -> None:
        modulus = _decode_integer(jwk.get("n"))
        exponent = _decode_integer(jwk.get("e"))
        if not 2048 <= modulus.bit_length() <= 8192 or exponent < 3 or exponent % 2 == 0 or exponent.bit_length() > 32:
            raise OIDCVerificationError("unsafe RSA public key parameters")
        try:
            public_key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
            public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature as exc:
            raise OIDCVerificationError("OIDC JWT signature verification failed") from exc
        except ValueError as exc:
            raise OIDCVerificationError("invalid RSA public key") from exc


def _decode_segment(value: str) -> object:
    try:
        raw = _decode_bytes(value)
        return _strict_json(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise OIDCVerificationError("invalid JWT JSON segment") from exc


def _decode_bytes(value: str) -> bytes:
    if not isinstance(value, str) or not value or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for ch in value):
        raise OIDCVerificationError("invalid base64url segment")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        raise OIDCVerificationError("invalid base64url segment") from exc


def _decode_integer(value: object) -> int:
    if not isinstance(value, str):
        raise OIDCVerificationError("invalid RSA JWK integer")
    raw = _decode_bytes(value)
    if not raw or len(raw) > 1024:
        raise OIDCVerificationError("RSA JWK integer exceeds bounds")
    return int.from_bytes(raw, "big")


def _strict_json(raw: bytes) -> object:
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise OIDCVerificationError("invalid JSON document") from exc
